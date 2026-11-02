"""wett-mcp-hostd: the only thing the connector can run on a host.

Invoked as an SSH forced command (`command="wett-mcp-hostd CONFIG",restrict`):
the request is a JSON object in SSH_ORIGINAL_COMMAND, the reply is one JSON
object on stdout. The server also imports this module and calls `handle()`
in-process for the host it runs on. Stdlib only.

Every verb is a fixed function; nothing from the request reaches a shell, and
argv elements built from the request are validated first.
"""

import datetime
import fnmatch
import json
import os
import re
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

MAX_LOG_LINES = 300
MAX_HISTORY_HOURS = 48

# Units that handle secrets: their logs are never returned, allowlisted or not.
LOG_DENY = ["sops-install-secrets*", "cloudflared*", "tailscaled*", "wett-mcp*"]

# Home Assistant domains no tool may call, whatever the allowlist says:
# physical security, HA/OS administration, and services that run arbitrary
# commands, publish raw messages or send notifications.
HA_DENY_DOMAINS = frozenset({
    "lock", "alarm_control_panel", "cover", "valve", "siren", "camera",
    "homeassistant", "hassio", "backup", "update", "recorder", "logger",
    "system_log", "shell_command", "rest_command", "command_line",
    "python_script", "pyscript", "notify", "persistent_notification",
    "automation", "mqtt", "zha", "zwave_js", "matter", "esphome", "input_text",
})
# Targeting keys that address many entities at once; calls must name entities.
HA_BROAD_TARGETS = ("area_id", "device_id", "floor_id", "label_id")
# Entities never shown by ha_states/ha_history unless explicitly exposed.
HA_HIDDEN_DOMAINS = ("person", "device_tracker", "zone", "camera", "image")

SINCE_RE = re.compile(
    r"^(-\d{1,4}(s|min|m|h|d|w)|today|yesterday|\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?)$"
)
UNIT_RE = re.compile(r"^[A-Za-z0-9@:._\\-]{1,200}$")
ENTITY_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
SLUG_RE = re.compile(r"^[a-z0-9_]+$")

REDACTIONS = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 [REDACTED]"),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|token|secret|password|passwd|authorization|auth)"
            r"(\"?\s*[=:]\s*\"?)[^\s\"',&;]+"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "[REDACTED-JWT]"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "[REDACTED-HEX]"),
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}"), "[REDACTED-B64]"),
]


class Denied(Exception):
    """The request is outside what this host allows."""


def redact(text):
    for pattern, repl in REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def _matches(name, patterns):
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _run(argv, timeout=15):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def _unit(req, cfg):
    unit = req.get("unit")
    if not isinstance(unit, str) or not UNIT_RE.match(unit) or unit.startswith("-"):
        raise Denied("invalid unit name")
    if not _matches(unit, cfg.get("units", [])):
        raise Denied(f"unit {unit!r} is not allowlisted on this host")
    return unit


# --- host verbs ---------------------------------------------------------------


def verb_status(req, cfg):
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    load = os.getloadavg()
    mem = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, value = line.split(":", 1)
            if key in ("MemTotal", "MemAvailable"):
                mem[key] = int(value.split()[0]) * 1024
    _, out, _ = _run(["systemctl", "list-units", "--failed", "--plain", "--no-legend", "--no-pager"])
    failed = [line.split()[0] for line in out.splitlines() if line.strip()]
    rc, out, _ = _run(["machinectl", "list", "--no-legend", "--no-pager"])
    containers = [line.split()[0] for line in out.splitlines() if line.strip()] if rc == 0 else []
    return {
        "host": socket.gethostname(),
        "uptime_s": int(uptime),
        "load": [round(x, 2) for x in load],
        "mem_total": mem.get("MemTotal"),
        "mem_available": mem.get("MemAvailable"),
        "failed_units": failed,
        "running_containers": containers,
    }


def verb_unit_status(req, cfg):
    unit = _unit(req, cfg)
    props = "Id,Description,LoadState,ActiveState,SubState,Result,ActiveEnterTimestamp,NRestarts,MemoryCurrent"
    _, out, err = _run(["systemctl", "show", "--no-pager", f"--property={props}", "--", unit])
    status = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if not status:
        raise Denied(err.strip() or "no such unit")
    return status


def verb_unit_logs(req, cfg):
    unit = _unit(req, cfg)
    if _matches(unit, LOG_DENY + cfg.get("logDeny", [])):
        raise Denied(f"logs of {unit!r} are never returned")
    since = req.get("since", "-1h")
    if not isinstance(since, str) or not SINCE_RE.match(since):
        raise Denied("since must look like -30min, -2h, -1d, today, yesterday or YYYY-MM-DD[ HH:MM]")
    lines = req.get("lines", 100)
    if not isinstance(lines, int) or isinstance(lines, bool) or lines < 1:
        raise Denied("lines must be a positive integer")
    lines = min(lines, MAX_LOG_LINES)
    grep = req.get("grep")
    if grep is not None and not isinstance(grep, str):
        raise Denied("grep must be a string")
    # Filter in Python, not with journalctl --grep: fetch a wider window first.
    fetch = MAX_LOG_LINES * 10 if grep else lines
    rc, out, err = _run(
        ["journalctl", "--no-pager", "--output=short-iso", f"--since={since}", f"--lines={fetch}",
         f"--unit={unit}"],
        timeout=30,
    )
    if rc != 0:
        raise Denied(err.strip()[:500] or "journalctl failed")
    entries = out.splitlines()
    if grep:
        needle = grep.lower()
        entries = [e for e in entries if needle in e.lower()]
    return {"unit": unit, "lines": [redact(e) for e in entries[-lines:]]}


def verb_df(req, cfg):
    _, out, _ = _run(["df", "-P", "-T", "-x", "tmpfs", "-x", "devtmpfs", "-x", "ramfs", "-x", "overlay",
                      "-x", "squashfs", "-x", "efivarfs"])
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 7:
            rows.append({"fs": parts[0], "type": parts[1], "size_kb": int(parts[2]), "used_kb": int(parts[3]),
                         "use": parts[5], "mount": parts[6]})
    return rows


# --- Home Assistant -----------------------------------------------------------


def ha_policy(domain, service, data, allow):
    """Raise Denied unless this service call is permitted. Returns entity ids."""
    if not isinstance(domain, str) or not SLUG_RE.match(domain):
        raise Denied("invalid domain")
    if not isinstance(service, str) or not SLUG_RE.match(service):
        raise Denied("invalid service")
    if domain in HA_DENY_DOMAINS:
        raise Denied(f"domain {domain!r} is on the deny list")
    if not isinstance(data, dict):
        raise Denied("data must be an object")
    for key in HA_BROAD_TARGETS:
        if key in data:
            raise Denied(f"{key} targeting is not allowed; name entity_id explicitly")
    entities = data.get("entity_id")
    if isinstance(entities, str):
        entities = [entities]
    if not entities or not isinstance(entities, list):
        raise Denied("entity_id is required")
    full = f"{domain}.{service}"
    for entity in entities:
        if not isinstance(entity, str) or not ENTITY_RE.match(entity):
            raise Denied(f"invalid entity_id {entity!r}")
        if entity.split(".", 1)[0] in HA_DENY_DOMAINS:
            raise Denied(f"entity {entity!r} is in a denied domain")
        if not any(fnmatch.fnmatchcase(full, rule["service"])
                   and _matches(entity, rule.get("entities", [])) for rule in allow):
            raise Denied(f"{full} on {entity} is not allowlisted")
    return entities


def ha_visible(entity_id, ha):
    if _matches(entity_id, ha.get("exposeEntities", [])):
        return True
    if entity_id.split(".", 1)[0] in HA_HIDDEN_DOMAINS:
        return False
    return not _matches(entity_id, ha.get("hideEntities", []))


def _ha_request(ha, method, path, body=None):
    with open(ha["tokenFile"]) as f:
        token = f.read().strip()
    request = urllib.request.Request(
        ha["url"].rstrip("/") + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as resp:
        return json.loads(resp.read().decode() or "null")


def _ha_cfg(cfg):
    ha = cfg.get("ha")
    if not ha:
        raise Denied("Home Assistant is not configured on this host")
    return ha


def _state_summary(s):
    attrs = s.get("attributes", {})
    out = {"entity_id": s["entity_id"], "state": s.get("state"), "last_changed": s.get("last_changed")}
    for key in ("friendly_name", "unit_of_measurement", "current_temperature", "temperature",
                "hvac_action", "brightness", "percentage"):
        if key in attrs:
            out[key] = attrs[key]
    return out


def filter_states(states, ha, domain=None, search=None):
    out = []
    for s in states:
        eid = s.get("entity_id", "")
        if not ha_visible(eid, ha):
            continue
        if domain and eid.split(".", 1)[0] != domain:
            continue
        if search:
            name = str(s.get("attributes", {}).get("friendly_name", ""))
            if search.lower() not in eid.lower() and search.lower() not in name.lower():
                continue
        out.append(_state_summary(s))
    return out


def verb_ha_states(req, cfg):
    ha = _ha_cfg(cfg)
    domain, search = req.get("domain"), req.get("search")
    if domain is not None and (not isinstance(domain, str) or not SLUG_RE.match(domain)):
        raise Denied("invalid domain")
    if search is not None and not isinstance(search, str):
        raise Denied("search must be a string")
    return filter_states(_ha_request(ha, "GET", "/api/states"), ha, domain, search)


def verb_ha_history(req, cfg):
    ha = _ha_cfg(cfg)
    entity = req.get("entity_id")
    if not isinstance(entity, str) or not ENTITY_RE.match(entity) or not ha_visible(entity, ha):
        raise Denied("entity is invalid or hidden")
    hours = req.get("hours", 6)
    if not isinstance(hours, (int, float)) or isinstance(hours, bool) or not 0 < hours <= MAX_HISTORY_HOURS:
        raise Denied(f"hours must be in (0, {MAX_HISTORY_HOURS}]")
    start = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)).isoformat()
    query = urllib.parse.urlencode({"filter_entity_id": entity, "minimal_response": "", "no_attributes": ""})
    data = _ha_request(ha, "GET", f"/api/history/period/{urllib.parse.quote(start)}?{query}")
    rows = data[0] if data else []
    return [{"state": r.get("state"), "at": r.get("last_changed")} for r in rows]


def verb_ha_call(req, cfg):
    ha = _ha_cfg(cfg)
    data = req.get("data") or {}
    ha_policy(req.get("domain"), req.get("service"), data, ha.get("allow", []))
    changed = _ha_request(ha, "POST", f"/api/services/{req['domain']}/{req['service']}", data)
    return {"changed": [_state_summary(s) for s in changed or [] if isinstance(s, dict)]}


VERBS = {
    "status": verb_status,
    "unit_status": verb_unit_status,
    "unit_logs": verb_unit_logs,
    "df": verb_df,
    "ha_states": verb_ha_states,
    "ha_history": verb_ha_history,
    "ha_call": verb_ha_call,
}


def handle(req, cfg):
    """Dispatch one request. Always returns {"ok": ...} JSON-able dict."""
    if not isinstance(req, dict):
        return {"ok": False, "error": "request must be a JSON object"}
    verb = req.get("verb")
    fn = VERBS.get(verb) if isinstance(verb, str) else None
    if fn is None:
        return {"ok": False, "error": f"unknown verb {verb!r}"}
    try:
        return {"ok": True, "result": fn(req, cfg)}
    except Denied as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001 - report, never crash the channel
        return {"ok": False, "error": f"{type(e).__name__}: {redact(str(e))[:500]}"}


def main():
    if len(sys.argv) < 2:
        print("usage: wett-mcp-hostd CONFIG [REQUEST-JSON]", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
    raw = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        req = json.loads(raw)
    except ValueError:
        req = None
    json.dump(handle(req, cfg), sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
