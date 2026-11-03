"""wett-mcp-hostd: the only thing the connector can run on a host.

Invoked as an SSH forced command (`command="wett-mcp-hostd CONFIG",restrict`):
the request is a JSON object in SSH_ORIGINAL_COMMAND, the reply is one JSON
object on stdout. The server also imports this module and calls `handle()`
in-process for the host it runs on. Stdlib only.

Every verb is a fixed function; nothing from the request reaches a shell, and
argv elements built from the request are validated first.
"""

import contextlib
import datetime
import fcntl
import fnmatch
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
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


# --- coding agents ------------------------------------------------------------
#
# Enabled by an "agents" section in the config, on a host (or container) where
# hostd runs as the agents' own user. A job is a directory under stateDir:
#
#   meta.json    state, inbox (queued messages), session id, unit, counters
#   turns.jsonl  one record per finished turn (status, final text, cost)
#   events/N.jsonl, events/N.stderr   raw omp output of turn N
#   session/     the omp session (--session-dir), resumable by hand
#   lock         flock guarding meta.json; <stateDir>/.lock guards starts
#
# A run is a transient `systemd-run --user` unit executing this file with
# --run-agent: it drains the inbox, one headless `omp -p` turn per message,
# resuming the job's session, and exits when the inbox is empty.

AGENT_ID_RE = re.compile(r"[0-9a-f]{8}")
AGENT_SESSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z_-]{7,63}")
REPO_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}")
GH_OWNER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
AGENT_UNIT_PREFIX = "wett-agent-"
AGENT_TEXT_MAX = 8000
AGENT_TURNS_MAX = 20
AGENT_INBOX_MAX = 20
AGENT_LIST_MAX = 50
AGENT_PROMPT_MAX = 20000
AGENT_TITLE_MAX = 100
AGENT_NOTE = (
    "You were dispatched remotely by Claude Duet (the owner's assistant), not by someone watching this session. "
    "Work autonomously; nobody can answer questions mid-turn. Never push to a repository's default branch or "
    "force-push shared branches unless the prompt explicitly asks: work on a new branch and open a pull request. "
    "End every turn with a concise plain-text summary (what you did, links to branches/PRs, what is left, what "
    "the owner must decide): that final message is all Duet sees. Follow-up messages may arrive as later turns."
)


class _Stopped(Exception):
    """SIGTERM reached the runner (agent_stop, RuntimeMaxSec, shutdown)."""


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def check_repo(repo, owners=None):
    """(owner or None, name). owners=None skips the allowlist (server-side syntax check)."""
    if not isinstance(repo, str):
        raise Denied("repo must be a string")
    parts = repo.split("/")
    if len(parts) == 1 and REPO_NAME_RE.fullmatch(parts[0]):
        return None, parts[0]
    if len(parts) == 2 and GH_OWNER_RE.fullmatch(parts[0]) and REPO_NAME_RE.fullmatch(parts[1]):
        if owners is not None and parts[0].lower() not in {o.lower() for o in owners}:
            raise Denied(f"cloning from {parts[0]!r} is not allowed; allowed owners: {sorted(owners)}")
        return parts[0], parts[1]
    raise Denied("repo must be a directory name under the work root or a GitHub owner/name")


def check_text(value, what, limit=AGENT_PROMPT_MAX):
    if not isinstance(value, str) or not value.strip():
        raise Denied(f"{what} must be a non-empty string")
    if len(value) > limit:
        raise Denied(f"{what} is {len(value)} chars; the limit is {limit}")
    if "\0" in value:
        raise Denied(f"{what} must not contain NUL")
    return value


def check_title(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise Denied("title must be a string")
    return re.sub(r"[\x00-\x1f\x7f]+", " ", value).strip()[:AGENT_TITLE_MAX] or None


def check_minutes(value, default, cap):
    if value is None:
        return min(default, cap)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise Denied("max_minutes must be a positive integer")
    return min(value, cap)


def check_agent_id(value):
    if not isinstance(value, str) or not AGENT_ID_RE.fullmatch(value):
        raise Denied("invalid agent job id")
    return value


def _agents_cfg(cfg):
    a = cfg.get("agents")
    if not a:
        raise Denied("coding agents are not enabled on this host")
    return a


def _agents_root(a):
    root = os.path.expanduser(a.get("stateDir", "~/.local/state/wett-agents"))
    os.makedirs(root, mode=0o700, exist_ok=True)
    return root


@contextlib.contextmanager
def _locked(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _load(jobdir):
    with open(os.path.join(jobdir, "meta.json")) as f:
        return json.load(f)


def _save(jobdir, meta):
    meta["updated"] = _now()
    tmp = os.path.join(jobdir, "meta.json.tmp")
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=1)
    os.replace(tmp, os.path.join(jobdir, "meta.json"))


def _user_run(argv, timeout=30, env=None):
    """Run a command against the caller's systemd user manager."""
    env = dict(os.environ if env is None else env)
    # An SSH forced command gets no XDG_RUNTIME_DIR; systemctl --user needs it.
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, env=env,
                          stdin=subprocess.DEVNULL)
    return proc.returncode, proc.stdout, proc.stderr


def _secret_env(env_files):
    """{NAME: file} -> {NAME: contents}; unreadable files are skipped."""
    out = {}
    for name, path in (env_files or {}).items():
        try:
            with open(path) as f:
                out[name] = f.read().strip()
        except OSError:
            pass
    return out


def _active_agent_units():
    """Names (without .service) of agent units that are still running."""
    rc, out, err = _user_run(["systemctl", "--user", "list-units", "--plain", "--no-legend", "--no-pager",
                              "--state=activating,active,deactivating,reloading", "--",
                              AGENT_UNIT_PREFIX + "*"])
    if rc != 0:
        raise Denied(f"cannot list agent units: {err.strip()[:300]}")
    return {line.split()[0].removesuffix(".service") for line in out.splitlines() if line.strip()}


def _launch(jobdir, unit, budget_s):
    argv = ["systemd-run", "--user", "--quiet", "--collect", f"--unit={unit}",
            f"--description=wett-mcp coding agent {os.path.basename(jobdir)}",
            f"--property=RuntimeMaxSec={budget_s + 300}",
            f"--setenv=PATH={os.environ.get('PATH', '/run/current-system/sw/bin')}",
            "--", sys.executable, os.path.abspath(__file__), "--run-agent", jobdir]
    rc, _, err = _user_run(argv)
    if rc != 0:
        raise Denied(f"could not start the agent unit: {redact(err.strip())[:300]}")


def _start_run(a, jobdir, meta):
    """Start a unit draining the inbox. Caller holds the global and the job lock."""
    running = _active_agent_units()
    limit = a.get("maxConcurrent", 3)
    if len(running) >= limit:
        raise Denied(f"{len(running)} agents are already running (limit {limit}); stop one or wait")
    meta["run"] += 1
    meta.update(state="running", unit=f"{AGENT_UNIT_PREFIX}{meta['id']}-{meta['run']}", error=None,
                run_started=_now())
    _save(jobdir, meta)
    try:
        _launch(jobdir, meta["unit"], meta["max_minutes"] * 60)
    except Exception as e:
        meta.update(state="failed", error=str(e)[:500])
        _save(jobdir, meta)
        raise


def _is_clone_of(path, owner, name):
    rc, out, _ = _user_run(["git", "-C", path, "remote", "get-url", "origin"], timeout=15)
    url = out.strip().lower().removesuffix("/").removesuffix(".git")
    want = f"{owner}/{name}".lower().removesuffix(".git")
    return rc == 0 and (url.endswith(f"github.com/{want}") or url.endswith(f"github.com:{want}"))


def _resolve_repo(a, owner, name):
    work = os.path.realpath(os.path.expanduser(a.get("workRoot", "~/work")))
    path = os.path.join(work, name)
    if owner is None:
        if not os.path.isdir(path):
            raise Denied(f"no directory {name!r} in the work root; pass owner/name to clone it")
    elif os.path.lexists(path):
        if not _is_clone_of(path, owner, name):
            raise Denied(f"{name!r} exists in the work root but is not a clone of {owner}/{name}")
    else:
        env = {**os.environ, **_secret_env(a.get("envFiles"))}
        rc, _, err = _user_run([a.get("gh", "gh"), "repo", "clone", f"{owner}/{name}", path], timeout=600,
                               env=env)
        if rc != 0:
            raise Denied(f"gh repo clone {owner}/{name} failed: {redact(err.strip())[-300:]}")
    real = os.path.realpath(path)
    if os.path.dirname(real) != work or not os.path.isdir(real):
        raise Denied(f"{name!r} resolves outside the work root")
    return real


def _jobdir(a, req):
    job_id = check_agent_id(req.get("id"))
    jobdir = os.path.join(_agents_root(a), job_id)
    if not os.path.isfile(os.path.join(jobdir, "meta.json")):
        raise Denied(f"no agent job {job_id}")
    return jobdir


def _state(meta, active):
    """Effective state: a 'running' job whose unit is gone died without recording it."""
    if meta.get("state") == "running" and meta.get("unit") not in active:
        return "failed", "the runner exited without recording a result (killed, OOM or box restart)"
    return meta.get("state"), meta.get("error")


def _last_activity(jobdir, meta):
    events = os.path.join(jobdir, "events", f"{meta.get('turns', 0)}.jsonl")
    stamps = [os.path.getmtime(os.path.join(jobdir, "meta.json"))]
    if os.path.exists(events):
        stamps.append(os.path.getmtime(events))
    return datetime.datetime.fromtimestamp(max(stamps)).astimezone().isoformat(timespec="seconds")


def _clip_text(text, limit):
    text = redact(text or "")
    return text if len(text) <= limit else text[:limit] + f"\n…[{len(text) - limit} more chars]"


def verb_agent_dispatch(req, cfg):
    a = _agents_cfg(cfg)
    owner, name = check_repo(req.get("repo"), a.get("cloneOwners", []))
    prompt = check_text(req.get("prompt"), "prompt", a.get("maxPromptChars", AGENT_PROMPT_MAX))
    title = check_title(req.get("title")) or check_title(prompt.strip().splitlines()[0][:60])
    minutes = check_minutes(req.get("max_minutes"), a.get("defaultMinutes", 60), a.get("maxMinutes", 240))
    root = _agents_root(a)
    cwd = _resolve_repo(a, owner, name)
    with _locked(os.path.join(root, ".lock")):
        running = _active_agent_units()
        if len(running) >= a.get("maxConcurrent", 3):
            raise Denied(f"{len(running)} agents are already running (limit {a.get('maxConcurrent', 3)})")
        job_id = secrets.token_hex(4)
        jobdir = os.path.join(root, job_id)
        os.makedirs(os.path.join(jobdir, "events"), mode=0o700)
        os.makedirs(os.path.join(jobdir, "session"), mode=0o700)
        note = os.path.join(jobdir, "system-note.md")
        with open(note, "w") as f:
            f.write(a.get("systemNote", AGENT_NOTE) + "\n")
        meta = {
            "id": job_id, "title": title, "repo": f"{owner}/{name}" if owner else name, "cwd": cwd,
            "created": _now(), "state": "new", "error": None, "unit": None, "run": 0, "turns": 0,
            "max_minutes": minutes, "session_id": None, "cost_usd": 0.0,
            "inbox": [{"text": prompt, "queued": _now(), "via": "dispatch"}],
            "runner": {"omp": a.get("omp", "omp"), "ompArgs": list(a.get("ompArgs", [])),
                       "envFiles": dict(a.get("envFiles", {})), "noteFile": note},
        }
        with _locked(os.path.join(jobdir, "lock")):
            _start_run(a, jobdir, meta)
    return {"id": job_id, "state": "running", "title": title, "repo": meta["repo"], "cwd": cwd,
            "max_minutes": minutes, "unit": meta["unit"]}


def verb_agent_send(req, cfg):
    a = _agents_cfg(cfg)
    jobdir = _jobdir(a, req)
    message = check_text(req.get("message"), "message", a.get("maxPromptChars", AGENT_PROMPT_MAX))
    with _locked(os.path.join(_agents_root(a), ".lock")), _locked(os.path.join(jobdir, "lock")):
        meta = _load(jobdir)
        if len(meta["inbox"]) >= AGENT_INBOX_MAX:
            raise Denied(f"{len(meta['inbox'])} messages are already queued")
        meta["inbox"].append({"text": message, "queued": _now(), "via": "send"})
        if meta["state"] == "running" and meta["unit"] in _active_agent_units():
            _save(jobdir, meta)
            return {"id": meta["id"], "state": "running", "queued": len(meta["inbox"]),
                    "note": "the agent is busy; the message runs as the next turn"}
        try:
            _start_run(a, jobdir, meta)
        except Denied:
            meta = _load(jobdir)
            meta["inbox"] = meta["inbox"][:-1]
            _save(jobdir, meta)
            raise
    return {"id": meta["id"], "state": "running", "queued": len(meta["inbox"]), "unit": meta["unit"],
            "note": "started a new run resuming the session"}


def verb_agent_stop(req, cfg):
    a = _agents_cfg(cfg)
    jobdir = _jobdir(a, req)
    with _locked(os.path.join(jobdir, "lock")):
        meta = _load(jobdir)
        was, unit, dropped = meta["state"], meta["unit"], len(meta["inbox"])
        meta["inbox"] = []
        if was == "running":
            meta.update(state="stopped", error="stopped by request")
        _save(jobdir, meta)
    if was == "running" and unit:
        # Outside the job lock: the runner records the interrupted turn under it.
        rc, _, err = _user_run(["systemctl", "--user", "stop", "--", unit + ".service"], timeout=120)
        if rc != 0 and unit in _active_agent_units():
            raise Denied(f"systemctl stop failed: {err.strip()[:300]}")
    return {"id": meta["id"], "state": meta["state"], "was": was, "dropped_queued": dropped}


def verb_agent_list(req, cfg):
    a = _agents_cfg(cfg)
    root = _agents_root(a)
    active = _active_agent_units()
    jobs = []
    for job_id in os.listdir(root):
        jobdir = os.path.join(root, job_id)
        if not AGENT_ID_RE.fullmatch(job_id) or not os.path.isfile(os.path.join(jobdir, "meta.json")):
            continue
        meta = _load(jobdir)
        state, error = _state(meta, active)
        jobs.append({"id": job_id, "title": meta.get("title"), "repo": meta.get("repo"), "state": state,
                     "error": _clip_text(error, 300) if error else None, "started": meta.get("created"),
                     "last_activity": _last_activity(jobdir, meta), "turns": meta.get("turns", 0),
                     "queued": len(meta.get("inbox", [])), "cost_usd": round(meta.get("cost_usd", 0.0), 4)})
    jobs.sort(key=lambda j: j["started"] or "", reverse=True)
    return {"running": len(active), "max_concurrent": a.get("maxConcurrent", 3), "jobs": jobs[:AGENT_LIST_MAX]}


def verb_agent_read(req, cfg):
    a = _agents_cfg(cfg)
    jobdir = _jobdir(a, req)
    since = req.get("since_turn", 0)
    if not isinstance(since, int) or isinstance(since, bool) or since < 0:
        raise Denied("since_turn must be a non-negative integer")
    meta = _load(jobdir)
    state, error = _state(meta, _active_agent_units())
    turns = []
    path = os.path.join(jobdir, "turns.jsonl")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try:
                    t = json.loads(line)
                except ValueError:
                    continue
                if t.get("turn", 0) > since:
                    turns.append({"turn": t.get("turn"), "status": t.get("status"), "via": t.get("via"),
                                  "prompt": _clip_text(t.get("prompt"), 500), "started": t.get("started"),
                                  "ended": t.get("ended"), "cost_usd": t.get("cost_usd"),
                                  "error": _clip_text(t.get("error"), 500) if t.get("error") else None,
                                  "final": _clip_text(t.get("final"), AGENT_TEXT_MAX)})
    omitted = max(0, len(turns) - AGENT_TURNS_MAX)
    out = {"id": meta["id"], "title": meta.get("title"), "repo": meta.get("repo"), "cwd": meta.get("cwd"),
           "state": state, "error": _clip_text(error, 500) if error else None, "started": meta.get("created"),
           "last_activity": _last_activity(jobdir, meta), "turn_count": meta.get("turns", 0),
           "cost_usd": round(meta.get("cost_usd", 0.0), 4), "turns": turns[omitted:],
           "omitted_earlier_turns": omitted,
           "queued": [_clip_text(m.get("text"), 300) for m in meta.get("inbox", [])],
           "session_id": meta.get("session_id")}
    if state == "running" and meta.get("turns", 0) > (turns[-1]["turn"] if turns else since):
        out["in_progress_turn"] = meta.get("turns")
    if meta.get("session_id"):
        out["resume_hint"] = (("agent_stop it first, then: " if state == "running" else "")
                              + f"cd {meta['cwd']} && omp --session-dir {os.path.join(jobdir, 'session')} "
                              f"--resume {meta['session_id']}")
    return out


# --- the runner (inside the transient unit) ------------------------------------


class OmpEvents:
    """Minimal reader of `omp --mode json` events: session id, final text, cost."""

    def __init__(self):
        self.session_id = None
        self.cost = 0.0
        self.last_agent_end = None

    def feed(self, line):
        try:
            ev = json.loads(line)
        except ValueError:
            return
        if not isinstance(ev, dict):
            return
        kind = ev.get("type")
        if kind == "session" and isinstance(ev.get("id"), str):
            self.session_id = ev["id"]
        elif kind == "message_end":
            msg = ev.get("message")
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                cost = ((msg.get("usage") or {}).get("cost") or {}).get("total")
                if isinstance(cost, (int, float)):
                    self.cost += cost
        elif kind == "agent_end":
            self.last_agent_end = ev

    def result(self, rc, stderr_tail=""):
        """(status, final text, error); status is ok | timed_out | failed."""
        if rc != 0:
            return "failed", None, f"omp exited {rc}: {stderr_tail}".strip()
        messages = (self.last_agent_end or {}).get("messages")
        if not isinstance(messages, list) or not messages:
            return "failed", None, "omp produced no agent_end event"
        last = messages[-1]
        if not isinstance(last, dict) or last.get("role") != "assistant":
            # --max-time cuts the run off with rc 0 and no error event.
            return "timed_out", None, "the turn hit its time limit before the agent answered"
        content = last.get("content")
        if isinstance(content, str):
            text = content
        else:
            text = "\n".join(b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text")
        if last.get("stopReason") == "error":
            return "failed", text or None, str(last.get("errorMessage") or "the model call failed")
        return "ok", text, None


def _agent_turn(meta, jobdir, turn, msg, budget_s):
    r = meta["runner"]
    argv = [r["omp"], "-p", "--mode", "json", "--no-title", "--cwd", meta["cwd"],
            "--session-dir", os.path.join(jobdir, "session"), "--max-time", str(budget_s),
            "--append-system-prompt", r["noteFile"], *r.get("ompArgs", [])]
    if meta.get("session_id") and AGENT_SESSION_RE.fullmatch(meta["session_id"]):
        argv += ["--resume", meta["session_id"]]
    # `--` ends flag parsing: the message is literal text even if it looks like a flag or an @file.
    argv += ["--", msg["text"]]
    env = {**os.environ, **_secret_env(r.get("envFiles"))}
    record = {"turn": turn, "via": msg.get("via"), "prompt": msg["text"][:2000], "started": _now()}
    events = OmpEvents()
    stderr_path = os.path.join(jobdir, "events", f"{turn}.stderr")
    proc = None
    try:
        with open(os.path.join(jobdir, "events", f"{turn}.jsonl"), "w") as out, open(stderr_path, "w") as err:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err,
                                    cwd=meta["cwd"], env=env, text=True)
            for line in proc.stdout:
                out.write(line)
                out.flush()
                events.feed(line)
            rc = proc.wait()
        with open(stderr_path) as f:
            tail = f.read()[-500:]
        status, final, error = events.result(rc, tail)
    except _Stopped:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        status, final, error = "stopped", None, "stopped before the turn finished"
    record.update(status=status, final=final, error=error, ended=_now(), cost_usd=round(events.cost, 6),
                  session_id=events.session_id)
    with open(os.path.join(jobdir, "turns.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")
    return record


def run_agent(jobdir):
    """Drain the job's inbox, one omp turn per queued message, then exit."""
    def on_term(signum, frame):
        raise _Stopped()

    signal.signal(signal.SIGTERM, on_term)
    lock = os.path.join(jobdir, "lock")
    try:
        with _locked(lock):
            meta = _load(jobdir)
        deadline = time.monotonic() + meta["max_minutes"] * 60
        while True:
            with _locked(lock):
                meta = _load(jobdir)
                if meta["state"] != "running":
                    return
                budget = int(deadline - time.monotonic())
                if not meta["inbox"] or budget < 60:
                    meta["state"] = "idle"
                    if meta["inbox"]:
                        meta["error"] = "this run's time budget is used up; agent_send to continue"
                    _save(jobdir, meta)
                    return
                msg = meta["inbox"].pop(0)
                meta["turns"] += 1
                turn = meta["turns"]
                _save(jobdir, meta)
            record = _agent_turn(meta, jobdir, turn, msg, budget)
            with _locked(lock):
                meta = _load(jobdir)
                if record["session_id"]:
                    meta["session_id"] = record["session_id"]
                meta["cost_usd"] = meta.get("cost_usd", 0.0) + record["cost_usd"]
                if record["status"] in ("failed", "stopped") and meta["state"] == "running":
                    meta.update(state=record["status"], error=record["error"])
                _save(jobdir, meta)
                if record["status"] in ("failed", "stopped"):
                    return
    except _Stopped:
        with _locked(lock):
            meta = _load(jobdir)
            if meta["state"] == "running":
                meta.update(state="stopped", error="the run was terminated")
                _save(jobdir, meta)


VERBS = {
    "status": verb_status,
    "unit_status": verb_unit_status,
    "unit_logs": verb_unit_logs,
    "df": verb_df,
    "ha_states": verb_ha_states,
    "ha_history": verb_ha_history,
    "ha_call": verb_ha_call,
    "agent_dispatch": verb_agent_dispatch,
    "agent_send": verb_agent_send,
    "agent_stop": verb_agent_stop,
    "agent_list": verb_agent_list,
    "agent_read": verb_agent_read,
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
    if len(sys.argv) == 3 and sys.argv[1] == "--run-agent":
        # Only reachable from the unit _launch starts: a forced command's argv is fixed.
        run_agent(sys.argv[2])
        return
    if len(sys.argv) < 2:
        print("usage: wett-mcp-hostd CONFIG [REQUEST-JSON] | --run-agent JOBDIR", file=sys.stderr)
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
