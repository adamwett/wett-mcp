import json
import os
import subprocess
import sys

import pytest

from wett_mcp import hostd

CFG = {
    "units": ["nginx.service", "container@*.service", "sops-install-secrets.service"],
    "ha": {
        "url": "http://ha.invalid:8123",
        "tokenFile": "/nonexistent",
        "allow": [
            {"service": "light.*", "entities": ["light.*"]},
            {"service": "climate.set_temperature", "entities": ["climate.office"]},
        ],
        "hideEntities": ["sensor.secret_*"],
        "exposeEntities": ["person.owner"],
    },
}


def run(req):
    return hostd.handle(req, CFG)


@pytest.mark.parametrize("req", [
    None,
    [],
    {"verb": "exec", "cmd": "id"},
    {"verb": "__class__"},
    {"verb": ["status"]},
])
def test_unknown_or_malformed_requests_rejected(req):
    reply = run(req)
    assert reply["ok"] is False


@pytest.mark.parametrize("unit", [
    "sshd.service",                 # not allowlisted
    "--output=json",                # option injection
    "-nginx.service",
    "nginx.service; id",            # shell metacharacters
    "container@../../etc.service",  # path-ish
    "",
    ["nginx.service"],
])
def test_unit_allowlist(unit, monkeypatch):
    calls = []
    monkeypatch.setattr(hostd, "_run", lambda argv, timeout=15: calls.append(argv) or (0, "Id=x\n", ""))
    for verb in ("unit_status", "unit_logs"):
        reply = run({"verb": verb, "unit": unit})
        assert reply["ok"] is False, (verb, unit)
    assert calls == []


def test_allowlisted_unit_reaches_systemctl(monkeypatch):
    calls = []
    monkeypatch.setattr(hostd, "_run", lambda argv, timeout=15: calls.append(argv) or (0, "Id=nginx.service\n", ""))
    assert run({"verb": "unit_status", "unit": "container@arr.service"})["ok"]
    assert calls[0][-2:] == ["--", "container@arr.service"]


def test_secret_units_logs_never_returned(monkeypatch):
    monkeypatch.setattr(hostd, "_run", lambda argv, timeout=15: (0, "line\n", ""))
    reply = run({"verb": "unit_logs", "unit": "sops-install-secrets.service"})
    assert reply["ok"] is False and "never" in reply["error"]


@pytest.mark.parametrize("since", ["--until=now", "-1h --grep x", "now; id", "1 hour ago", "-99999h"])
def test_logs_since_validated(since, monkeypatch):
    monkeypatch.setattr(hostd, "_run", lambda argv, timeout=15: pytest.fail("must not run"))
    assert run({"verb": "unit_logs", "unit": "nginx.service", "since": since})["ok"] is False


def test_logs_capped_filtered_and_redacted(monkeypatch):
    seen = {}
    lines = [f"line {i} ok" for i in range(5000)] + [
        "auth ok Authorization: Bearer abc.def.ghi",
        "auth ok api_key=supersecretvalue123",
        "auth ok token " + "a" * 40,
    ]

    def fake(argv, timeout=15):
        seen["argv"] = argv
        return 0, "\n".join(lines), ""

    monkeypatch.setattr(hostd, "_run", fake)
    reply = run({"verb": "unit_logs", "unit": "nginx.service", "lines": 10_000})
    assert reply["ok"] and len(reply["result"]["lines"]) == hostd.MAX_LOG_LINES
    reply = run({"verb": "unit_logs", "unit": "nginx.service", "grep": "AUTH"})
    out = "\n".join(reply["result"]["lines"])
    assert len(reply["result"]["lines"]) == 3
    assert "abc.def.ghi" not in out and "supersecretvalue123" not in out and "a" * 40 not in out


@pytest.mark.parametrize("domain,service,data", [
    ("lock", "unlock", {"entity_id": "lock.front"}),
    ("alarm_control_panel", "alarm_disarm", {"entity_id": "alarm_control_panel.home"}),
    ("cover", "open_cover", {"entity_id": "cover.garage"}),
    ("homeassistant", "turn_on", {"entity_id": "light.kitchen"}),
    ("homeassistant", "restart", {"entity_id": "light.kitchen"}),
    ("shell_command", "anything", {"entity_id": "light.kitchen"}),
    ("light", "turn_on", {"area_id": "kitchen", "entity_id": "light.kitchen"}),
    ("light", "turn_on", {"entity_id": "all"}),
    ("light", "turn_on", {}),
    ("light", "turn_on", {"entity_id": "lock.front"}),
    ("climate", "set_temperature", {"entity_id": "climate.bedroom", "temperature": 20}),
    ("climate", "set_hvac_mode", {"entity_id": "climate.office", "hvac_mode": "off"}),
    ("fan", "turn_on", {"entity_id": "fan.attic"}),
    ("Light", "turn_on", {"entity_id": "light.kitchen"}),
])
def test_ha_policy_denies(domain, service, data):
    with pytest.raises(hostd.Denied):
        hostd.ha_policy(domain, service, data, CFG["ha"]["allow"])


@pytest.mark.parametrize("domain,service,data", [
    ("light", "turn_on", {"entity_id": "light.kitchen", "brightness_pct": 40}),
    ("light", "turn_off", {"entity_id": ["light.kitchen", "light.hall"]}),
    ("climate", "set_temperature", {"entity_id": "climate.office", "temperature": 21}),
])
def test_ha_policy_allows(domain, service, data):
    hostd.ha_policy(domain, service, data, CFG["ha"]["allow"])


def test_deny_list_beats_allowlist():
    with pytest.raises(hostd.Denied):
        hostd.ha_policy("lock", "unlock", {"entity_id": "lock.front"}, [{"service": "*", "entities": ["*"]}])


def test_ha_call_denied_never_contacts_ha(monkeypatch):
    monkeypatch.setattr(hostd, "_ha_request", lambda *a, **k: pytest.fail("must not call HA"))
    reply = run({"verb": "ha_call", "domain": "lock", "service": "unlock", "data": {"entity_id": "lock.front"}})
    assert reply["ok"] is False


def test_ha_states_hides_people_and_configured_entities():
    states = [
        {"entity_id": "light.kitchen", "state": "on", "attributes": {"friendly_name": "Kitchen"}},
        {"entity_id": "person.someone", "state": "home", "attributes": {}},
        {"entity_id": "person.owner", "state": "home", "attributes": {}},
        {"entity_id": "device_tracker.phone", "state": "home", "attributes": {}},
        {"entity_id": "camera.door", "state": "idle", "attributes": {}},
        {"entity_id": "sensor.secret_code", "state": "1234", "attributes": {}},
    ]
    ids = [s["entity_id"] for s in hostd.filter_states(states, CFG["ha"])]
    assert ids == ["light.kitchen", "person.owner"]
    assert [s["entity_id"] for s in hostd.filter_states(states, CFG["ha"], search="kitch")] == ["light.kitchen"]


def test_ha_history_refuses_hidden_entity(monkeypatch):
    monkeypatch.setattr(hostd, "_ha_request", lambda *a, **k: pytest.fail("must not call HA"))
    assert run({"verb": "ha_history", "entity_id": "device_tracker.phone"})["ok"] is False


def test_forced_command_entrypoint(tmp_path):
    """The SSH path: request in SSH_ORIGINAL_COMMAND, one JSON reply on stdout."""
    cfg = tmp_path / "hostd.json"
    cfg.write_text(json.dumps(CFG))
    env = {**os.environ, "SSH_ORIGINAL_COMMAND": json.dumps({"verb": "unit_status", "unit": "sshd.service"})}
    out = subprocess.run([sys.executable, hostd.__file__, str(cfg)], env=env, capture_output=True, text=True,
                         check=True).stdout
    assert json.loads(out) == {"ok": False, "error": "unit 'sshd.service' is not allowlisted on this host"}
    env["SSH_ORIGINAL_COMMAND"] = "id; cat /etc/shadow"
    assert json.loads(subprocess.run([sys.executable, hostd.__file__, str(cfg)], env=env, capture_output=True,
                                     text=True, check=True).stdout)["ok"] is False
