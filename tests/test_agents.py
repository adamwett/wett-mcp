"""hostd's agent_* verbs and the runner, against a fake `omp` on PATH."""

import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from wett_mcp import hostd

FAKE_OMP = textwrap.dedent('''\
    #!PYTHON
    """Fake omp: records its argv, emits omp-like JSON events; behaviour keyed off the prompt."""
    import json, os, sys, time, uuid
    args = sys.argv[1:]
    with open(os.environ["FAKE_OMP_LOG"], "a") as f:
        f.write(json.dumps({"argv": args, "cwd": os.getcwd(), "gh": os.environ.get("GH_TOKEN"),
                            "stdin_tty": sys.stdin.isatty(), "stdin": sys.stdin.read()}) + "\\n")
    prompt = args[args.index("--") + 1]
    session = args[args.index("--resume") + 1] if "--resume" in args else str(uuid.uuid4())
    def emit(ev):
        print(json.dumps(ev), flush=True)
    emit({"type": "session", "version": 3, "id": session, "cwd": os.getcwd()})
    emit({"type": "notice", "level": "warning", "message": "noise"})
    emit({"type": "agent_start"})
    if prompt.startswith("SLEEP"):
        time.sleep(float(prompt.split()[1]))
    if prompt.startswith("FAIL"):
        print("model exploded", file=sys.stderr)
        sys.exit(2)
    user = {"role": "user", "content": [{"type": "text", "text": prompt}]}
    if prompt.startswith("TIMEOUT"):
        emit({"type": "agent_end", "isTerminal": True, "yielded": True, "messages": [user]})
        sys.exit(0)
    reply = {"role": "assistant", "stopReason": "stop",
             "content": [{"type": "thinking", "thinking": "hmm"}, {"type": "text", "text": "done: " + prompt}],
             "usage": {"cost": {"total": 0.25}}}
    emit({"type": "message_end", "message": reply})
    emit({"type": "agent_end", "isTerminal": True, "yielded": True, "messages": [user, reply]})
''').replace("PYTHON", sys.executable)


class Box:
    """A fake agents host: work root, state dir, runner processes standing in for user units."""

    def __init__(self, tmp_path, monkeypatch):
        self.work = tmp_path / "work"
        (self.work / "proj").mkdir(parents=True)
        self.state = tmp_path / "state"
        bindir = tmp_path / "bin"
        bindir.mkdir()
        omp = bindir / "omp"
        omp.write_text(FAKE_OMP)
        omp.chmod(0o755)
        self.log = tmp_path / "omp.log"
        token = tmp_path / "gh-token"
        token.write_text("ghp_test\n")
        monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
        monkeypatch.setenv("FAKE_OMP_LOG", str(self.log))
        self.cfg = {"agents": {"workRoot": str(self.work), "stateDir": str(self.state), "cloneOwners": ["Owner"],
                               "maxConcurrent": 2, "envFiles": {"GH_TOKEN": str(token)}}}
        self.units = {}  # unit name -> Popen of the runner
        self.launched = []
        self.systemctl = []

        def launch(jobdir, unit, budget_s):
            self.launched.append((unit, budget_s))
            self.units[unit] = subprocess.Popen([sys.executable, hostd.__file__, "--run-agent", jobdir])

        def active():
            return {u for u, p in self.units.items() if p.poll() is None}

        real_user_run = hostd._user_run

        def user_run(argv, timeout=30, env=None):
            if argv[:3] == ["systemctl", "--user", "stop"]:
                self.systemctl.append(argv)
                proc = self.units[argv[-1].removesuffix(".service")]
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=30)
                return 0, "", ""
            return real_user_run(argv, timeout, env)

        monkeypatch.setattr(hostd, "_launch", launch)
        monkeypatch.setattr(hostd, "_active_agent_units", active)
        monkeypatch.setattr(hostd, "_user_run", user_run)

    def __call__(self, verb, **req):
        reply = hostd.handle({"verb": verb, **req}, self.cfg)
        return reply

    def ok(self, verb, **req):
        reply = self(verb, **req)
        assert reply["ok"], reply
        return reply["result"]

    def wait_idle(self, timeout=30):
        for p in self.units.values():
            p.wait(timeout=timeout)

    def omp_calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path, monkeypatch)
    yield b
    for p in b.units.values():
        if p.poll() is None:
            p.kill()


@pytest.mark.parametrize("repo", [
    "..", ".", "../proj", "/etc", "/home/agent/work/proj", "proj/", "a/b/c", "-rf", "--upload-pack=x",
    "-o/x", "proj\n", "pr oj", "", None, ["proj"], "evil/proj", "Owner/..", "Owner/-x", "-Owner/proj",
])
def test_bad_repos_rejected(box, repo):
    reply = box("agent_dispatch", repo=repo, prompt="hi")
    assert reply["ok"] is False
    assert box.launched == [] and box.omp_calls() == []


def test_missing_dir_and_symlink_escape_rejected(box, tmp_path):
    assert "no directory" in box("agent_dispatch", repo="nope", prompt="hi")["error"]
    outside = tmp_path / "outside"
    outside.mkdir()
    (box.work / "link").symlink_to(outside)
    assert "outside the work root" in box("agent_dispatch", repo="link", prompt="hi")["error"]
    assert box.launched == []


def test_clone_existing_dir_must_match_origin(box):
    subprocess.run(["git", "init", "-q", str(box.work / "other")], check=True)
    subprocess.run(["git", "-C", str(box.work / "other"), "remote", "add", "origin",
                    "https://github.com/someone/other.git"], check=True)
    reply = box("agent_dispatch", repo="owner/other", prompt="hi")
    assert reply["ok"] is False and "not a clone" in reply["error"]
    subprocess.run(["git", "-C", str(box.work / "other"), "remote", "set-url", "origin",
                    "git@github.com:Owner/other.git"], check=True)
    assert box.ok("agent_dispatch", repo="owner/other", prompt="hi")["cwd"] == str(box.work / "other")


@pytest.mark.parametrize("req", [
    {"prompt": ""}, {"prompt": "   "}, {"prompt": 5}, {"prompt": "x" * 20001}, {"prompt": "a\0b"},
    {"prompt": "hi", "max_minutes": 0}, {"prompt": "hi", "max_minutes": True}, {"prompt": "hi", "max_minutes": "5"},
    {"prompt": "hi", "title": 7},
])
def test_bad_dispatch_args_rejected(box, req):
    assert box("agent_dispatch", repo="proj", **req)["ok"] is False
    assert box.launched == []


@pytest.mark.parametrize("job_id", ["../x", "0123abc", "0123ABCD", "-0123abc", "", None, 12345678])
def test_bad_ids_rejected(box, job_id):
    for verb, extra in (("agent_read", {}), ("agent_send", {"message": "hi"}), ("agent_stop", {})):
        assert box(verb, id=job_id, **extra)["ok"] is False


def test_flag_like_prompt_is_literal_text(box):
    prompt = "--help @/etc/passwd --resume x"
    job = box.ok("agent_dispatch", repo="proj", prompt=prompt, max_minutes=10_000)
    assert job["max_minutes"] == 240 and box.launched[0][1] == 240 * 60
    box.wait_idle()
    (call,) = box.omp_calls()
    argv = call["argv"]
    assert argv[-2:] == ["--", prompt]
    assert argv.count("--") == 1 and "--resume" not in argv[:-1]
    assert argv[argv.index("--cwd") + 1] == str(box.work / "proj") == call["cwd"]
    assert call["gh"] == "ghp_test" and call["stdin"] == "" and not call["stdin_tty"]
    note = argv[argv.index("--append-system-prompt") + 1]
    assert "Claude Duet" in open(note).read()


def test_dispatch_send_resume_loop(box):
    job = box.ok("agent_dispatch", repo="proj", prompt="SLEEP 1.5 first", title="t")
    jid = job["id"]
    # While the first turn runs, follow-ups queue instead of starting another unit.
    time.sleep(0.3)
    assert box.ok("agent_send", id=jid, message="second")["queued"] == 1
    assert box.ok("agent_send", id=jid, message="third")["queued"] == 2
    assert box.ok("agent_read", id=jid)["queued"] == ["second", "third"]
    assert len(box.launched) == 1
    box.wait_idle()

    read = box.ok("agent_read", id=jid)
    assert read["state"] == "idle" and read["turn_count"] == 3 and read["queued"] == []
    assert [t["final"] for t in read["turns"]] == ["done: SLEEP 1.5 first", "done: second", "done: third"]
    assert [t["status"] for t in read["turns"]] == ["ok"] * 3
    assert read["cost_usd"] == 0.75
    calls = box.omp_calls()
    session = read["session_id"]
    assert "--resume" not in calls[0]["argv"]
    assert [c["argv"][c["argv"].index("--resume") + 1] for c in calls[1:]] == [session, session]
    assert session in read["resume_hint"] and "--session-dir" in read["resume_hint"]
    assert box.ok("agent_read", id=jid, since_turn=2)["turns"][0]["turn"] == 3

    # Idle job: a message starts a new run that resumes the same session.
    assert box.ok("agent_send", id=jid, message="fourth")["note"].startswith("started")
    assert [u for u, _ in box.launched] == [f"wett-agent-{jid}-1", f"wett-agent-{jid}-2"]
    box.wait_idle()
    read = box.ok("agent_read", id=jid)
    assert read["turns"][-1]["final"] == "done: fourth" and read["session_id"] == session

    (listed,) = box.ok("agent_list")["jobs"]
    assert listed["id"] == jid and listed["state"] == "idle" and listed["turns"] == 4 and listed["title"] == "t"


def test_concurrency_cap(box):
    a = box.ok("agent_dispatch", repo="proj", prompt="SLEEP 3 a")["id"]
    box.ok("agent_dispatch", repo="proj", prompt="SLEEP 3 b")
    reply = box("agent_dispatch", repo="proj", prompt="c")
    assert reply["ok"] is False and "limit 2" in reply["error"]
    assert len(box.launched) == 2 and len(box.ok("agent_list")["jobs"]) == 2
    box.wait_idle()
    # A message to an idle job needs a slot too; it is not left queued when refused.
    box.ok("agent_dispatch", repo="proj", prompt="SLEEP 3 d")
    box.ok("agent_dispatch", repo="proj", prompt="SLEEP 3 e")
    reply = box("agent_send", id=a, message="more")
    assert reply["ok"] is False and "limit" in reply["error"]
    assert box.ok("agent_read", id=a)["queued"] == []


def test_stop_kills_turn_and_keeps_session(box):
    jid = box.ok("agent_dispatch", repo="proj", prompt="SLEEP 30 long")["id"]
    time.sleep(1)
    box.ok("agent_send", id=jid, message="queued one")
    start = time.monotonic()
    stopped = box.ok("agent_stop", id=jid)
    assert time.monotonic() - start < 20
    assert stopped == {"id": jid, "state": "stopped", "was": "running", "dropped_queued": 1}
    assert box.systemctl[0][-1] == f"wett-agent-{jid}-1.service"
    read = box.ok("agent_read", id=jid)
    assert read["state"] == "stopped" and read["queued"] == []
    assert [t["status"] for t in read["turns"]] == ["stopped"]
    assert len(box.omp_calls()) == 1  # the queued message never ran
    # Stopping again is a no-op; a message resumes the session.
    assert box.ok("agent_stop", id=jid)["was"] == "stopped"
    box.ok("agent_send", id=jid, message="carry on")
    box.wait_idle()
    read = box.ok("agent_read", id=jid)
    assert read["state"] == "idle" and read["turns"][-1]["final"] == "done: carry on"
    assert box.omp_calls()[-1]["argv"][box.omp_calls()[-1]["argv"].index("--resume") + 1] == read["session_id"]


def test_failed_and_timed_out_turns(box):
    jid = box.ok("agent_dispatch", repo="proj", prompt="TIMEOUT please")["id"]
    box.wait_idle()
    read = box.ok("agent_read", id=jid)
    assert read["turns"][0]["status"] == "timed_out" and read["state"] == "idle"
    box.ok("agent_send", id=jid, message="FAIL now")
    box.wait_idle()
    read = box.ok("agent_read", id=jid)
    assert read["state"] == "failed" and read["turns"][-1]["status"] == "failed"
    assert "exited 2" in read["error"] and "model exploded" in read["turns"][-1]["error"]
    box.ok("agent_send", id=jid, message="recover")
    box.wait_idle()
    assert box.ok("agent_read", id=jid)["state"] == "idle"


def test_dead_runner_reported_as_failed(box):
    jid = box.ok("agent_dispatch", repo="proj", prompt="SLEEP 30 x")["id"]
    time.sleep(0.5)
    proc = box.units[f"wett-agent-{jid}-1"]
    proc.kill()  # SIGKILL: nothing gets recorded
    proc.wait()
    read = box.ok("agent_read", id=jid)
    assert read["state"] == "failed" and "without recording" in read["error"]


def test_final_text_redacted_and_clipped():
    ev = hostd.OmpEvents()
    text = "token=hunter2hunter2 " + "word " * 2000
    ev.feed(json.dumps({"type": "agent_end", "messages": [{"role": "assistant", "content": [
        {"type": "text", "text": text}]}]}))
    status, final, _ = ev.result(0)
    assert status == "ok" and final == text
    clipped = hostd._clip_text(final, hostd.AGENT_TEXT_MAX)
    assert "hunter2" not in clipped and "more chars" in clipped


def test_events_parser_edge_cases():
    ev = hostd.OmpEvents()
    for line in ["not json", "[]", json.dumps({"type": "session", "id": "abc"})]:
        ev.feed(line)
    assert ev.session_id == "abc"
    assert ev.result(0)[0] == "failed"  # no agent_end
    ev.feed(json.dumps({"type": "agent_end", "messages": [
        {"role": "assistant", "stopReason": "error", "errorMessage": "overloaded", "content": []}]}))
    assert ev.result(0) == ("failed", None, "overloaded")
    assert ev.result(1, "boom")[0] == "failed"


def test_agents_disabled_without_config():
    reply = hostd.handle({"verb": "agent_list"}, {})
    assert reply == {"ok": False, "error": "coding agents are not enabled on this host"}
