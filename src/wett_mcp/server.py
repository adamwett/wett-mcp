"""wett-mcp: remote MCP server exposing a small, allowlisted view of a homelab."""

import argparse
import asyncio
import datetime
import json
import os
import inspect
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

import anyio
import httpx
import uvicorn
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.routing import Route

from . import hostd, printer
from .oauth import SCOPE_AGENTS, SCOPE_READ, SCOPE_WRITE, AccessVerifier, AuthServer, Store, Verifier

READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
# Agents run code that reaches the internet and can push to GitHub.
AGENT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)
MAX_RESULT_CHARS = 60_000
PROM_MAX_RANGE_MIN = 7 * 24 * 60
PROM_MAX_POINTS = 1000
PROM_MAX_SERIES = 200


def secret(cfg: dict, name: str | None) -> str | None:
    """Read a secret file; relative names resolve in $CREDENTIALS_DIRECTORY."""
    if not name:
        return None
    path = Path(name)
    if not path.is_absolute():
        path = Path(os.environ.get("CREDENTIALS_DIRECTORY", cfg.get("stateDir", "."))) / name
    return path.read_text().strip()


class Audit:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, **entry: Any) -> None:
        entry = {"ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), **entry}
        line = hostd.redact(json.dumps(entry, default=str))
        with self._lock, self.path.open("a") as f:
            f.write(line + "\n")


class AuthFailureAlarm:
    """ASGI wrapper: count 401s; notify once per window when over threshold."""

    def __init__(self, app, lab: "Lab", threshold: int, window: int):
        self.app, self.lab, self.threshold, self.window = app, lab, threshold, window
        self.hits: list[float] = []
        self.alerted_until = 0.0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def watch(message):
            if message["type"] == "http.response.start" and message["status"] == 401:
                now = time.time()
                self.hits = [t for t in self.hits if t > now - self.window] + [now]
                if len(self.hits) > self.threshold and now > self.alerted_until:
                    self.alerted_until = now + self.window
                    self.lab.audit.write(event="auth_failure_burst", count=len(self.hits))
                    try:
                        await self.lab.notify(f"{len(self.hits)} unauthenticated requests in "
                                              f"{self.window // 60} min", "auth alert")
                    except Exception:  # noqa: BLE001 - alerting must not break serving
                        pass
            await send(message)

        await self.app(scope, receive, watch)


class Lab:
    """Backends the tools talk to."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.audit = Audit(Path(cfg["stateDir"]) / "audit.jsonl")
        self.printer = printer.Printer(cfg["printer"]) if cfg.get("printer") else None
        self.hosts: dict[str, dict] = cfg.get("hosts", {})
        self._notify_times: list[float] = []

    async def hostd(self, host: str, req: dict) -> Any:
        spec = self.hosts.get(host)
        if spec is None:
            raise ToolError(f"unknown host {host!r}; known: {sorted(self.hosts)}")
        if spec.get("ssh"):
            argv = ["ssh", "-F", "/dev/null", "-i", self._ssh_key_path(spec.get("keyFile")), "-o", "BatchMode=yes",
                    "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", f"GlobalKnownHostsFile={self.cfg.get('sshKnownHostsFile', '/etc/ssh/ssh_known_hosts')}",
                    "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
                    spec["ssh"], json.dumps(req)]
            proc = await anyio.run_process(argv, check=False)
            try:
                reply = json.loads(proc.stdout.decode())
            except ValueError:
                raise ToolError(f"{host}: hostd unreachable ({hostd.redact(proc.stderr.decode())[:300]})") from None
        else:
            reply = await anyio.to_thread.run_sync(hostd.handle, req, self.cfg.get("localHostd", {}))
        if not reply.get("ok"):
            raise ToolError(f"{host}: {reply.get('error')}")
        return reply["result"]

    def _ssh_key_path(self, name: str | None = None) -> str:
        """The host's own key if it has one, else the shared sshKeyFile."""
        name = name or self.cfg["sshKeyFile"]
        if os.path.isabs(name):
            return name
        return str(Path(os.environ.get("CREDENTIALS_DIRECTORY", ".")) / name)

    async def prom(self, path: str, params: dict) -> Any:
        prom = self.cfg.get("prometheus")
        if not prom:
            raise ToolError("Prometheus is not configured")
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(prom["url"].rstrip("/") + path, params=params)
        body = resp.json()
        if body.get("status") != "success":
            raise ToolError(f"prometheus: {body.get('error', resp.status_code)}")
        return body["data"]

    async def notify(self, message: str, title: str | None = None, guardrail: bool = False) -> None:
        """Push to the owner's phone. guardrail=True (agent alerts) skips lab_notify's rate limit and is
        titled `<prefix> → <title>`, so it can't be mistaken for a lab_notify message."""
        n = self.cfg.get("notify")
        if not n:
            raise ToolError("notifications are not configured")
        now = time.time()
        if not guardrail:
            self._notify_times = [t for t in self._notify_times if t > now - 3600]
            if len(self._notify_times) >= n.get("maxPerHour", 10):
                raise ToolError("notification rate limit reached; try later")
            self._notify_times.append(now)
        prefix = n.get("titlePrefix", "Claude")
        if guardrail:
            full_title = f"{prefix} → {title}"
        else:
            full_title = f"{prefix}: {title}" if title else prefix
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(n["url"], json={"message": message[:1000], "title": full_title[:100]},
                                     headers={"Authorization": f"Bearer {secret(self.cfg, n['tokenFile'])}"})
        if resp.status_code >= 300:
            raise ToolError(f"notify relay returned HTTP {resp.status_code}")


def _token(ctx: Context):
    request = ctx.request_context.request
    user = request.scope.get("user") if request is not None else None
    return user.access_token if isinstance(user, AuthenticatedUser) else None


def _clip(value: Any) -> Any:
    text = json.dumps(value, default=str)
    if len(text) <= MAX_RESULT_CHARS:
        return value
    return {"truncated": True, "chars": len(text), "head": text[:MAX_RESULT_CHARS]}


def build_mcp(cfg: dict, lab: Lab, auth: AuthServer) -> FastMCP:
    public = urllib.parse.urlsplit(cfg["publicUrl"])
    mcp = FastMCP(
        "wett-mcp",
        instructions="Read-mostly access to a homelab: host and service health, logs, metrics, "
                     "Home Assistant, media queues, the printer, and phone notifications. Write tools need "
                     "lab.write. agent_* tools dispatch and talk to headless coding agents (dispatch/send/stop "
                     "need lab.agents); each turn ends with the agent's summary, which agent_read returns.",
        token_verifier=Verifier(auth),
        auth=AuthSettings(issuer_url=cfg["publicUrl"], resource_server_url=cfg["publicUrl"].rstrip("/") + "/mcp",
                          required_scopes=[SCOPE_READ]),
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[public.netloc, "127.0.0.1:*", "localhost:*"],
            allowed_origins=[f"{public.scheme}://{public.netloc}"],
        ),
    )

    def tool(annotations: ToolAnnotations, scope: str = SCOPE_READ, omit: tuple[str, ...] = ()):
        """Register a tool with scope check, audit and output clipping. `omit`: arguments the audit log
        records only by length (document contents)."""

        def deco(fn):
            async def run(ctx: Context, **kwargs):
                token = _token(ctx)
                scopes = token.scopes if token else []
                args = {k: {"omitted_chars": len(v)} if k in omit and isinstance(v, str) else v
                        for k, v in kwargs.items()}
                entry = {"tool": fn.__name__, "args": args, "client": getattr(token, "client_id", None),
                         "family": getattr(token, "family", None)}
                if scope not in scopes:
                    # The SDK checks scopes per endpoint, not per tool, so this can't be a 403
                    # insufficient_scope challenge; the message says how to step up instead.
                    lab.audit.write(**entry, ok=False, error=f"missing {scope}")
                    raise ToolError(f"{fn.__name__} requires the {scope} scope, which this connection was not "
                                    "granted. Disconnect and reconnect the connector, then tick the matching "
                                    "box on the consent page.")
                try:
                    result = _clip(await fn(**kwargs))
                except ToolError as e:
                    lab.audit.write(**entry, ok=False, error=str(e))
                    raise
                except Exception as e:
                    lab.audit.write(**entry, ok=False, error=f"{type(e).__name__}: {e}")
                    raise ToolError(f"{type(e).__name__}: {hostd.redact(str(e))[:300]}") from None
                lab.audit.write(**entry, ok=True, chars=len(json.dumps(result, default=str)))
                return result

            # FastMCP builds the schema from the signature: keep fn's, add ctx.
            sig = inspect.signature(fn)
            params = list(sig.parameters.values()) + [
                inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, annotation=Context)]
            run.__signature__ = sig.replace(parameters=params)
            run.__annotations__ = {**fn.__annotations__, "ctx": Context}
            run.__name__, run.__doc__ = fn.__name__, fn.__doc__
            mcp.add_tool(run, name=fn.__name__, description=fn.__doc__, annotations=annotations)
            return fn

        return deco

    host_label = cfg.get("prometheus", {}).get("hostLabel", "instance")

    @tool(READ)
    async def lab_overview() -> dict:
        """Health of every host: uptime, load, memory, failed systemd units, running containers,
        plus root filesystem usage and scrape status from Prometheus."""

        async def one(host):
            try:
                return host, await lab.hostd(host, {"verb": "status"})
            except ToolError as e:
                return host, {"error": str(e)}

        results = dict(await asyncio.gather(*(one(h) for h in lab.hosts)))
        if cfg.get("prometheus"):
            try:
                up = await lab.prom("/api/v1/query", {"query": "up"})
                disk = await lab.prom("/api/v1/query", {"query": (
                    '100 * (1 - node_filesystem_avail_bytes{mountpoint="/"} '
                    '/ node_filesystem_size_bytes{mountpoint="/"})')})
                results["prometheus"] = {
                    "targets": [{"host": r["metric"].get(host_label), "job": r["metric"].get("job"),
                                 "up": r["value"][1] == "1"} for r in up["result"]],
                    "root_disk_used_pct": {r["metric"].get(host_label): round(float(r["value"][1]), 1)
                                           for r in disk["result"]},
                }
            except (ToolError, httpx.HTTPError) as e:
                results["prometheus"] = {"error": str(e)}
        return results

    @tool(READ)
    async def prom_query(query: str, range_minutes: int = 0, step_seconds: int = 60) -> dict:
        """Run a PromQL query against the lab's Prometheus. range_minutes=0 is an instant query;
        otherwise a range query over the last range_minutes (max 7 days)."""
        if range_minutes <= 0:
            data = await lab.prom("/api/v1/query", {"query": query, "timeout": "10s"})
        else:
            range_minutes = min(range_minutes, PROM_MAX_RANGE_MIN)
            step = max(step_seconds, (range_minutes * 60) // PROM_MAX_POINTS, 1)
            end = time.time()
            data = await lab.prom("/api/v1/query_range", {
                "query": query, "start": end - range_minutes * 60, "end": end, "step": step, "timeout": "10s"})
        result = data.get("result")
        if isinstance(result, list) and len(result) > PROM_MAX_SERIES:
            data = {**data, "result": result[:PROM_MAX_SERIES], "truncated_series": len(result)}
        return data

    @tool(READ)
    async def unit_status(host: str, unit: str) -> dict:
        """State of one allowlisted systemd unit (service, container@name, timer) on a host."""
        return await lab.hostd(host, {"verb": "unit_status", "unit": unit})

    @tool(READ)
    async def unit_logs(host: str, unit: str, since: str = "-1h", lines: int = 100, grep: str | None = None) -> dict:
        """Recent journal lines of an allowlisted unit (max 300, secrets redacted). since: -30min, -2h, -1d,
        today, yesterday or YYYY-MM-DD[ HH:MM]. grep: optional case-insensitive substring filter."""
        return await lab.hostd(host, {"verb": "unit_logs", "unit": unit, "since": since, "lines": lines,
                                      "grep": grep})

    def ha_host() -> str:
        host = cfg.get("haHost")
        if not host:
            raise ToolError("Home Assistant is not configured")
        return host

    @tool(READ)
    async def ha_states(domain: str | None = None, search: str | None = None) -> list:
        """Current Home Assistant entity states, optionally filtered by domain (e.g. light, climate,
        sensor) and a substring of entity id or friendly name. People, trackers and cameras are hidden."""
        return await lab.hostd(ha_host(), {"verb": "ha_states", "domain": domain, "search": search})

    @tool(READ)
    async def ha_history(entity_id: str, hours: float = 6) -> list:
        """State history of one Home Assistant entity over the last `hours` (max 48)."""
        return await lab.hostd(ha_host(), {"verb": "ha_history", "entity_id": entity_id, "hours": hours})

    @tool(READ)
    async def media_status() -> dict:
        """Media server status: download queues (Sonarr, Radarr, SABnzbd, qBittorrent), upcoming episodes
        and movies for the next 7 days, and recently added Jellyfin items."""
        return await media(cfg, lab)

    @tool(WRITE, scope=SCOPE_WRITE)
    async def lab_notify(message: str, title: str | None = None) -> dict:
        """Push a notification to the lab owner's phone. Rate limited."""
        await lab.notify(message, title)
        return {"sent": True}

    @tool(WRITE, scope=SCOPE_WRITE)
    async def ha_call_service(domain: str, service: str, entity_id: list[str],
                              data: dict | None = None) -> dict:
        """Call a Home Assistant service on named entities, e.g. light.turn_on with
        data={"brightness_pct": 40}. Only allowlisted service/entity pairs work; locks, alarms, covers and
        HA administration are always denied. Every call is also pushed to the owner's phone."""
        payload = {**(data or {}), "entity_id": entity_id}
        hostd.ha_policy(domain, service, payload, [{"service": "*", "entities": ["*"]}])  # deny list early
        result = await lab.hostd(ha_host(), {"verb": "ha_call", "domain": domain, "service": service,
                                             "data": payload})
        if cfg.get("notify"):
            try:
                await lab.notify(f"{domain}.{service} on {', '.join(entity_id)}", "Home Assistant")
            except ToolError:
                pass
        return result

    if lab.printer is not None:
        @tool(READ)
        async def printer_status() -> dict:
            """The home printer over IPP: model, state (idle, processing, stopped) and reasons such as
            media-empty or toner-low, ink/toner levels, paper loaded, duplex support, accepted formats, and
            unfinished jobs (on the printer and, if jobs go through a CUPS queue, on the queue)."""
            return await lab.printer.status()

        @tool(WRITE, scope=SCOPE_WRITE, omit=("text", "document_base64"))
        async def print_document(text: str | None = None, document_base64: str | None = None,
                                 title: str | None = None, copies: int = 1, duplex: bool = False,
                                 paper: str | None = None) -> dict:
            """Print on the home printer. Give exactly one of text (plain text, printed in Courier) or
            document_base64 (a PDF, JPEG or PNG, base64-encoded). title: job name shown on the printer.
            copies: 1 to the configured cap. duplex: two-sided, long-edge binding. paper: letter, legal, a4,
            a5, a6, 4x6, 5x7 or a PWG media name (default: the printer's). Size, page and copy counts are
            capped. Every job is logged and pushed to the owner's phone."""
            job = await lab.printer.print(text, document_base64, title, copies, duplex, paper)
            lab.audit.write(event="print_job", **job)
            if cfg.get("notify"):
                try:
                    await lab.notify(f"{job['title']}: {job['pages']} page(s) x {copies}", "Printer")
                except (ToolError, httpx.HTTPError, OSError):  # the job is already printing
                    pass
            return job

    agents_host = cfg.get("agentsHost")
    if agents_host:
        async def alert(text: str) -> None:
            """Guardrail push for every agent action; fails closed for dispatch/send."""
            if not cfg.get("notify"):
                return
            try:
                await lab.notify(text, "agent", guardrail=True)
            except (ToolError, httpx.HTTPError) as e:
                raise ToolError(f"refused: the phone notification for this agent action failed ({e})") from None

        @tool(AGENT, scope=SCOPE_AGENTS)
        async def agent_dispatch(repo: str, prompt: str, title: str | None = None,
                                 max_minutes: int | None = None) -> dict:
            """Start a headless coding agent (oh-my-pi) on the agents host. repo: a directory name in the
            agents' work root, or a GitHub owner/name (cloned if missing; owners are allowlisted). prompt: the
            task, self-contained (nobody answers questions mid-run). The agent works on a branch and opens a
            PR; it never pushes default branches unless the prompt says so. max_minutes: run time budget
            (default 60, capped by the host). Returns a job id; agent_read shows the agent's final summary.
            Every dispatch is pushed to the owner's phone."""
            hostd.check_repo(repo)
            hostd.check_text(prompt, "prompt")
            title = hostd.check_title(title)
            if max_minutes is not None:
                hostd.check_minutes(max_minutes, 1, max_minutes)
            await alert(f"dispatch in {repo}: {prompt.strip()[:120]}")
            return await lab.hostd(agents_host, {"verb": "agent_dispatch", "repo": repo, "prompt": prompt,
                                                 "title": title, "max_minutes": max_minutes})

        @tool(AGENT, scope=SCOPE_AGENTS)
        async def agent_send(id: str, message: str) -> dict:
            """Send a follow-up message to an agent job. Queued as its next turn if it is busy; if it is
            idle, finished, failed or stopped, a new run resumes the same session with it."""
            hostd.check_agent_id(id)
            hostd.check_text(message, "message")
            await alert(f"message to {id}: {message.strip()[:120]}")
            return await lab.hostd(agents_host, {"verb": "agent_send", "id": id, "message": message})

        @tool(ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False),
              scope=SCOPE_AGENTS)
        async def agent_stop(id: str) -> dict:
            """Stop an agent job's current run and drop its queued messages. The session is kept:
            agent_send resumes it later."""
            hostd.check_agent_id(id)
            result = await lab.hostd(agents_host, {"verb": "agent_stop", "id": id})
            try:
                await alert(f"stopped {id}")
            except ToolError:
                pass
            return result

        @tool(READ)
        async def agent_list() -> dict:
            """Agent jobs, newest first: id, title, repo, state (running, idle, stopped, failed), start and
            last activity, turn count, queued messages, cost."""
            return await lab.hostd(agents_host, {"verb": "agent_list"})

        @tool(READ)
        async def agent_read(id: str, since_turn: int = 0) -> dict:
            """An agent job's state and, per finished turn after since_turn, the prompt and the agent's final
            message (redacted, clipped), plus queued messages and how to resume the session by hand."""
            hostd.check_agent_id(id)
            return await lab.hostd(agents_host, {"verb": "agent_read", "id": id, "since_turn": since_turn})

    return mcp


async def media(cfg: dict, lab: Lab) -> dict:
    m = cfg.get("media") or {}
    if not m:
        raise ToolError("no media services configured")
    out: dict[str, Any] = {}
    today = datetime.date.today()
    window = {"start": today.isoformat(), "end": (today + datetime.timedelta(days=7)).isoformat()}

    async with httpx.AsyncClient(timeout=10) as client:

        async def arr(name, calendar_key):
            s = m[name]
            h = {"X-Api-Key": secret(cfg, s["keyFile"])}
            base = s["url"].rstrip("/") + "/api/v3"
            q = (await client.get(f"{base}/queue", params={"pageSize": 20}, headers=h)).json()
            cal = (await client.get(f"{base}/calendar", params={**window, "includeSeries": "true"}, headers=h)).json()
            return {
                "queue": [{"title": r.get("title"), "status": r.get("status"),
                           "left": r.get("timeleft"), "size": r.get("size")} for r in q.get("records", [])],
                "upcoming": [calendar_key(c) for c in cal],
            }

        async def sabnzbd():
            s = m["sabnzbd"]
            q = (await client.get(s["url"].rstrip("/") + "/api", params={
                "mode": "queue", "output": "json", "apikey": secret(cfg, s["keyFile"])})).json()["queue"]
            return {"status": q.get("status"), "speed": q.get("speed"), "left": q.get("timeleft"),
                    "items": [{"name": i.get("filename"), "pct": i.get("percentage")} for i in q.get("slots", [])]}

        async def qbittorrent():
            s = m["qbittorrent"]
            rows = (await client.get(s["url"].rstrip("/") + "/api/v2/torrents/info",
                                     params={"filter": "active"})).json()
            return [{"name": t.get("name"), "progress": round(t.get("progress", 0) * 100, 1),
                     "state": t.get("state"), "eta_s": t.get("eta")} for t in rows]

        async def jellyfin():
            s = m["jellyfin"]
            r = (await client.get(s["url"].rstrip("/") + "/Items", params={
                "SortBy": "DateCreated", "SortOrder": "Descending", "Limit": 15, "Recursive": "true",
                "IncludeItemTypes": "Movie,Episode"},
                headers={"Authorization": f'MediaBrowser Token="{secret(cfg, s["keyFile"])}"'})).json()
            return [{"name": i.get("Name"), "series": i.get("SeriesName"), "type": i.get("Type")}
                    for i in r.get("Items", [])]

        jobs = {
            "sonarr": lambda: arr("sonarr", lambda c: {
                "series": (c.get("series") or {}).get("title"), "episode": c.get("title"),
                "s": c.get("seasonNumber"), "e": c.get("episodeNumber"), "air": c.get("airDateUtc")}),
            "radarr": lambda: arr("radarr", lambda c: {
                "title": c.get("title"), "digital": c.get("digitalRelease"), "cinema": c.get("inCinemas")}),
            "sabnzbd": sabnzbd,
            "qbittorrent": qbittorrent,
            "jellyfin_recent": jellyfin,
        }
        for key, job in jobs.items():
            if key.split("_")[0] not in m:
                continue
            try:
                out[key] = await job()
            except Exception as e:  # noqa: BLE001 - one backend down must not hide the others
                out[key] = {"error": f"{type(e).__name__}: {hostd.redact(str(e))[:200]}"}
    return out


def build_app(cfg: dict, access: AccessVerifier | None = None, fetch_cimd=None):
    state = Path(cfg["stateDir"])
    state.mkdir(parents=True, exist_ok=True)
    store = Store(str(state / "oauth.sqlite"))
    a = cfg["access"]
    access = access or AccessVerifier(a["teamDomain"], a["aud"], a["allowEmails"])
    auth = AuthServer(cfg, store, access, fetch_cimd)
    lab = Lab(cfg)
    mcp = build_mcp(cfg, lab, auth)
    app = mcp.streamable_http_app()
    ours = [
        Route("/.well-known/oauth-protected-resource/mcp", auth.resource_metadata),
        Route("/.well-known/oauth-protected-resource", auth.resource_metadata),
        Route("/.well-known/oauth-authorization-server", auth.as_metadata),
        Route("/oauth/authorize", auth.authorize, methods=["GET", "POST"]),
        Route("/oauth/token", auth.token, methods=["POST"]),
        Route("/oauth/revoke", auth.revoke, methods=["POST"]),
        Route("/oauth/register", auth.register, methods=["POST"]),
    ]
    # First, so they shadow the SDK's resource-metadata route, which lists only required scopes.
    app.router.routes[:0] = ours
    alarm = cfg.get("authFailureAlert", {"threshold": 20, "windowSeconds": 300})
    wrapped = AuthFailureAlarm(app, lab, alarm["threshold"], alarm["windowSeconds"]) if cfg.get("notify") else app
    return wrapped, auth, lab


def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="wett-mcp")
    parser.add_argument("--config", default=os.environ.get("WETT_MCP_CONFIG", "/etc/wett-mcp/config.json"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the server")
    sub.add_parser("revoke-all", help="revoke every grant (kill switch)")
    mint = sub.add_parser("mint-token", help="issue a token directly (local testing; needs DB write access)")
    mint.add_argument("--write", action="store_true", help="include lab.write")
    mint.add_argument("--agents", action="store_true", help="include lab.agents")
    mint.add_argument("--ttl", type=int, default=3600)
    args = parser.parse_args(argv)
    cfg = load_config(args.config)

    if args.cmd == "serve":
        app, _, _ = build_app(cfg)
        listen = cfg.get("listen", {})
        uvicorn.run(app, host=listen.get("host", "127.0.0.1"), port=listen.get("port", 8790),
                    proxy_headers=False, server_header=False, log_level="info")
        return
    Path(cfg["stateDir"]).mkdir(parents=True, exist_ok=True)
    store = Store(str(Path(cfg["stateDir"]) / "oauth.sqlite"))
    if args.cmd == "revoke-all":
        print(f"revoked {store.revoke_all()} grant(s)")
    elif args.cmd == "mint-token":
        scopes = [SCOPE_READ] + ([SCOPE_WRITE] if args.write else []) + ([SCOPE_AGENTS] if args.agents else [])
        resource = cfg["publicUrl"].rstrip("/") + "/mcp"
        family = store.new_family("cli", "cli", scopes, resource)
        access, _ = store.issue(family, args.ttl, args.ttl)
        print(access)


if __name__ == "__main__":
    sys.exit(main())
