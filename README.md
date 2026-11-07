# wett-mcp

A remote [MCP](https://modelcontextprotocol.io) server that gives Claude a small, allowlisted, read-mostly view of a
homelab. It works with Claude custom connectors (claude.ai, the mobile apps, Claude Duet, Claude Code).
It is meant to sit behind a Cloudflare Tunnel.

- **Transport:** Streamable HTTP at `<publicUrl>/mcp`. It runs stateless with JSON responses, via the official
  `mcp` Python SDK.
- **Auth:** the server is its own single-user OAuth 2.1 authorization server.
  - Clients identify with a Client ID Metadata Document (CIMD) whose URL matches an allowlisted prefix
    (`https://claude.ai/` by default).
  - Dynamic Client Registration is off unless you enable it. When enabled, it accepts only allowlisted redirect URIs.
  - PKCE S256 is required.
  - Refresh tokens rotate on every use. Reusing a rotated refresh token, or replaying an authorization code,
    revokes the whole grant.
  - Only SHA-256 hashes of codes and tokens are stored, in SQLite.
- **Human gate:** `/oauth/authorize` must be the only path covered by a Cloudflare Access application.
  - The server verifies the `Cf-Access-Jwt-Assertion` JWT itself: RS256 signature against the team's certs, plus
    `aud`, `iss`, `exp` and the email allowlist.
  - Without a valid JWT it answers 403 and never redirects, so a missing or misconfigured Access app fails closed.
  - The consent page is HMAC-protected against tampering and cannot be framed.
  - The **write tools** checkbox decides whether the grant gets `lab.write`; a separate **coding agents** checkbox
    grants `lab.agents`. Neither is ticked by default. A grant without a scope gets a tool error naming it; to add
    one, disconnect and reconnect the connector (the SDK checks scopes per endpoint, so there is no per-tool 403
    step-up challenge).
- **No shell.** Host access goes through `wett-mcp-hostd`, a stdlib-only program of fixed verbs. It runs in-process
  for the local host, or as an SSH forced command (`command=…,restrict`) on other hosts.

## Tools

| Tool | Scope | What it does |
|---|---|---|
| `lab_overview` | read | Per host: uptime, load, memory, failed units, running containers. From Prometheus: scrape status and root disk use. |
| `prom_query` | read | Instant or range PromQL. Range max 7 days, ≤1000 points, ≤200 series. |
| `unit_status` | read | `systemctl show` for allowlisted units. |
| `unit_logs` | read | Journal lines for allowlisted units: ≤300 lines, validated `since`, substring filter, secrets redacted. Units that handle secrets (`sops-install-secrets*`, `cloudflared*`, `tailscaled*`, `wett-mcp*`) are never returned. |
| `ha_states`, `ha_history` | read | Home Assistant states and ≤48 h history. `person`, `device_tracker`, `zone`, `camera` and `image` entities are hidden unless exposed. |
| `media_status` | read | Sonarr/Radarr queue and 7-day calendar, SABnzbd and qBittorrent queues, recent Jellyfin items. |
| `lab_notify` | write | Phone notification through a bearer-token relay. Rate limited. |
| `ha_call_service` | write | Allowlisted `domain.service` + entity globs, which must name entities explicitly. The built-in deny list always wins: locks, alarms, covers, valves, sirens, cameras, HA/OS administration, command/notify/MQTT services and others. Every call is mirrored as a notification. |
| `printer_status` | read | The printer over IPP: model, state and reasons (`media-empty`, `toner-low`…), ink/toner levels, paper loaded, duplex, accepted formats, unfinished jobs on the printer and on the CUPS queue if there is one. |
| `print_document(text?, document_base64?, title?, copies?, duplex?, paper?, font_size?)` | write | Print plain text (rendered to PDF in Courier, `font_size` 8–36 pt, default 10, wrapped at spaces) or a base64 PDF, JPEG or PNG. Duplex is long-edge; `paper` takes `letter`, `legal`, `a4`, `a5`, `a6`, `4x6`, `5x7` or a PWG media name. Size, pages × copies and copies are capped. Every job is logged and mirrored as a notification. |
| `agent_list` | read | Coding-agent jobs: id, title, repo, state (`running`, `idle`, `stopped`, `failed`), start, last activity, turns, queued messages, cost. |
| `agent_read(id, since_turn?)` | read | Per finished turn: prompt, status (`ok`, `timed_out`, `failed`, `stopped`) and the agent's final message (redacted, ≤8000 chars), plus state, queued messages and an `omp --resume` command for taking the session over by hand. |
| `agent_dispatch(repo, prompt, title?, max_minutes?)` | agents | Start a headless oh-my-pi (`omp`) coding agent. `repo` is a directory name in the work root, or `owner/name` from an allowlisted GitHub owner (cloned with `gh` if missing). |
| `agent_send(id, message)` | agents | Follow-up: queued as the next turn while the agent runs; otherwise starts a run that resumes the session. |
| `agent_stop(id)` | agents | Stop the current run and drop queued messages; the session stays resumable. |

Every call is appended to `/var/lib/wett-mcp/audit.jsonl` with secrets redacted. Documents sent to `print_document`
are logged only by length, plus a `print_job` entry per job (job id, format, pages, copies, sides, paper, bytes, a
SHA-256 prefix). More than 20 401s in 5 minutes triggers one notification.

### Coding agents

Set `agentsHost` to a host whose hostd has `hostd.agents.enable`, running as the agents' own user
(`hostd.user = "agent"; hostd.createUser = false;`). That user needs a lingering systemd user manager, `omp` and
`gh`, and whatever credentials the agents should have (pass them with `hostd.agents.envFiles`).

- **Runs.** A dispatch puts the prompt in the job's inbox and starts a transient `systemd-run --user` unit
  (`wett-agent-<id>-<run>`). The unit runs hostd's runner, which drains the inbox: one headless
  `omp -p --mode json --session-dir <job>/session [--resume <session>] -- <message>` per message, then exits.
  The message always follows `--`, so it can't be read as a flag or an `@file`.
- **State** lives in `~/.local/state/wett-agents/<id>/`: `meta.json` (state, inbox, session id), `turns.jsonl`
  (status and final text per turn), raw `events/<turn>.jsonl`, and the omp session.
- **Limits.** `maxConcurrent` running units (default 3), a per-run time budget (`defaultMinutes` 60, capped at
  `maxMinutes` 240, passed to `omp --max-time` and backed by the unit's `RuntimeMaxSec`), `maxPromptChars` (20000),
  20 queued messages per job.
- **Validation.** The server checks arguments, and hostd checks them again: repo names can't contain `/` (beyond
  one `owner/` prefix), can't start with `-` or `.`, and must resolve to a direct child of the work root. Job ids
  are 8 hex chars.
- **Guardrails.** Every dispatch, send and stop is pushed to the phone (`<titlePrefix> → agent`, outside
  `lab_notify`'s rate limit). Dispatch and send are refused if that push fails. Every agent's system prompt gets
  a note (`hostd.agents.systemNote`) saying it was dispatched remotely, must not push default branches unless
  told to, and must end each turn with a summary, which is what `agent_read` returns.
- **Annotations.** The agents tools are `destructiveHint`; set dispatch and send to *always ask* in Claude.

### Printer

Set `printer.uri` to the printer's IPP endpoint (`ipp://<address>/ipp/print` on IPP Everywhere and AirPrint
printers). Use a DHCP-reserved address, or the printer's mDNS `.local` name, which needs
`services.avahi = { enable = true; nssmdns4 = true; }` on the server host.

- **No drivers.** wett-mcp speaks IPP/1.1 itself (Get-Printer-Attributes, Get-Jobs, Print-Job). It checks the
  format, duplex, paper and copies against what the printer advertises before sending anything.
- **Raster-only printers.** Many inkjets accept only `image/pwg-raster`, `image/urf` and `image/jpeg`, not PDF.
  Set `printer.cupsQueue = "canon"`: the module enables CUPS, creates a driverless (IPP Everywhere,
  `lpadmin -m everywhere`) queue for `printer.uri`, retrying every minute until the printer answers, and sends jobs
  through `ipp://localhost:631/printers/canon`. CUPS then converts PDF, text and images and holds jobs while the
  printer is busy or asleep. `printer_status` still reads supplies and state from the printer itself.
- **Without a queue**, a printer still on its previous job answers `server-error-busy`; Print-Job is retried for
  30 s.
- **Limits.** `maxBytes` (10 MiB), `maxPages` (30, copies included) and `maxCopies` (10). PDF pages are counted from
  the page objects, including compressed object streams; a PDF whose pages can't be counted (encrypted) is
  refused.
- **TLS.** `ipps://` is encrypted but the certificate is not verified: printers use self-signed ones.

## NixOS

```nix
inputs.wett-mcp = {
  url = "github:adamwett/wett-mcp";
  inputs.nixpkgs.follows = "nixpkgs";
};

# on the host running the server
imports = [ inputs.wett-mcp.nixosModules.default ];
services.wettMcp = {
  enable = true;
  publicUrl = "https://mcp.example.com";
  access = {
    teamDomain = "myteam.cloudflareaccess.com";
    aud = "<Access application AUD tag>";
    allowEmails = [ "me@example.com" ];
  };
  hosts.server = { };                                   # this machine, in-process
  hosts.other.ssh = "wett-mcp-hostd@other.example.lan"; # remote hostd
  hosts.agents = { ssh = "agent@agents.example.lan"; keyFile = "/run/secrets/agents-key"; };
  sshKeyFile = "/run/secrets/wett-mcp-ssh-key";
  agentsHost = "agents";
  haHost = "other";
  prometheus.url = "http://127.0.0.1:9090";
  notify = { url = "http://relay.example.lan/notify"; tokenFile = "/run/secrets/notify-token"; };
  printer = { uri = "ipp://printer.example.lan/ipp/print"; cupsQueue = "canon"; };
  hostd.units = [ "nginx.service" "container@*.service" ];
};

# on each other host
imports = [ inputs.wett-mcp.nixosModules.default ];
services.wettMcp.hostd = {
  enable = true;
  authorizedKeys = [ "ssh-ed25519 AAAA… wett-mcp" ];
  units = [ "home-assistant.service" ];
  ha = {
    url = "http://127.0.0.1:8123";
    tokenFile = "/run/secrets/ha-token"; # readable by the hostd user
    allow = [
      { service = "light.*"; entities = [ "light.*" ]; }
      { service = "climate.set_temperature"; entities = [ "climate.living_room" ]; }
    ];
  };
};

# on the agents host (its own key; hostd runs as the agents' user)
services.wettMcp.hostd = {
  enable = true;
  user = "agent";
  createUser = false;
  authorizedKeys = [ "ssh-ed25519 AAAA… wett-mcp-agents" ];
  agents = {
    enable = true;
    cloneOwners = [ "my-github-user" ];
    envFiles.GH_TOKEN = "/run/secrets/github-token";
  };
};
```

How it runs:

- The server is a `DynamicUser` systemd service listening on `127.0.0.1:8790`.
- Secrets arrive as systemd credentials.
- The remote host keys must be in `sshKnownHostsFile` (`/etc/ssh/ssh_known_hosts` by default); they are checked strictly.

`wett-mcp-ctl` runs admin commands as the service user. It starts a transient unit, so it needs root:

- `sudo wett-mcp-ctl revoke-all` is the kill switch.
- `sudo wett-mcp-ctl mint-token [--write] [--agents]` issues a token for local testing.

The module does not publish anything. Point a Cloudflare Tunnel ingress at the listen address, for example with nixpkgs
`services.cloudflared`:

```nix
services.cloudflared.tunnels."<tunnel-uuid>" = {
  credentialsFile = "/run/secrets/tunnel-credentials.json";
  ingress."mcp.example.com" = "http://127.0.0.1:8790";
  default = "http_status:404";
};
```

## Setup

1. **Tunnel:** `cloudflared tunnel login`, then `cloudflared tunnel create <name>`, then
   `cloudflared tunnel route dns <name> mcp.example.com`. Put the credentials JSON in your secret store.
2. **Cloudflare Access:** in Zero Trust, add a **self-hosted application** for `mcp.example.com/oauth/authorize`
   only, with an Allow policy for your email.
   - Copy the team domain and the application's AUD tag into `services.wettMcp.access`.
   - Do **not** put Access in front of the whole hostname: Claude's backend calls `/mcp`, `/oauth/token` and the
     metadata endpoints without a browser session.
3. **Bot rules:** Cloudflare's *AI Crawl Control* / AI-bot blocking matches Claude's `Claude-User` user agent and
   blocks connector traffic. Add a custom rule scoped to this hostname that skips it, ordered before the block.
4. **Home Assistant:** create a non-admin user and a long-lived token for hostd. The allowlist is the real limit: HA
   doesn't scope REST access per entity.
5. **Claude:** go to Customize → Connectors → Add custom connector.
   - URL: `https://mcp.example.com/mcp`
   - Authentication: *Sign in now*
   - OAuth client: *Use Claude's published identity*. Use *Register automatically* only if `dcr.enable = true`.
   - Approve in the Access login and consent page.
   - In the connector's tool settings, set the write tools to require approval.

Before exposing anything, test from the tailnet or LAN with `sudo wett-mcp-ctl mint-token` and any MCP client. Claude Code
works too: its loopback redirect matches on any port.

## Development

```sh
nix develop
PYTHONPATH=src python -m pytest
nix build .#wett-mcp .#wett-mcp-hostd
nix flake check
```

The tests run a real OAuth flow end to end:

- Metadata and the 401 challenge.
- Access JWTs that are valid, forged, expired, for the wrong audience or for the wrong email.
- PKCE.
- Refresh rotation, and revocation on reuse or code replay.
- Scope enforcement on write and agent tools, through a real MCP client.
- Hostd's verb, unit, `since` and Home Assistant policy checks.
- The agent verbs against a fake `omp` on `PATH`: repo/id/argument validation (`..`, absolute paths, symlink
  escapes, owners outside the allowlist, flag-like repos and prompts), the concurrency cap, the inbox → resume
  loop, stop, timed-out and failed turns, and a runner killed without recording anything.
- The IPP client against RFC 8010 wire-format fixtures and a fake printer: job attributes, checks that refuse a
  job before it is sent (size, pages × copies, format, duplex, paper, copies, a printer not accepting jobs),
  `server-error-busy` retries, supply levels from `marker-*` and `printer-supply`, and the audit log keeping
  documents out.
- PDF page counting through compressed object streams and incremental updates, and text → PDF pagination.
