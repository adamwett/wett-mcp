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
  - The **write tools** checkbox decides whether the grant gets `lab.write`.
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

Every call is appended to `/var/lib/wett-mcp/audit.jsonl` with secrets redacted. More than 20 401s in 5 minutes
triggers one notification.

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
  sshKeyFile = "/run/secrets/wett-mcp-ssh-key";
  haHost = "other";
  prometheus.url = "http://127.0.0.1:9090";
  notify = { url = "http://relay.example.lan/notify"; tokenFile = "/run/secrets/notify-token"; };
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
```

How it runs:

- The server is a `DynamicUser` systemd service listening on `127.0.0.1:8790`.
- Secrets arrive as systemd credentials.
- The remote host keys must be in `sshKnownHostsFile` (`/etc/ssh/ssh_known_hosts` by default); they are checked strictly.

`wett-mcp-ctl` runs admin commands as the service user. It starts a transient unit, so it needs root:

- `sudo wett-mcp-ctl revoke-all` is the kill switch.
- `sudo wett-mcp-ctl mint-token [--write]` issues a token for local testing.

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
- Scope enforcement on write tools, through a real MCP client.
- Hostd's verb, unit, `since` and Home Assistant policy checks.
