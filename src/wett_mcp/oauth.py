"""Single-user OAuth 2.1 authorization server for the connector.

Clients identify with a Client ID Metadata Document (CIMD) whose URL matches
an allowlisted prefix; Dynamic Client Registration is optional and only
accepts allowlisted redirect URIs. The human step is /oauth/authorize, which
must sit behind a Cloudflare Access application: this module verifies the
Access JWT itself and fails closed without it.
"""

import base64
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import threading
import time
import urllib.parse
from collections.abc import Callable

import httpx
import jwt
from mcp.server.auth.provider import AccessToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

SCOPE_READ = "lab.read"
SCOPE_WRITE = "lab.write"
SCOPE_AGENTS = "lab.agents"
SCOPES = [SCOPE_READ, SCOPE_WRITE, SCOPE_AGENTS]
CODE_TTL = 120
FORM_TTL = 600
CIMD_TTL = 3600
CIMD_MAX_BYTES = 64 * 1024


class LabToken(AccessToken):
    family: str


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class Store:
    """SQLite token store. Only hashes of codes and tokens are persisted."""

    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._db.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS families (
              id TEXT PRIMARY KEY, client_id TEXT, email TEXT, scopes TEXT,
              resource TEXT, created INTEGER, revoked INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS codes (
              hash TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, challenge TEXT,
              scopes TEXT, resource TEXT, email TEXT, expires INTEGER,
              family TEXT, used INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS tokens (
              hash TEXT PRIMARY KEY, kind TEXT, family TEXT, expires INTEGER, used INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS clients (
              client_id TEXT PRIMARY KEY, metadata TEXT, created INTEGER);
            """
        )

    def q(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def revoke_family(self, family: str) -> None:
        self.q("UPDATE families SET revoked=1 WHERE id=?", (family,))

    def revoke_all(self) -> int:
        n = self.q("SELECT count(*) FROM families WHERE revoked=0")[0][0]
        self.q("UPDATE families SET revoked=1")
        return n

    def issue(self, family: str, access_ttl: int, refresh_ttl: int) -> tuple[str, str]:
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.q("INSERT INTO tokens(hash, kind, family, expires) VALUES (?,?,?,?)",
               (_hash(access), "access", family, now + access_ttl))
        self.q("INSERT INTO tokens(hash, kind, family, expires) VALUES (?,?,?,?)",
               (_hash(refresh), "refresh", family, now + refresh_ttl))
        self.q("DELETE FROM tokens WHERE expires < ?", (now - 86400,))
        return access, refresh

    def new_family(self, client_id: str, email: str, scopes: list[str], resource: str) -> str:
        family = secrets.token_hex(8)
        self.q("INSERT INTO families(id, client_id, email, scopes, resource, created) VALUES (?,?,?,?,?,?)",
               (family, client_id, email, " ".join(scopes), resource, int(time.time())))
        return family

    def lookup(self, token: str, kind: str) -> tuple | None:
        """(family, client_id, scopes, resource, expires, used, revoked) or None."""
        rows = self.q(
            "SELECT t.family, f.client_id, f.scopes, f.resource, t.expires, t.used, f.revoked "
            "FROM tokens t JOIN families f ON f.id = t.family WHERE t.hash=? AND t.kind=?",
            (_hash(token), kind),
        )
        return rows[0] if rows else None


class AccessVerifier:
    """Verifies the Cf-Access-Jwt-Assertion header Cloudflare Access adds."""

    def __init__(self, team_domain: str, aud: str, allow_emails: list[str],
                 get_key: Callable[[str], object] | None = None):
        self.issuer = f"https://{team_domain}"
        self.aud = aud
        self.allow = {e.lower() for e in allow_emails}
        if get_key is None:
            client = jwt.PyJWKClient(f"{self.issuer}/cdn-cgi/access/certs", cache_keys=True, lifespan=3600)
            get_key = lambda token: client.get_signing_key_from_jwt(token).key  # noqa: E731
        self._get_key = get_key

    def email(self, request: Request) -> str | None:
        token = request.headers.get("cf-access-jwt-assertion")
        if not token or not self.aud or not self.allow:
            return None
        try:
            claims = jwt.decode(token, self._get_key(token), algorithms=["RS256"], audience=self.aud,
                                issuer=self.issuer, options={"require": ["exp", "iat", "aud", "iss"]})
        except Exception:  # noqa: BLE001 - any failure means no identity
            return None
        email = str(claims.get("email", "")).lower()
        return email if email in self.allow else None


def _is_loopback(uri: str) -> bool:
    p = urllib.parse.urlsplit(uri)
    return p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1")


def redirect_allowed(uri: str, registered: list[str]) -> bool:
    """Exact match, or RFC 8252 loopback match ignoring the port."""
    if uri in registered:
        return True
    if not _is_loopback(uri):
        return False
    p = urllib.parse.urlsplit(uri)
    for r in registered:
        if _is_loopback(r):
            rp = urllib.parse.urlsplit(r)
            if (rp.hostname, rp.path, rp.query) == (p.hostname, p.path, p.query):
                return True
    return False


def _with_params(uri: str, params: dict) -> str:
    p = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qsl(p.query) + [(k, v) for k, v in params.items() if v is not None]
    return urllib.parse.urlunsplit(p._replace(query=urllib.parse.urlencode(query)))


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status_code=status,
                        headers={"Cache-Control": "no-store"})


PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "form-action 'self' https: http://localhost:* http://127.0.0.1:*; "
                               "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>body{{font:16px system-ui;max-width:32em;margin:2em auto;"
        "padding:0 1em}button{font-size:1.1em;padding:.5em 1.2em;margin-right:.5em}</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{body}</body></html>"
    )
    return HTMLResponse(doc, status_code=status, headers=PAGE_HEADERS)


class AuthServer:
    def __init__(self, cfg: dict, store: Store, access: AccessVerifier,
                 fetch_cimd: Callable[[str], dict] | None = None):
        self.base = cfg["publicUrl"].rstrip("/")
        self.resource = self.base + "/mcp"
        self.store = store
        self.access = access
        self.cimd_prefixes = cfg["cimd"]["allowedPrefixes"]
        self.dcr = cfg["dcr"]
        self.access_ttl = cfg.get("accessTokenTtl", 3600)
        self.refresh_ttl = cfg.get("refreshTokenTtl", 30 * 86400)
        self._form_key = secrets.token_bytes(32)
        self._cimd_cache: dict[str, tuple[float, dict]] = {}
        self._fetch_cimd = fetch_cimd or self._http_fetch_cimd

    # --- metadata ---------------------------------------------------------

    def as_metadata(self, request: Request) -> JSONResponse:
        meta = {
            "issuer": self.base,
            "authorization_endpoint": f"{self.base}/oauth/authorize",
            "token_endpoint": f"{self.base}/oauth/token",
            "revocation_endpoint": f"{self.base}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "client_id_metadata_document_supported": True,
            "scopes_supported": SCOPES + ["offline_access"],
        }
        if self.dcr["enable"]:
            meta["registration_endpoint"] = f"{self.base}/oauth/register"
        return JSONResponse(meta)

    def resource_metadata(self, request: Request) -> JSONResponse:
        return JSONResponse({
            "resource": self.resource,
            "authorization_servers": [self.base],
            "scopes_supported": SCOPES,
            "bearer_methods_supported": ["header"],
        })

    # --- clients ----------------------------------------------------------

    def _http_fetch_cimd(self, url: str) -> dict:
        with httpx.Client(timeout=5, follow_redirects=False) as client:
            resp = client.get(url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            if len(resp.content) > CIMD_MAX_BYTES:
                raise ValueError("client metadata document too large")
            return resp.json()

    def client_redirects(self, client_id: str) -> list[str] | None:
        """Registered redirect URIs for an acceptable client, else None."""
        if client_id.startswith("https://"):
            if not any(client_id.startswith(p) for p in self.cimd_prefixes):
                return None
            cached = self._cimd_cache.get(client_id)
            if cached and cached[0] > time.time():
                doc = cached[1]
            else:
                try:
                    doc = self._fetch_cimd(client_id)
                except Exception:  # noqa: BLE001
                    return None
                if not isinstance(doc, dict) or doc.get("client_id") != client_id:
                    return None
                self._cimd_cache[client_id] = (time.time() + CIMD_TTL, doc)
            uris = doc.get("redirect_uris")
            return [u for u in uris if isinstance(u, str)] if isinstance(uris, list) else None
        if self.dcr["enable"]:
            rows = self.store.q("SELECT metadata FROM clients WHERE client_id=?", (client_id,))
            if rows:
                return json.loads(rows[0][0])["redirect_uris"]
        return None

    async def register(self, request: Request) -> Response:
        if not self.dcr["enable"]:
            return _oauth_error("invalid_request", "dynamic client registration is disabled", 404)
        try:
            body = await request.json()
        except ValueError:
            return _oauth_error("invalid_client_metadata", "body must be JSON")
        uris = body.get("redirect_uris") if isinstance(body, dict) else None
        allowed = self.dcr["allowedRedirectUris"]
        if not isinstance(uris, list) or not uris or any(u not in allowed for u in uris):
            return _oauth_error("invalid_redirect_uri", "redirect_uris must be within the allowlist")
        if body.get("token_endpoint_auth_method", "none") != "none":
            return _oauth_error("invalid_client_metadata", "only public clients (auth method none)")
        client_id = "dcr-" + secrets.token_urlsafe(16)
        meta = {"client_id": client_id, "redirect_uris": uris, "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "client_name": str(body.get("client_name", ""))[:100],
                "client_id_issued_at": int(time.time())}
        self.store.q("INSERT INTO clients(client_id, metadata, created) VALUES (?,?,?)",
                     (client_id, json.dumps(meta), int(time.time())))
        return JSONResponse(meta, status_code=201)

    # --- authorize --------------------------------------------------------

    def _form_token(self, params: dict, email: str, ts: int) -> str:
        msg = json.dumps([params, email, ts], sort_keys=True).encode()
        return f"{ts}.{hmac.new(self._form_key, msg, hashlib.sha256).hexdigest()}"

    def _check_form_token(self, token: str, params: dict, email: str) -> bool:
        try:
            ts = int(token.split(".", 1)[0])
        except ValueError:
            return False
        if time.time() - ts > FORM_TTL:
            return False
        return hmac.compare_digest(token, self._form_token(params, email, ts))

    async def authorize(self, request: Request) -> Response:
        email = self.access.email(request)
        if email is None:
            return _page("Forbidden", "<p>No valid Cloudflare Access identity.</p>", 403)
        if request.method == "POST":
            form = await request.form()
            src = {k: str(v) for k, v in form.items()}
        else:
            src = dict(request.query_params)
        names = ("response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method",
                 "state", "scope", "resource")
        params = {k: src.get(k, "") for k in names}

        client_id, redirect_uri = params["client_id"], params["redirect_uri"]
        registered = self.client_redirects(client_id) if client_id else None
        if registered is None:
            return _page("Unknown client", "<p>This client is not allowed.</p>", 400)
        if not redirect_uri or not redirect_allowed(redirect_uri, registered):
            return _page("Bad redirect", "<p>redirect_uri is not registered for this client.</p>", 400)

        def fail(error: str, desc: str) -> Response:
            return RedirectResponse(_with_params(redirect_uri, {
                "error": error, "error_description": desc, "state": params["state"] or None,
                "iss": self.base}), status_code=302)

        if params["response_type"] != "code":
            return fail("unsupported_response_type", "only code")
        if not params["code_challenge"] or params["code_challenge_method"] != "S256":
            return fail("invalid_request", "PKCE S256 is required")
        if params["resource"] and params["resource"].rstrip("/") != self.resource:
            return fail("invalid_target", "unknown resource")

        if request.method == "GET":
            token = self._form_token(params, email, int(time.time()))
            hidden = "".join(f"<input type=hidden name={k} value='{html.escape(v, quote=True)}'>"
                             for k, v in params.items())
            host = html.escape(urllib.parse.urlsplit(redirect_uri).netloc)
            body = (
                f"<p>Signed in as <b>{html.escape(email)}</b>.</p>"
                f"<p>Client <code>{html.escape(client_id)}</code> wants access to this lab, "
                f"returning to <b>{host}</b>.</p>"
                f"<form method=post action='{html.escape(self.base)}/oauth/authorize'>{hidden}"
                f"<input type=hidden name=form_token value='{token}'>"
                "<p><label><input type=checkbox name=allow_write value=1> Also allow write tools "
                f"(<code>{SCOPE_WRITE}</code>: Home Assistant actions, notifications)</label></p>"
                "<p><label><input type=checkbox name=allow_agents value=1> Also allow dispatching coding "
                f"agents (<code>{SCOPE_AGENTS}</code>: they run code on the agents host with its credentials; "
                "every dispatch is pushed to your phone)</label></p>"
                "<button name=decision value=approve>Approve</button>"
                "<button name=decision value=deny>Deny</button></form>"
            )
            return _page("Authorize access", body)

        if not self._check_form_token(src.get("form_token", ""), params, email):
            return _page("Expired", "<p>The approval form expired or was tampered with. Start again.</p>", 400)
        if src.get("decision") != "approve":
            return fail("access_denied", "denied by the user")
        scopes = ([SCOPE_READ] + ([SCOPE_WRITE] if src.get("allow_write") == "1" else [])
                  + ([SCOPE_AGENTS] if src.get("allow_agents") == "1" else []))
        code = secrets.token_urlsafe(32)
        self.store.q(
            "INSERT INTO codes(hash, client_id, redirect_uri, challenge, scopes, resource, email, expires) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (_hash(code), client_id, redirect_uri, params["code_challenge"], " ".join(scopes), self.resource,
             email, int(time.time()) + CODE_TTL),
        )
        return RedirectResponse(_with_params(redirect_uri, {
            "code": code, "state": params["state"] or None, "iss": self.base}), status_code=302)

    # --- token ------------------------------------------------------------

    def _token_response(self, family: str, scopes: str) -> JSONResponse:
        access, refresh = self.store.issue(family, self.access_ttl, self.refresh_ttl)
        return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": self.access_ttl,
                             "refresh_token": refresh, "scope": scopes},
                            headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    async def token(self, request: Request) -> Response:
        form = {k: str(v) for k, v in (await request.form()).items()}
        grant = form.get("grant_type")
        client_id = form.get("client_id", "")
        if form.get("resource") and form["resource"].rstrip("/") != self.resource:
            return _oauth_error("invalid_target", "unknown resource")
        if grant == "authorization_code":
            rows = self.store.q(
                "SELECT client_id, redirect_uri, challenge, scopes, email, expires, family, used "
                "FROM codes WHERE hash=?", (_hash(form.get("code", "")),))
            if not rows:
                return _oauth_error("invalid_grant", "unknown code")
            c_client, c_redirect, challenge, scopes, email, expires, family, used = rows[0]
            if used:
                # A replayed code: revoke what the first exchange issued.
                if family:
                    self.store.revoke_family(family)
                return _oauth_error("invalid_grant", "code already used")
            self.store.q("UPDATE codes SET used=1 WHERE hash=?", (_hash(form["code"]),))
            if expires < time.time():
                return _oauth_error("invalid_grant", "code expired")
            if client_id != c_client or form.get("redirect_uri") != c_redirect:
                return _oauth_error("invalid_grant", "client or redirect_uri mismatch")
            verifier = form.get("code_verifier", "")
            if not verifier or not hmac.compare_digest(_s256(verifier), challenge):
                return _oauth_error("invalid_grant", "PKCE verification failed")
            family = self.store.new_family(client_id, email, scopes.split(), self.resource)
            self.store.q("UPDATE codes SET family=? WHERE hash=?", (family, _hash(form["code"])))
            return self._token_response(family, scopes)
        if grant == "refresh_token":
            row = self.store.lookup(form.get("refresh_token", ""), "refresh")
            if row is None:
                return _oauth_error("invalid_grant", "unknown refresh token")
            family, f_client, scopes, _, expires, used, revoked = row
            if used:
                # Reuse of a rotated refresh token: assume theft, kill the grant.
                self.store.revoke_family(family)
                return _oauth_error("invalid_grant", "refresh token reused; grant revoked")
            if revoked or expires < time.time() or client_id != f_client:
                return _oauth_error("invalid_grant", "refresh token invalid")
            self.store.q("UPDATE tokens SET used=1 WHERE hash=?", (_hash(form["refresh_token"]),))
            return self._token_response(family, scopes)
        return _oauth_error("unsupported_grant_type", "authorization_code or refresh_token")

    async def revoke(self, request: Request) -> Response:
        form = await request.form()
        token = str(form.get("token", ""))
        for kind in ("access", "refresh"):
            row = self.store.lookup(token, kind)
            if row:
                self.store.revoke_family(row[0])
        return Response(status_code=200)

    # --- resource server --------------------------------------------------

    def verify(self, token: str) -> LabToken | None:
        row = self.store.lookup(token, "access")
        if row is None:
            return None
        family, client_id, scopes, resource, expires, _, revoked = row
        if revoked or expires < time.time():
            return None
        return LabToken(token=token, client_id=client_id, scopes=scopes.split(), expires_at=expires,
                        resource=resource, family=family)


class Verifier:
    """mcp TokenVerifier adapter."""

    def __init__(self, server: AuthServer):
        self.server = server

    async def verify_token(self, token: str) -> AccessToken | None:
        return self.server.verify(token)
