import base64
import hashlib
import re
import secrets
import time
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from wett_mcp.oauth import AccessVerifier
from wett_mcp.server import build_app

BASE = "https://mcp.example.test"
TEAM = "team.example.test"
AUD = "test-aud"
OWNER = "owner@example.test"
CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"
CLIENT = "https://claude.ai/oauth/test-client"
CODE_CLIENT = "https://claude.ai/oauth/claude-code-client-metadata"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

CIMD = {
    CLIENT: {"client_id": CLIENT, "redirect_uris": [CLAUDE_CB]},
    CODE_CLIENT: {"client_id": CODE_CLIENT,
                  "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"]},
    "https://claude.ai/oauth/liar": {"client_id": "https://claude.ai/oauth/someone-else", "redirect_uris": [CLAUDE_CB]},
}


def access_jwt(email=OWNER, aud=AUD, key=KEY, exp_in=300, iss=f"https://{TEAM}"):
    now = int(time.time())
    return jwt.encode({"email": email, "aud": aud, "iss": iss, "iat": now, "exp": now + exp_in}, key,
                      algorithm="RS256")


def config(tmp_path, dcr=False):
    return {
        "publicUrl": BASE,
        "stateDir": str(tmp_path),
        "access": {"teamDomain": TEAM, "aud": AUD, "allowEmails": [OWNER]},
        "cimd": {"allowedPrefixes": ["https://claude.ai/"]},
        "dcr": {"enable": dcr, "allowedRedirectUris": [CLAUDE_CB]},
        "hosts": {},
        "notify": {"url": "http://notify.invalid/notify", "tokenFile": "/nonexistent"},
    }


class Harness:
    def __init__(self, tmp_path, dcr=False):
        access = AccessVerifier(TEAM, AUD, [OWNER], get_key=lambda token: KEY.public_key())
        self.app, self.auth, self.lab = build_app(config(tmp_path, dcr), access=access, fetch_cimd=CIMD.__getitem__)
        self.notified = []

        async def fake_notify(message, title=None):
            self.notified.append((message, title))

        self.lab.notify = fake_notify
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=BASE)

    async def authorize(self, client_id=CLIENT, redirect_uri=CLAUDE_CB, write=False, jwt_header=None,
                        verifier=None):
        verifier = verifier or secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
                  "code_challenge": challenge, "code_challenge_method": "S256", "state": "st8",
                  "scope": "lab.read lab.write", "resource": f"{BASE}/mcp"}
        headers = {"cf-access-jwt-assertion": jwt_header or access_jwt()}
        page = await self.http.get("/oauth/authorize", params=params, headers=headers)
        assert page.status_code == 200, page.text
        assert page.headers["x-frame-options"] == "DENY"
        form_token = re.search(r"name=form_token value='([^']+)'", page.text).group(1)
        form = {**params, "form_token": form_token, "decision": "approve"}
        if write:
            form["allow_write"] = "1"
        resp = await self.http.post("/oauth/authorize", data=form, headers=headers)
        assert resp.status_code == 302, resp.text
        loc = urllib.parse.urlsplit(resp.headers["location"])
        q = dict(urllib.parse.parse_qsl(loc.query))
        assert q["state"] == "st8" and q["iss"] == BASE
        return q["code"], verifier

    async def exchange(self, code, verifier, client_id=CLIENT, redirect_uri=CLAUDE_CB):
        return await self.http.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier, "client_id": client_id,
            "redirect_uri": redirect_uri, "resource": f"{BASE}/mcp"})

    async def refresh(self, refresh_token, client_id=CLIENT):
        return await self.http.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id})

    async def tokens(self, write=False):
        code, verifier = await self.authorize(write=write)
        resp = await self.exchange(code, verifier)
        assert resp.status_code == 200, resp.text
        return resp.json()

    async def mcp_status(self, token):
        resp = await self.http.post("/mcp", headers={"Authorization": f"Bearer {token}",
                                                     "Accept": "application/json, text/event-stream"},
                                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        return resp.status_code

    def running(self):
        """Run the app's lifespan (the MCP session manager); once per Harness."""
        inner = self.app.app
        return inner.router.lifespan_context(inner)

    async def call(self, token, tool, args):
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=BASE,
                                   headers={"Authorization": f"Bearer {token}"})
        async with client, streamable_http_client(f"{BASE}/mcp", http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return [t.name for t in tools.tools], await session.call_tool(tool, args)


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)


async def test_discovery_and_401(h):
    asm = (await h.http.get("/.well-known/oauth-authorization-server")).json()
    assert asm["issuer"] == BASE
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["client_id_metadata_document_supported"] is True
    assert "none" in asm["token_endpoint_auth_methods_supported"]
    assert "registration_endpoint" not in asm
    prm = (await h.http.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert prm["resource"] == f"{BASE}/mcp"
    assert prm["authorization_servers"] == [BASE]
    assert "lab.write" in prm["scopes_supported"]
    resp = await h.http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp.status_code == 401
    assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp"' in resp.headers["www-authenticate"]


@pytest.mark.parametrize("header", [
    None,
    "garbage",
    access_jwt(aud="other-app"),
    access_jwt(email="intruder@example.test"),
    access_jwt(exp_in=-10),
    access_jwt(key=OTHER_KEY),
    access_jwt(iss="https://evil.example.test"),
])
async def test_authorize_requires_valid_access_jwt(h, header):
    params = {"response_type": "code", "client_id": CLIENT, "redirect_uri": CLAUDE_CB, "code_challenge": "x",
              "code_challenge_method": "S256"}
    headers = {"cf-access-jwt-assertion": header} if header else {}
    for resp in (await h.http.get("/oauth/authorize", params=params, headers=headers),
                 await h.http.post("/oauth/authorize", data={**params, "decision": "approve"}, headers=headers)):
        assert resp.status_code == 403
        assert "location" not in resp.headers


async def test_authorize_rejects_unknown_clients_and_redirects(h):
    hdr = {"cf-access-jwt-assertion": access_jwt()}
    base = {"response_type": "code", "code_challenge": "x", "code_challenge_method": "S256"}
    for client, redirect in [("https://evil.example/client", CLAUDE_CB),
                             ("https://claude.ai/oauth/liar", CLAUDE_CB),
                             ("plain-id-without-dcr", CLAUDE_CB),
                             (CLIENT, "https://evil.example/cb"),
                             (CODE_CLIENT, "http://evil.example:5000/callback")]:
        resp = await h.http.get("/oauth/authorize", params={**base, "client_id": client, "redirect_uri": redirect},
                                headers=hdr)
        assert resp.status_code == 400, (client, redirect)
        assert "location" not in resp.headers
    # Valid client but no PKCE: error goes back to the (verified) redirect URI.
    resp = await h.http.get("/oauth/authorize", headers=hdr, params={
        "response_type": "code", "client_id": CLIENT, "redirect_uri": CLAUDE_CB, "state": "s"})
    assert resp.status_code == 302 and "error=invalid_request" in resp.headers["location"]


async def test_tampered_consent_form_rejected(h):
    hdr = {"cf-access-jwt-assertion": access_jwt()}
    params = {"response_type": "code", "client_id": CLIENT, "redirect_uri": CLAUDE_CB, "code_challenge": "abc",
              "code_challenge_method": "S256", "state": "s"}
    page = await h.http.get("/oauth/authorize", params=params, headers=hdr)
    token = re.search(r"name=form_token value='([^']+)'", page.text).group(1)
    resp = await h.http.post("/oauth/authorize", headers=hdr, data={
        **params, "code_challenge": "attacker", "form_token": token, "decision": "approve"})
    assert resp.status_code == 400


async def test_full_flow_pkce_refresh_rotation_and_reuse(h):
    code, verifier = await h.authorize()
    bad = await h.exchange(code, "wrong-verifier-" + "x" * 40)
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    # The failed attempt burned the code.
    assert (await h.exchange(code, verifier)).status_code == 400

    async with h.running():
        code, verifier = await h.authorize()
        first = (await h.exchange(code, verifier)).json()
        assert first["scope"] == "lab.read" and first["token_type"] == "Bearer"
        assert await h.mcp_status(first["access_token"]) == 200

        rotated = await h.refresh(first["refresh_token"])
        assert rotated.status_code == 200
        second = rotated.json()
        assert second["refresh_token"] != first["refresh_token"]
        assert await h.mcp_status(second["access_token"]) == 200

        reused = await h.refresh(first["refresh_token"])
        assert reused.status_code == 400 and reused.json()["error"] == "invalid_grant"
        # Reuse revoked the whole family, including the newest tokens.
        assert await h.mcp_status(second["access_token"]) == 401
        assert (await h.refresh(second["refresh_token"])).status_code == 400


async def test_code_replay_revokes_issued_tokens(h):
    code, verifier = await h.authorize()
    tokens = (await h.exchange(code, verifier)).json()
    assert (await h.exchange(code, verifier)).status_code == 400
    assert await h.mcp_status(tokens["access_token"]) == 401


async def test_refresh_bound_to_client(h):
    tokens = await h.tokens()
    assert (await h.refresh(tokens["refresh_token"], client_id=CODE_CLIENT)).status_code == 400


async def test_revoke_endpoint(h):
    tokens = await h.tokens()
    assert (await h.http.post("/oauth/revoke", data={"token": tokens["refresh_token"]})).status_code == 200
    assert await h.mcp_status(tokens["access_token"]) == 401


async def test_claude_code_loopback_any_port(h):
    code, verifier = await h.authorize(client_id=CODE_CLIENT, redirect_uri="http://127.0.0.1:53111/callback")
    resp = await h.exchange(code, verifier, client_id=CODE_CLIENT, redirect_uri="http://127.0.0.1:53111/callback")
    assert resp.status_code == 200


async def test_write_tool_needs_write_scope(h):
    async with h.running():
        read_only = await h.tokens(write=False)
        names, result = await h.call(read_only["access_token"], "lab_notify", {"message": "hi"})
        assert {"lab_overview", "prom_query", "unit_status", "unit_logs", "ha_states", "ha_history",
                "media_status", "lab_notify", "ha_call_service"} == set(names)
        assert result.isError and "lab.write" in result.content[0].text
        assert h.notified == []

        writer = await h.tokens(write=True)
        assert writer["scope"] == "lab.read lab.write"
        _, result = await h.call(writer["access_token"], "lab_notify", {"message": "hi"})
        assert not result.isError
        assert h.notified == [("hi", None)]


async def test_ha_call_service_deny_list_before_backend(h):
    async with h.running():
        writer = await h.tokens(write=True)
        _, result = await h.call(writer["access_token"], "ha_call_service",
                                 {"domain": "lock", "service": "unlock", "entity_id": ["lock.front_door"]})
        assert result.isError and "deny list" in result.content[0].text


async def test_dcr_off_by_default_and_restricted_when_on(tmp_path):
    off = Harness(tmp_path / "off")
    assert (await off.http.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB]})).status_code == 404

    on = Harness(tmp_path / "on", dcr=True)
    asm = (await on.http.get("/.well-known/oauth-authorization-server")).json()
    assert asm["registration_endpoint"] == f"{BASE}/oauth/register"
    evil = await on.http.post("/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]})
    assert evil.status_code == 400
    ok = await on.http.post("/oauth/register", json={"redirect_uris": [CLAUDE_CB], "client_name": "Claude"})
    assert ok.status_code == 201
    client_id = ok.json()["client_id"]
    code, verifier = await on.authorize(client_id=client_id)
    assert (await on.exchange(code, verifier, client_id=client_id)).status_code == 200
