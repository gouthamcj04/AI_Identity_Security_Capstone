"""SecureNova chat web app and API (Project 2).

One Flask process plays two roles:
  * Regular Web Application: signs users in with OAuth 2.0 Authorization Code + PKCE.
  * Resource server: /api/chat needs `read:ai-data`, /api/admin needs `write:admin`.

Run a second copy on another port with a different ENV_FILE to test SSO.
"""
import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import jwt
import requests
from dotenv import load_dotenv

load_dotenv(os.environ.get("ENV_FILE", ".env"))

from flask import Flask, g, jsonify, redirect, render_template_string, request, session  # noqa: E402
from markupsafe import escape  # noqa: E402

import auth  # noqa: E402

DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
CLIENT_ID = os.environ.get("WEB_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("WEB_CLIENT_SECRET", "")
API_AUDIENCE = os.environ.get("API_AUDIENCE", "")
BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")
PORT = int(os.environ.get("PORT", "5000"))
SCOPES = os.environ.get("SCOPES", "openid profile email read:ai-data")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
# Cookies are shared across ports on localhost, so each instance gets its own cookie name.
app.config.update(
    SESSION_COOKIE_NAME=f"securenova_session_{PORT}",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Tokens stay on the server; the browser cookie only holds an opaque session id.
TOKEN_STORE = {}

PAGE = """<!doctype html><title>SecureNova - {{ title }}</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
pre,textarea{width:100%;background:#f4f4f4;padding:.6rem;border-radius:6px;white-space:pre-wrap;word-break:break-all}
td{padding:.2rem .8rem .2rem 0;vertical-align:top}a{margin-right:1rem}</style>
<h2>SecureNova AI Chat ({{ title }})</h2>{{ body|safe }}"""


def page(title, body, status=200):
    """Render a page and return (html, status). `body` is trusted markup: callers must
    escape() every value that comes from the URL, a token or a remote response."""
    return render_template_string(PAGE, title=title, body=body), status


def pkce_challenge(verifier):
    """S256 code challenge: BASE64URL(SHA256(verifier)) without padding (RFC 7636)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_pair():
    """Random 86-character verifier and its challenge."""
    verifier = secrets.token_urlsafe(64)
    return verifier, pkce_challenge(verifier)


@app.route("/")
def home():
    if session.get("sid") in TOKEN_STORE:
        return redirect("/tokens")
    return page("Home", '<p>You are signed out.</p><a href="/login">Sign in with Auth0</a>')


@app.route("/login")
def login():
    verifier, challenge = pkce_pair()
    session["state"] = secrets.token_urlsafe(24)   # CSRF protection
    session["nonce"] = secrets.token_urlsafe(24)   # binds the ID token to this login
    session["verifier"] = verifier
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/callback",
        "scope": SCOPES,
        "audience": API_AUDIENCE,
        "state": session["state"],
        "nonce": session["nonce"],
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"https://{DOMAIN}/authorize?{urlencode(params)}")


@app.route("/callback")
def callback():
    if request.args.get("error"):
        error = escape(request.args.get("error"))
        description = escape(request.args.get("error_description", ""))
        return page("Login error", f"<pre>{error}: {description}</pre>", 400)
    expected_state = session.pop("state", None)
    if not expected_state or request.args.get("state") != expected_state:
        return page("Login error", "<pre>State mismatch: possible CSRF, login rejected.</pre>", 400)
    verifier = session.pop("verifier", None)
    expected_nonce = session.pop("nonce", None)
    if not verifier or not expected_nonce or not request.args.get("code"):
        return page("Login error", "<pre>Login session expired. Start again.</pre>", 400)

    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": request.args["code"],
            "code_verifier": verifier,
            "redirect_uri": f"{BASE_URL}/callback",
        },
        timeout=10,
    )
    if resp.status_code != 200:
        detail = resp.json().get("error_description", "token exchange failed") if resp.content else "token exchange failed"
        return page("Login error", f"<pre>HTTP {resp.status_code}: {escape(detail)}</pre>", 502)
    tokens = resp.json()

    try:
        id_claims = auth.verify_id_token(tokens["id_token"], CLIENT_ID)
    except (jwt.InvalidTokenError, KeyError) as exc:
        return page("Login error", f"<pre>ID token rejected: {type(exc).__name__}</pre>", 400)
    if id_claims.get("nonce") != expected_nonce:
        return page("Login error", "<pre>Nonce mismatch, login rejected.</pre>", 400)

    sid = secrets.token_urlsafe(16)
    TOKEN_STORE[sid] = tokens
    session["sid"] = sid
    return redirect("/tokens")


def _decoded(token):
    """Decode WITHOUT verifying, for display only. Never use this for authorisation."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return {}


@app.route("/tokens")
def tokens_page():
    tokens = TOKEN_STORE.get(session.get("sid"))
    if not tokens:
        return redirect("/login")
    access, idt = tokens.get("access_token", ""), tokens.get("id_token", "")
    claims = _decoded(access)
    rows = ""
    for key in ("iss", "aud", "scope", "azp", auth.AGENT_CLAIM, "agent_id"):
        if key in claims:
            rows += f"<tr><td><b>{escape(key)}</b></td><td>{escape(str(claims[key]))}</td></tr>"
    if isinstance(claims.get("exp"), int):
        exp = datetime.fromtimestamp(claims["exp"], timezone.utc).isoformat()
        life = claims["exp"] - claims.get("iat", claims["exp"])
        rows += f"<tr><td><b>exp</b></td><td>{exp} (lifetime {life}s)</td></tr>"
    body = (
        "<p>Lab view only: copy a token into jwt.io to inspect it.</p>"
        f"<table>{rows}</table>"
        "<h4>Access token</h4><textarea rows=6 readonly>" + str(escape(access)) + "</textarea>"
        "<h4>ID token</h4><textarea rows=6 readonly>" + str(escape(idt)) + "</textarea>"
        '<p><a href="/demo/chat">Call /api/chat</a><a href="/demo/admin">Call /api/admin</a>'
        '<a href="/logout">Sign out</a></p>'
    )
    return page("Tokens", body)


@app.route("/demo/<endpoint>")
def demo(endpoint):
    """Call our own API with the signed-in user's token to show the 200 / 403 behaviour."""
    if endpoint not in {"chat", "admin"}:
        return page("Not found", "<p>Unknown endpoint</p>", 404)
    tokens = TOKEN_STORE.get(session.get("sid"))
    if not tokens:
        return redirect("/login")
    resp = requests.get(
        f"{BASE_URL}/api/{endpoint}",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        timeout=10,
    )
    return page(f"GET /api/{endpoint}", f"<pre>HTTP {resp.status_code}\n{escape(resp.text)}</pre><a href='/tokens'>Back</a>")


@app.route("/logout")
def logout():
    TOKEN_STORE.pop(session.get("sid"), None)
    session.clear()
    return redirect(f"https://{DOMAIN}/v2/logout?{urlencode({'client_id': CLIENT_ID, 'returnTo': BASE_URL + '/'})}")


@app.route("/api/chat", methods=["GET", "POST"])
@auth.require_scope("read:ai-data")
def api_chat():
    """User-level endpoint. The LLM agent is wired in during Project 3."""
    if request.method == "POST":
        message = (request.get_json(silent=True) or {}).get("message", "")
    else:
        message = request.args.get("message", "")
    return jsonify(
        reply=f"SecureNova assistant received: {message[:200]}",
        sub=g.claims.get("sub"),
        client=g.claims.get("azp") or g.claims.get("client_id"),
    )


@app.route("/api/admin", methods=["GET", "POST"])
@auth.require_scope("write:admin")
def api_admin():
    """Admin-level endpoint: a user token without write:admin must get 403."""
    return jsonify(status="admin action permitted", sub=g.claims.get("sub"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)