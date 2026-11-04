"""JWT validation, scope enforcement and audit logging for the SecureNova API.

This module is the resource-server side of the design: it never trusts the
caller, it checks the token's signature, issuer, audience and expiry on every
request, and it records one JSON audit line per decision.
"""
import json
import os
import threading
from datetime import datetime, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request
from jwt import PyJWKClient

AGENT_CLAIM = "https://securenova.local/agent_id"  # namespaced claim set by the Auth0 Action

_jwks_client = None
_log_lock = threading.Lock()


def _issuer():
    """Auth0 issues tokens with the tenant domain as issuer, trailing slash included."""
    return f"https://{os.environ['AUTH0_DOMAIN']}/"


def _audiences():
    """Accepted API audiences: the main API (user tokens) and the agent API (M2M tokens)."""
    return [a for a in (os.environ.get("API_AUDIENCE"), os.environ.get("M2M_AUDIENCE")) if a]


def _signing_key(token):
    """Return the public key matching the token's `kid` from Auth0's JWKS endpoint.

    Tests replace this function so no network access is needed.
    """
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(f"https://{os.environ['AUTH0_DOMAIN']}/.well-known/jwks.json")
    return _jwks_client.get_signing_key_from_jwt(token).key


def verify_token(token):
    """Validate an access token and return its claims.

    - Only RS256 is accepted, which blocks algorithm-confusion attacks.
    - exp, iss and aud are mandatory; there is no clock leeway, so an expired
      token is rejected the moment it expires.
    """
    return jwt.decode(
        token,
        _signing_key(token),
        algorithms=["RS256"],
        audience=_audiences(),
        issuer=_issuer(),
        options={"require": ["exp", "iss", "aud"]},
        leeway=0,
    )


def verify_id_token(id_token, client_id):
    """Validate an OIDC ID token for the web app (audience is the client ID)."""
    return jwt.decode(
        id_token,
        _signing_key(id_token),
        algorithms=["RS256"],
        audience=client_id,
        issuer=_issuer(),
        options={"require": ["exp", "iss", "aud"]},
    )


def scopes_of(claims):
    """Collect granted scopes from the `scope` string and the RBAC `permissions` list."""
    granted = set((claims.get("scope") or "").split())
    granted.update(claims.get("permissions") or [])
    return granted


def log_event(event, status, claims=None, unverified=False, **extra):
    """Append one JSON audit line. Tokens are never written to the log."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "status": status,
        "method": request.method,
        "path": request.path,
        "ip": request.remote_addr,
    }
    if claims:
        record.update(
            sub=claims.get("sub"),
            client=claims.get("azp") or claims.get("client_id"),
            scope=claims.get("scope"),
            agent_id=claims.get(AGENT_CLAIM) or claims.get("agent_id"),
            jti=claims.get("jti"),
            identity_verified=not unverified,
        )
    record.update(extra)
    with _log_lock:
        with open(os.environ.get("AUDIT_LOG", "audit.log"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


def _bearer_token():
    header = request.headers.get("Authorization", "")
    parts = header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _unverified_claims(token):
    """Read claims WITHOUT verifying, only to attribute a rejected token in the audit log."""
    try:
        return jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
    except jwt.InvalidTokenError:
        return None


def _deny(status, error, description):
    response = jsonify(error=error, error_description=description)
    response.status_code = status
    if status == 401:
        response.headers["WWW-Authenticate"] = f'Bearer error="{error}"'
    return response


def require_scope(required):
    """Decorator: 401 for a missing or invalid token, 403 when the scope is not granted."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = _bearer_token()
            if not token:
                log_event("missing_token", 401)
                return _deny(401, "missing_token", "Authorization: Bearer <token> is required")
            try:
                claims = verify_token(token)
            except jwt.ExpiredSignatureError:
                log_event("token_expired", 401, claims=_unverified_claims(token), unverified=True)
                return _deny(401, "invalid_token", "The access token has expired")
            except jwt.InvalidTokenError as exc:
                log_event("invalid_token", 401, claims=_unverified_claims(token), unverified=True,
                          reason=type(exc).__name__)
                return _deny(401, "invalid_token", "The access token is not valid")
            if required not in scopes_of(claims):
                log_event("insufficient_scope", 403, claims=claims, required_scope=required)
                return _deny(403, "insufficient_scope", f"Scope '{required}' is required")
            g.claims = claims
            log_event("access_granted", 200, claims=claims, required_scope=required)
            return fn(*args, **kwargs)

        return wrapper

    return decorator