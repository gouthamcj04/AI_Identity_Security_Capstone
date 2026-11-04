"""Credential rotation demo for the AI agent's M2M identity (Project 2, item 4).

1. Request a short-lived token from Auth0 (client credentials grant).
2. Call the /chat API with it and expect 200.
3. Wait until the token has expired.
4. Replay the same token and expect 401.

Every step prints a UTC timestamp so the terminal output works as evidence.
The token itself is never printed in full.
"""
import os
import sys
import time
from datetime import datetime, timezone

import jwt
import requests
from dotenv import load_dotenv

load_dotenv(os.environ.get("ENV_FILE", ".env"))

DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["M2M_CLIENT_ID"]
CLIENT_SECRET = os.environ["M2M_CLIENT_SECRET"]
AUDIENCE = os.environ["M2M_AUDIENCE"]
API_URL = os.environ.get("API_URL", "http://localhost:5000/api/chat")


def stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def say(message):
    print(f"[{stamp()}] {message}", flush=True)


def call_api(token):
    return requests.get(API_URL, params={"message": "rotation test"},
                        headers={"Authorization": f"Bearer {token}"}, timeout=10)


def main():
    say(f"Requesting M2M token from {DOMAIN} (audience {AUDIENCE})")
    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        json={"grant_type": "client_credentials", "client_id": CLIENT_ID,
              "client_secret": CLIENT_SECRET, "audience": AUDIENCE},
        timeout=10,
    )
    if resp.status_code != 200:
        say(f"Token request failed: HTTP {resp.status_code} {resp.json().get('error_description', '')}")
        return 1
    token = resp.json()["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    ttl = claims["exp"] - claims["iat"]
    say(f"Token issued: {token[:12]}... lifetime={ttl}s exp={datetime.fromtimestamp(claims['exp'], timezone.utc):%H:%M:%S}Z")

    first = call_api(token)
    say(f"Call 1 with fresh token -> HTTP {first.status_code}")

    wait = max(0, claims["exp"] - time.time()) + 2
    say(f"Waiting {wait:.0f}s for the token to expire")
    while wait > 0:
        step = min(10, wait)
        time.sleep(step)
        wait -= step

    replay = call_api(token)
    detail = replay.json().get("error_description", "") if replay.content else ""
    say(f"Call 2 replaying expired token -> HTTP {replay.status_code} {detail}")

    ok = first.status_code == 200 and replay.status_code == 401
    say("RESULT: PASS - fresh token accepted, expired token rejected" if ok
        else "RESULT: FAIL - unexpected status codes")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())