"""Tests refresh token rotation + reuse detection (Project 4, item 1: old refresh
token replay should fail after rotation).

Requires, in the Auth0 dashboard:
  1. APIs > SecureNova AI API > Settings > Allow Offline Access: ON
  2. Applications > SecureNova Chat Web > Advanced Settings > Grant Types: tick
     "Refresh Token"
  3. Applications > SecureNova Chat Web > Refresh Token Rotation: set to Rotating,
     and Reuse Interval to 0 (or your preferred small value), with Reuse Detection ON.

Also needs ROPG enabled on the application (see test_legitimate_logins.py) so this
script can get an initial refresh token without a browser.
"""
import os
import sys
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv(os.environ.get("ENV_FILE", ".env"))

DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENT_ID = os.environ["WEB_CLIENT_ID"]
CLIENT_SECRET = os.environ["WEB_CLIENT_SECRET"]
TEST_USER_EMAIL = os.environ["TEST_USER_EMAIL"]
TEST_USER_PASSWORD = os.environ["TEST_USER_PASSWORD"]


def stamp():
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def say(msg):
    print(f"[{stamp()}] {msg}")


def get_tokens_via_password_grant():
    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        json={
            "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
            "realm": "Username-Password-Authentication",
            "username": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid profile email offline_access",
        },
        timeout=10,
    )
    if resp.status_code != 200:
        raise SystemExit(f"Initial login failed: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json()


def refresh(refresh_token):
    return requests.post(
        f"https://{DOMAIN}/oauth/token",
        json={"grant_type": "refresh_token", "client_id": CLIENT_ID,
              "client_secret": CLIENT_SECRET, "refresh_token": refresh_token},
        timeout=10,
    )


def main():
    say("Logging in to obtain an initial refresh token...")
    tokens = get_tokens_via_password_grant()
    old_refresh = tokens.get("refresh_token")
    if not old_refresh:
        print("No refresh_token returned -- check Allow Offline Access and the "
              "offline_access scope are both enabled.")
        return 1
    say(f"Got refresh token: {old_refresh[:10]}...")

    say("Using it once (this is the normal, expected rotation)...")
    first = refresh(old_refresh)
    if first.status_code != 200:
        print(f"First refresh failed unexpectedly: HTTP {first.status_code} {first.text[:300]}")
        return 1
    new_refresh = first.json().get("refresh_token")
    say(f"HTTP 200 -- rotated, new refresh token: {new_refresh[:10] if new_refresh else '(none)'}...")

    say("Replaying the OLD (already-rotated-away) refresh token...")
    replay = refresh(old_refresh)
    detail = replay.json().get("error_description", "") if replay.content else ""
    say(f"HTTP {replay.status_code} {detail}")

    ok = replay.status_code != 200
    say("RESULT: PASS -- old refresh token rejected after rotation" if ok
        else "RESULT: FAIL -- old refresh token was still accepted; check rotation settings")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())