"""Tests the risk-action.js Action against 10 legitimate logins (Project 4, item 1:
"test 10 legitimate inputs against the guardrails and record the false positive rate").

This uses the Resource Owner Password Grant (ROPG), which IS the simplest way to
script repeated logins for a test user, but it bypasses the browser and is disabled
by default and discouraged by Auth0 for production use. It still goes through the
post-login Action (the Action runs on the Login flow regardless of grant type), so
it's a valid way to test the Action's false-positive behaviour.

To enable it for this test ONLY:
  Auth0 Dashboard > Your Application > Advanced Settings > Grant Types > tick
  "Password". Untick it again once you're done testing.

If you'd rather not enable ROPG, log in 10 times by hand through the browser instead
and just record in your report whether any were blocked -- the Action and its logic
are what's being evidenced, not this particular script.
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
AUDIENCE = os.environ.get("API_AUDIENCE", "")
TEST_USER_EMAIL = os.environ["TEST_USER_EMAIL"]
TEST_USER_PASSWORD = os.environ["TEST_USER_PASSWORD"]
TRIALS = int(os.environ.get("LOGIN_TRIALS", "10"))


def stamp():
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def attempt_login():
    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        json={
            "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
            "realm": "Username-Password-Authentication",
            "username": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "audience": AUDIENCE,
            "scope": "openid profile email",
        },
        timeout=10,
    )
    return resp


def main():
    blocked, allowed = 0, 0
    for i in range(1, TRIALS + 1):
        resp = attempt_login()
        if resp.status_code == 200:
            allowed += 1
            print(f"[{stamp()}] Attempt {i}/{TRIALS}: HTTP 200 allowed")
        else:
            blocked += 1
            detail = resp.json().get("error_description", "") if resp.content else ""
            print(f"[{stamp()}] Attempt {i}/{TRIALS}: HTTP {resp.status_code} blocked -- {detail}")

    fp_rate = blocked / TRIALS * 100
    print(f"\nRESULT: {allowed}/{TRIALS} allowed, {blocked}/{TRIALS} blocked")
    print(f"False positive rate: {fp_rate:.1f}% (blocked legitimate logins / total legitimate attempts)")
    if blocked:
        print("A legitimate login was blocked. Check ALLOWED_COUNTRY_CODES in risk-action.js "
              "matches the country you're testing from.")
    return 0


if __name__ == "__main__":
    sys.exit(main())