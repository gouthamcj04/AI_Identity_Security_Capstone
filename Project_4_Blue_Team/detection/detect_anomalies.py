"""Anomaly detection over the audit log (Project 4, item 4).

Reads the JSON-lines audit log written by 02-iam-design/auth.py's log_event() (each
line: ts, event, status, sub, client, scope, agent_id, jti, ...) and fires three
alert types:

  1. volume_spike    more than 20 requests in any 60-second window from one identity
  2. scope_change    consecutive requests from the same identity with a different
                     `scope` string
  3. token_reuse     a token (by `jti`) is used again after a token_expired event
                     was already logged for that same jti

Usage:
    python detect_anomalies.py <path-to-audit.log>
    python detect_anomalies.py --replay <path-to-audit.log>   # same thing, explicit

Each alert line has a timestamp, the identity involved, and the event type, as the
brief asks.
"""
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

VOLUME_WINDOW_SECONDS = 60
VOLUME_THRESHOLD = 20


def _parse_ts(ts_str):
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def _identity_of(record):
    """Prefer agent_id (non-human identity) then sub (human/user), then client."""
    return record.get("agent_id") or record.get("sub") or record.get("client") or "unknown"


def load_records(log_path):
    records = []
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    records.sort(key=lambda r: r.get("ts", ""))
    return records


def detect(records):
    """Return a list of alert dicts: {ts, identity, alert_type, detail}."""
    alerts = []

    # --- 1. Volume spike: sliding window per identity ---
    windows = defaultdict(deque)  # identity -> deque of datetimes
    spiked_already = set()  # avoid re-alerting every single request once over threshold
    for r in records:
        if "ts" not in r:
            continue
        identity = _identity_of(r)
        ts = _parse_ts(r["ts"])
        dq = windows[identity]
        dq.append(ts)
        while dq and (ts - dq[0]) > timedelta(seconds=VOLUME_WINDOW_SECONDS):
            dq.popleft()
        if len(dq) > VOLUME_THRESHOLD:
            key = (identity, ts.replace(microsecond=0))
            if identity not in spiked_already:
                alerts.append({
                    "ts": r["ts"], "identity": identity, "alert_type": "volume_spike",
                    "detail": f"{len(dq)} requests within {VOLUME_WINDOW_SECONDS}s (threshold {VOLUME_THRESHOLD})",
                })
                spiked_already.add(identity)
        else:
            spiked_already.discard(identity)

    # --- 2. Scope change between consecutive requests from the same identity ---
    last_scope = {}
    for r in records:
        if "ts" not in r or "scope" not in r or r.get("scope") is None:
            continue
        identity = _identity_of(r)
        scope = r["scope"]
        if identity in last_scope and last_scope[identity] != scope:
            alerts.append({
                "ts": r["ts"], "identity": identity, "alert_type": "scope_change",
                "detail": f"scope changed from {last_scope[identity]!r} to {scope!r}",
            })
        last_scope[identity] = scope

    # --- 3. Token reuse after expiry (same jti seen again after a token_expired event) ---
    expired_jtis = {}  # jti -> ts of the token_expired event
    for r in records:
        if "ts" not in r or not r.get("jti"):
            continue
        jti = r["jti"]
        if r.get("event") == "token_expired":
            expired_jtis[jti] = r["ts"]
        elif jti in expired_jtis and r["ts"] > expired_jtis[jti]:
            alerts.append({
                "ts": r["ts"], "identity": _identity_of(r), "alert_type": "token_reuse",
                "detail": f"jti {jti} reused at {r['ts']} after expiring at {expired_jtis[jti]}",
            })

    alerts.sort(key=lambda a: a["ts"])
    return alerts


def main():
    args = [a for a in sys.argv[1:] if a != "--replay"]
    if len(args) != 1:
        print("Usage: python detect_anomalies.py <path-to-audit.log>")
        return 1
    records = load_records(args[0])
    alerts = detect(records)
    if not alerts:
        print(f"Loaded {len(records)} log records. No anomalies detected.")
        return 0
    print(f"Loaded {len(records)} log records. {len(alerts)} alert(s):\n")
    for a in alerts:
        print(f"[{a['ts']}] ALERT type={a['alert_type']} identity={a['identity']} -- {a['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())