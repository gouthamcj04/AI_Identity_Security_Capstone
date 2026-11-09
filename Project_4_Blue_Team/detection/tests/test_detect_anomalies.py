"""Synthetic log data confirming each of the 3 alert types fires correctly.
Run against your real audit.log too: python detect_anomalies.py <path>
"""
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import detect_anomalies as da  # noqa: E402

BASE = datetime.fromisoformat("2026-11-06T12:00:00+00:00")


def ts(seconds_offset):
    return (BASE + timedelta(seconds=seconds_offset)).isoformat().replace("+00:00", "Z")


class VolumeSpikeTests(unittest.TestCase):
    def test_fires_when_over_threshold_in_window(self):
        records = [{"ts": ts(i), "sub": "auth0|user1", "event": "access_granted"}
                   for i in range(25)]  # 25 requests within 25 seconds < 60s window
        alerts = da.detect(records)
        spikes = [a for a in alerts if a["alert_type"] == "volume_spike"]
        self.assertTrue(spikes, "expected a volume_spike alert")
        self.assertEqual(spikes[0]["identity"], "auth0|user1")
        self.assertIn("ts", spikes[0])

    def test_does_not_fire_under_threshold(self):
        records = [{"ts": ts(i * 5), "sub": "auth0|user1", "event": "access_granted"}
                   for i in range(10)]  # spread out, well under threshold
        alerts = da.detect(records)
        self.assertFalse([a for a in alerts if a["alert_type"] == "volume_spike"])

    def test_requests_outside_window_do_not_count(self):
        # 15 requests now, then a gap, then 10 more later -- never >20 within any 60s window
        records = [{"ts": ts(i), "sub": "auth0|user1", "event": "access_granted"} for i in range(15)]
        records += [{"ts": ts(200 + i), "sub": "auth0|user1", "event": "access_granted"} for i in range(10)]
        alerts = da.detect(records)
        self.assertFalse([a for a in alerts if a["alert_type"] == "volume_spike"])


class ScopeChangeTests(unittest.TestCase):
    def test_fires_on_scope_change_same_identity(self):
        records = [
            {"ts": ts(0), "agent_id": "agent-01", "scope": "read:ai-data"},
            {"ts": ts(1), "agent_id": "agent-01", "scope": "write:admin"},
        ]
        alerts = da.detect(records)
        changes = [a for a in alerts if a["alert_type"] == "scope_change"]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["identity"], "agent-01")

    def test_no_alert_when_scope_stays_the_same(self):
        records = [
            {"ts": ts(0), "agent_id": "agent-01", "scope": "read:ai-data"},
            {"ts": ts(1), "agent_id": "agent-01", "scope": "read:ai-data"},
        ]
        self.assertFalse([a for a in da.detect(records) if a["alert_type"] == "scope_change"])

    def test_different_identities_do_not_cross_trigger(self):
        records = [
            {"ts": ts(0), "agent_id": "agent-01", "scope": "read:ai-data"},
            {"ts": ts(1), "agent_id": "agent-02", "scope": "write:admin"},
        ]
        self.assertFalse([a for a in da.detect(records) if a["alert_type"] == "scope_change"])


class TokenReuseTests(unittest.TestCase):
    def test_fires_when_expired_jti_used_again(self):
        records = [
            {"ts": ts(0), "sub": "auth0|user1", "jti": "tok-123", "event": "token_expired"},
            {"ts": ts(5), "sub": "auth0|user1", "jti": "tok-123", "event": "access_granted"},
        ]
        alerts = da.detect(records)
        reuses = [a for a in alerts if a["alert_type"] == "token_reuse"]
        self.assertEqual(len(reuses), 1)
        self.assertEqual(reuses[0]["identity"], "auth0|user1")

    def test_no_alert_for_a_fresh_jti_never_expired(self):
        records = [{"ts": ts(0), "sub": "auth0|user1", "jti": "tok-456", "event": "access_granted"}]
        self.assertFalse([a for a in da.detect(records) if a["alert_type"] == "token_reuse"])

    def test_no_alert_when_reuse_precedes_the_expiry_record(self):
        # out-of-order ts: the "reuse" happened before the expiry was ever logged
        records = [
            {"ts": ts(5), "sub": "auth0|user1", "jti": "tok-789", "event": "token_expired"},
            {"ts": ts(0), "sub": "auth0|user1", "jti": "tok-789", "event": "access_granted"},
        ]
        self.assertFalse([a for a in da.detect(records) if a["alert_type"] == "token_reuse"])


class LoadRecordsTests(unittest.TestCase):
    def test_skips_malformed_lines(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write('{"ts": "%s", "event": "x"}\n' % ts(0))
            fh.write("not json\n")
            fh.write("\n")
            path = fh.name
        records = da.load_records(path)
        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main()