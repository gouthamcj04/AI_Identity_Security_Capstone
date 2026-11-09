"""Run: python -m unittest discover -s tests -v"""
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MODULE_DIR))

import sign_agent_messages as sam  # noqa: E402


class SigningTests(unittest.TestCase):
    def setUp(self):
        sam.KEY_DIR = Path(tempfile.mkdtemp())

    def test_valid_signed_message_verifies(self):
        priv, pub = sam.generate_keypair("orchestrator")
        envelope = sam.sign_message(priv, sender="orchestrator", instruction="lookup_ticket")
        payload = sam.verify_message(pub, envelope)
        self.assertEqual(payload["instruction"], "lookup_ticket")

    def test_one_character_tamper_is_rejected(self):
        priv, pub = sam.generate_keypair("orchestrator")
        envelope = sam.sign_message(priv, sender="orchestrator", instruction="lookup_ticket")
        envelope["payload"]["instruction"] = "lookup_tickeu"  # one character changed
        with self.assertRaises(sam.VerificationError):
            sam.verify_message(pub, envelope)

    def test_tampering_with_sender_field_is_rejected(self):
        priv, pub = sam.generate_keypair("orchestrator")
        envelope = sam.sign_message(priv, sender="orchestrator", instruction="x")
        envelope["payload"]["sender"] = "definitely-not-the-orchestrator"
        with self.assertRaises(sam.VerificationError):
            sam.verify_message(pub, envelope)

    def test_message_signed_by_a_different_key_is_rejected(self):
        _, legit_pub = sam.generate_keypair("orchestrator")
        attacker_priv, _ = sam.generate_keypair("attacker")
        forged = sam.sign_message(attacker_priv, sender="orchestrator", instruction="issue_refund")
        with self.assertRaises(sam.VerificationError):
            sam.verify_message(legit_pub, forged)

    def test_malformed_signature_field_is_rejected_not_raised_as_crash(self):
        _, pub = sam.generate_keypair("orchestrator")
        bad_envelope = {"payload": {"sender": "x", "instruction": "y"}, "signature": "not-hex!!"}
        with self.assertRaises(sam.VerificationError):
            sam.verify_message(pub, bad_envelope)

    def test_keys_round_trip_through_disk(self):
        sam.generate_keypair("orchestrator")
        priv = sam.load_private_key("orchestrator")
        pub = sam.load_public_key("orchestrator")
        envelope = sam.sign_message(priv, sender="orchestrator", instruction="lookup_ticket")
        self.assertEqual(sam.verify_message(pub, envelope)["sender"], "orchestrator")

    def test_canonical_encoding_is_order_independent(self):
        payload_a = {"b": 2, "a": 1}
        payload_b = {"a": 1, "b": 2}
        self.assertEqual(sam._canonical(payload_a), sam._canonical(payload_b))


if __name__ == "__main__":
    unittest.main()