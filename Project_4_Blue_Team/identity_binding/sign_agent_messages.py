"""Cryptographic agent identity binding with Ed25519 (Project 4, item 2).

Fixes the exact gap Project 3 item 2 targeted: 03-red-team/lab/agents.py's
`handle_agent_b_message` accepted any `sender` string with no verification.
Here, every inter-agent message is signed by the sender's private key and verified
with the sender's public key before Agent B acts on it. A message with even one
byte changed after signing must fail verification.

Run this file directly for a demo: generates keys, signs a message, verifies it,
tampers with it, and shows the rejection -- this is your terminal screenshot.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_DIR = Path(__file__).parent / "keys"


def generate_keypair(name):
    """Write <name>_private.pem and <name>_public.pem to keys/. Returns (private, public)."""
    KEY_DIR.mkdir(exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = KEY_DIR / f"{name}_private.pem"
    pub_path = KEY_DIR / f"{name}_public.pem"
    priv_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_key, public_key


def load_private_key(name):
    path = KEY_DIR / f"{name}_private.pem"
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(name):
    path = KEY_DIR / f"{name}_public.pem"
    return serialization.load_pem_public_key(path.read_bytes())


def _canonical(payload: dict) -> bytes:
    """Deterministic byte encoding so sign and verify always hash the same bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_message(private_key: Ed25519PrivateKey, sender, instruction, **fields):
    """Build and sign an agent-to-agent message. Returns the full signed envelope."""
    payload = {
        "sender": sender,
        "instruction": instruction,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nonce": f"{time.time_ns()}",
        **fields,
    }
    signature = private_key.sign(_canonical(payload))
    return {"payload": payload, "signature": signature.hex()}


class VerificationError(Exception):
    pass


def verify_message(public_key: Ed25519PublicKey, envelope: dict):
    """Raise VerificationError if the signature doesn't match the payload bytes
    exactly. Returns the verified payload dict on success."""
    try:
        signature = bytes.fromhex(envelope["signature"])
    except (KeyError, ValueError) as exc:
        raise VerificationError(f"malformed signature field: {exc}") from exc
    try:
        public_key.verify(signature, _canonical(envelope["payload"]))
    except InvalidSignature as exc:
        raise VerificationError("signature does not match payload -- message rejected") from exc
    return envelope["payload"]


def _demo():
    print("=== Ed25519 Agent Identity Binding Demo ===\n")

    print("[1] Generating Ed25519 key pair for 'orchestrator'...")
    priv, pub = generate_keypair("orchestrator")
    print(f"    Wrote {KEY_DIR / 'orchestrator_private.pem'}")
    print(f"    Wrote {KEY_DIR / 'orchestrator_public.pem'}\n")

    print("[2] Signing a message from the orchestrator to Agent B...")
    envelope = sign_message(priv, sender="orchestrator",
                            instruction="lookup_ticket", ticket_id="TCK-1001")
    print(f"    Payload:   {json.dumps(envelope['payload'])}")
    print(f"    Signature: {envelope['signature'][:32]}... ({len(envelope['signature'])} hex chars)\n")

    print("[3] Agent B verifies the signature with the orchestrator's PUBLIC key...")
    verified = verify_message(pub, envelope)
    print(f"    VERIFIED OK -- Agent B may now act on: {verified}\n")

    print("[4] Tampering with the message (changing one character in the instruction)...")
    tampered = json.loads(json.dumps(envelope))
    tampered["payload"]["instruction"] = "issue_refund"  # one field changed after signing
    print(f"    Tampered payload: {json.dumps(tampered['payload'])}")
    try:
        verify_message(pub, tampered)
        print("    UNEXPECTED: tampered message was accepted -- this should never happen")
    except VerificationError as exc:
        print(f"    REJECTED as expected: {exc}\n")

    print("[5] A message claiming to be from the orchestrator but signed by a DIFFERENT key...")
    attacker_priv, _ = generate_keypair("attacker")
    forged = sign_message(attacker_priv, sender="orchestrator",
                          instruction="export_customer_data", customer_id="CUST-001")
    try:
        verify_message(pub, forged)  # verifying with the orchestrator's real public key
        print("    UNEXPECTED: forged message was accepted")
    except VerificationError as exc:
        print(f"    REJECTED as expected: {exc}")
        print("    (the 'sender' field alone proves nothing -- only a valid signature does)")


if __name__ == "__main__":
    _demo()