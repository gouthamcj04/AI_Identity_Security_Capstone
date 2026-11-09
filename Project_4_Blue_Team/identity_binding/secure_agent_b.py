"""Signed-message version of Agent B, wired against the Project 3 lab (item 2 fix).

03-red-team/lab/agents.handle_agent_b_message() accepts a plain `sender` string with
no verification. This module replaces that with a signed-envelope version: Agent B
only acts if the message verifies against a known sender's public key.

Run with the lab app's directory on the path so it can reuse mcp_tools:
    PYTHONPATH=../../03-red-team/lab python secure_agent_b.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sign_agent_messages as sam  # noqa: E402

LAB_DIR = Path(__file__).resolve().parents[2] / "03-red-team" / "lab"
sys.path.insert(0, str(LAB_DIR))
try:
    import mcp_tools  # noqa: E402
except ImportError:
    mcp_tools = None  # the demo below still runs the signing logic without the lab app


# Which public key is trusted to issue orchestrator instructions.
TRUSTED_SENDER_KEY = "orchestrator"


def handle_signed_agent_b_message(envelope):
    """Verify the envelope, then run the instructed tool only on success.

    Returns a result dict mirroring the Project 3 lab's shape, plus
    `sender_verified: True` -- the field Project 3's version always set False.
    """
    try:
        public_key = sam.load_public_key(TRUSTED_SENDER_KEY)
    except FileNotFoundError:
        return {"sender_verified": False, "tool_call": None,
                "error": f"no trusted public key on file for {TRUSTED_SENDER_KEY!r}"}

    try:
        payload = sam.verify_message(public_key, envelope)
    except sam.VerificationError as exc:
        return {"sender_verified": False, "tool_call": None, "error": str(exc)}

    instruction = payload.get("instruction", "")
    tool_result, tool_name = None, None
    if mcp_tools:
        if instruction == "lookup_ticket" and payload.get("ticket_id"):
            tool_name = "lookup_ticket"
            tool_result = mcp_tools.lookup_ticket(payload["ticket_id"])
        elif instruction == "issue_refund" and payload.get("ticket_id") and "amount_usd" in payload:
            tool_name = "issue_refund"
            tool_result = mcp_tools.issue_refund(payload["ticket_id"], payload["amount_usd"])
        elif instruction == "export_customer_data" and payload.get("customer_id"):
            tool_name = "export_customer_data"
            tool_result = mcp_tools.export_customer_data(payload["customer_id"])

    return {"sender_verified": True, "sender": payload["sender"],
            "tool_call": tool_name, "tool_result": tool_result}


def _demo():
    print("=== Secure Agent B (Project 4 fix for Project 3 item 2) ===\n")
    priv, _ = sam.generate_keypair(TRUSTED_SENDER_KEY)

    print("[1] Legitimate, signed instruction from the orchestrator:")
    good = sam.sign_message(priv, sender="orchestrator", instruction="lookup_ticket",
                            ticket_id="TCK-1001")
    print(f"    {handle_signed_agent_b_message(good)}\n")

    print("[2] Same instruction, but tampered after signing (ticket_id changed):")
    tampered = good.copy()
    tampered["payload"] = dict(good["payload"], ticket_id="TCK-9999")
    print(f"    {handle_signed_agent_b_message(tampered)}\n")

    print("[3] A message that merely CLAIMS sender='orchestrator' but is signed by an")
    print("    unrelated key (what Project 3's spoofing attack relied on):")
    attacker_priv, _ = sam.generate_keypair("attacker")
    forged = sam.sign_message(attacker_priv, sender="orchestrator",
                              instruction="issue_refund", ticket_id="TCK-1001", amount_usd=500)
    print(f"    {handle_signed_agent_b_message(forged)}")


if __name__ == "__main__":
    _demo()