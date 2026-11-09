"""Runs your real Project 3 payloads through the guardrail (Project 4, item 1,
screenshots: BLOCKED status, and the JWT-redaction demo).

1. Fill in payloads.json with the exact text you used for each Project 3 attack
   (copy it from 03-red-team/lab/logs/interactions.jsonl -- the "user_message" field,
   or the text of the knowledge_base/ files you added).
2. Run: python run_guardrail_tests.py
3. It prints BLOCKED/PASSED per payload for your screenshot, and separately shows the
   output guardrail redacting a JWT out of a sample model reply.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import guardrail  # noqa: E402

PAYLOADS_FILE = Path(__file__).parent / "payloads.json"


def load_payloads():
    if not PAYLOADS_FILE.exists():
        print(f"Create {PAYLOADS_FILE} first -- see payloads.json.template")
        sys.exit(1)
    return json.loads(PAYLOADS_FILE.read_text(encoding="utf-8"))


def main():
    payloads = load_payloads()
    if not payloads:
        print("payloads.json is empty -- add your Project 3 payload text first.")
        return

    print(f"{'ID':<8} {'STATUS':<8} REASON")
    print("-" * 70)
    for entry in payloads:
        result = guardrail.check_input(entry["text"])
        status = "BLOCKED" if result["blocked"] else "PASSED"
        reason = "; ".join(result["reasons"]) or "no match"
        print(f"{entry['id']:<8} {status:<8} {reason}")

    print("\n--- Output guardrail demo (JWT redaction) ---")
    sample_reply = (
        "Sure, here is the internal reference: "
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.ZmFrZS1zaWduYXR1cmU "
        "and also FAKE-sk-securenova-9f3c1a7b2e4d -- let me know if you need anything else."
    )
    redacted, count = guardrail.redact_output(sample_reply)
    print(f"Original: {sample_reply}")
    print(f"Redacted ({count} secret(s) found): {redacted}")


if __name__ == "__main__":
    main()