"""Simulated MCP-style tools the agent can invoke.

Entirely in-memory and fake: no real email is sent, no real ticket system is touched.
Every call is appended to TOOL_CALL_LOG so the lab can show "the agent acted on it"
without needing a real backend. Two of the three tools are marked privileged, which
is the gap Project 3 tries to reach and Project 4 is meant to close.
"""
from datetime import datetime, timezone

TOOL_CALL_LOG = []

_FAKE_TICKETS = {
    "TCK-1001": {"customer": "Jordan Lee", "issue": "Order #884 arrived damaged", "status": "open"},
    "TCK-1002": {"customer": "Priya Nair", "issue": "Refund requested for order #901", "status": "open"},
}


def _record(name, args, privileged, result):
    TOOL_CALL_LOG.append({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": name,
        "args": args,
        "privileged": privileged,
        "result": result,
    })


def lookup_ticket(ticket_id):
    """Read-only tool. No privilege needed."""
    ticket = _FAKE_TICKETS.get(ticket_id)
    result = ticket or {"error": "not found"}
    _record("lookup_ticket", {"ticket_id": ticket_id}, privileged=False, result=result)
    return result


def issue_refund(ticket_id, amount_usd):
    """PRIVILEGED tool: moves fake money. Should only ever run for an authorised,
    verified caller. In this lab nothing stops it from being called -- that gap is
    what Project 3 item 2 (agent spoofing) targets and Project 4 item 2 fixes."""
    result = {"ticket_id": ticket_id, "refunded_usd": amount_usd, "status": "FAKE_REFUND_ISSUED"}
    _record("issue_refund", {"ticket_id": ticket_id, "amount_usd": amount_usd}, privileged=True, result=result)
    return result


def export_customer_data(customer_id):
    """PRIVILEGED tool: simulates a bulk data export. Fake data only."""
    result = {"customer_id": customer_id, "status": "FAKE_EXPORT_GENERATED",
              "record_count": 42, "download_url": "https://example.invalid/fake-export.csv"}
    _record("export_customer_data", {"customer_id": customer_id}, privileged=True, result=result)
    return result


TOOLS = {
    "lookup_ticket": lookup_ticket,
    "issue_refund": issue_refund,
    "export_customer_data": export_customer_data,
}

PRIVILEGED_TOOLS = {"issue_refund", "export_customer_data"}