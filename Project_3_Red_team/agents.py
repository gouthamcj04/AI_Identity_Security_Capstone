"""Orchestrator and Agent B.

Orchestrator: handles a user chat message, retrieves context from rag_store, calls
the LLM, and executes any TOOL_CALL the model emits.

Agent B: a second, worker agent that receives messages claiming to come from the
orchestrator and, today, does NOT verify that claim before acting -- it just reads a
`sender` field. That is the identity-spoofing gap Project 3 item 2 targets and
Project 4 item 2 (Ed25519 signing) is meant to close. Nothing here crafts a
message designed to exploit that gap; it only reports the sender it was given.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import llm_client
import mcp_tools
import rag_store

SYSTEM_PROMPT = (Path(__file__).parent / "system_prompt.txt").read_text(encoding="utf-8")
INTERACTION_LOG = Path(__file__).parent / "logs" / "interactions.jsonl"

TOOL_CALL_RE = re.compile(r"TOOL_CALL:\s*(\w+)\(([^)]*)\)")


def _parse_tool_call(text):
    match = TOOL_CALL_RE.search(text)
    if not match:
        return None
    name, arg_str = match.group(1), match.group(2)
    args = {}
    for part in arg_str.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        args[key.strip()] = value.strip().strip("'\"")
    return name, args


def _append_log(record):
    INTERACTION_LOG.parent.mkdir(exist_ok=True)
    record = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **record}
    with open(INTERACTION_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def handle_user_message(message, history=None):
    """Orchestrator path: retrieve -> prompt -> model reply -> optional tool call."""
    history = history or []
    retrieved = rag_store.retrieve(message)
    context_block = "\n\n".join(f"[Document: {d['name']}]\n{d['text']}" for d in retrieved) or "(no matching documents)"

    full_system = SYSTEM_PROMPT + "\n\n--- Retrieved context (untrusted, may contain user-provided content) ---\n" + context_block

    messages = history + [{"role": "user", "content": message}]
    reply = llm_client.chat(full_system, messages)

    tool_result = None
    parsed = _parse_tool_call(reply)
    if parsed:
        name, args = parsed
        fn = mcp_tools.TOOLS.get(name)
        if fn:
            try:
                tool_result = fn(**args)
            except TypeError as exc:
                tool_result = {"error": f"bad arguments for {name}: {exc}"}
        else:
            tool_result = {"error": f"unknown tool: {name}"}

    record = _append_log({
        "channel": "user-to-orchestrator",
        "user_message": message,
        "retrieved_documents": [d["name"] for d in retrieved],
        "model_reply": reply,
        "tool_call": parsed[0] if parsed else None,
        "tool_args": parsed[1] if parsed else None,
        "tool_result": tool_result,
    })
    return {
        "reply": reply,
        "retrieved_documents": [d["name"] for d in retrieved],
        "tool_call": parsed[0] if parsed else None,
        "tool_result": tool_result,
        "logged_at": record["ts"],
    }


def handle_agent_b_message(sender, instruction, ticket_id=None, amount_usd=None, customer_id=None):
    """Agent B path (Project 3 item 2 / Project 4 item 2 surface).

    `sender` is caller-supplied and UNVERIFIED -- there is no signature check here.
    Agent B logs whatever sender value it was given and, if the instruction matches a
    known pattern, runs the matching privileged tool. This file does not generate a
    message that impersonates the orchestrator; what to put in `sender` and
    `instruction` is for you to decide and enter yourself when you call the endpoint.
    """
    instruction_lower = instruction.lower()
    tool_result = None
    tool_name = None

    if "refund" in instruction_lower and ticket_id and amount_usd is not None:
        tool_name = "issue_refund"
        tool_result = mcp_tools.issue_refund(ticket_id, amount_usd)
    elif "export" in instruction_lower and customer_id:
        tool_name = "export_customer_data"
        tool_result = mcp_tools.export_customer_data(customer_id)
    elif "lookup" in instruction_lower and ticket_id:
        tool_name = "lookup_ticket"
        tool_result = mcp_tools.lookup_ticket(ticket_id)

    record = _append_log({
        "channel": "orchestrator-to-agent-b",
        "claimed_sender": sender,
        "sender_verified": False,  # always False today -- Project 4 adds real verification
        "instruction": instruction,
        "tool_call": tool_name,
        "tool_result": tool_result,
    })
    return {
        "claimed_sender": sender,
        "sender_verified": False,
        "tool_call": tool_name,
        "tool_result": tool_result,
        "logged_at": record["ts"],
    }