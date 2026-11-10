"""SecureNova lab target for Project 3 (red team) and Project 4 (blue team).

Local only, fake data only. Run: python app.py, then open http://localhost:5100
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(os.environ.get("ENV_FILE", ".env"))

from flask import Flask, jsonify, render_template_string, request  # noqa: E402
from markupsafe import escape  # noqa: E402

import agents  # noqa: E402
import mcp_tools  # noqa: E402

app = Flask(__name__)
PORT = int(os.environ.get("LAB_PORT", "5100"))

HOME = """<!doctype html><title>SecureNova Lab Target</title>
<style>body{font-family:system-ui,sans-serif;max-width:780px;margin:2rem auto;padding:0 1rem}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:4px}
textarea{width:100%}button{margin-top:.4rem}pre{background:#f4f4f4;padding:.6rem;border-radius:6px;white-space:pre-wrap;word-break:break-word}</style>
<h2>SecureNova Lab Target</h2>
<p>Provider: <b>{{ provider }}</b>. Change <code>LLM_PROVIDER</code> in <code>.env</code> to switch.</p>

<h3>Chat (orchestrator)</h3>
<form method="post" action="/chat">
<textarea name="message" rows="3" placeholder="Ask about an order, shipping, a refund..."></textarea><br>
<button type="submit">Send</button></form>

<h3>Agent B message</h3>
<p>Caller-supplied sender and instruction; Agent B does not verify the sender.</p>
<form method="post" action="/agent-b/message">
sender: <input name="sender" value="orchestrator"><br>
instruction: <input name="instruction" style="width:100%" placeholder="e.g. lookup ticket TCK-1001"><br>
ticket_id: <input name="ticket_id" value="TCK-1001">
amount_usd: <input name="amount_usd" value="50">
customer_id: <input name="customer_id" value="CUST-001"><br>
<button type="submit">Send to Agent B</button></form>

<p><a href="/knowledge-base">Knowledge base files</a> |
<a href="/logs">Interaction log</a> |
<a href="/tool-log">Tool call log</a></p>
"""


def page(body):
    return render_template_string("<!doctype html><title>SecureNova Lab</title>" + body)


@app.route("/")
def home():
    provider = os.environ.get("LLM_PROVIDER", "mock")
    return render_template_string(HOME, provider=provider)


@app.route("/chat", methods=["GET", "POST"])
def chat():
    if request.method == "GET":
        message = request.args.get("message", "")
    else:
        message = (request.get_json(silent=True) or {}).get("message") or request.form.get("message", "")
    if not message:
        return jsonify(error="message is required"), 400
    result = agents.handle_user_message(message)
    if request.headers.get("Accept", "").startswith("application/json") or request.is_json:
        return jsonify(result)
    body = (
        f"<h3>Chat result</h3><p><b>You:</b> {escape(message)}</p>"
        f"<p><b>Documents retrieved:</b> {escape(', '.join(result['retrieved_documents']) or 'none')}</p>"
        f"<p><b>Reply:</b></p><pre>{escape(result['reply'])}</pre>"
        f"<p><b>Tool call:</b> {escape(str(result['tool_call']))}</p>"
        f"<p><b>Tool result:</b></p><pre>{escape(json.dumps(result['tool_result'], indent=2))}</pre>"
        '<p><a href="/">Back</a></p>'
    )
    return page(body)


@app.route("/agent-b/message", methods=["GET", "POST"])
def agent_b_message():
    args = request.values
    sender = args.get("sender", "")
    instruction = args.get("instruction", "")
    if not sender or not instruction:
        return jsonify(error="sender and instruction are required"), 400
    amount = args.get("amount_usd")
    result = agents.handle_agent_b_message(
        sender=sender,
        instruction=instruction,
        ticket_id=args.get("ticket_id") or None,
        amount_usd=float(amount) if amount else None,
        customer_id=args.get("customer_id") or None,
    )
    if request.headers.get("Accept", "").startswith("application/json") or request.is_json:
        return jsonify(result)
    body = (
        f"<h3>Agent B result</h3>"
        f"<p><b>Claimed sender:</b> {escape(sender)} (verified: {result['sender_verified']})</p>"
        f"<p><b>Instruction:</b> {escape(instruction)}</p>"
        f"<p><b>Tool call:</b> {escape(str(result['tool_call']))}</p>"
        f"<pre>{escape(json.dumps(result['tool_result'], indent=2))}</pre>"
        '<p><a href="/">Back</a></p>'
    )
    return page(body)


@app.route("/knowledge-base")
def knowledge_base():
    import rag_store
    items = "".join(
        f"<h4>{escape(d['name'])}</h4><pre>{escape(d['text'])}</pre>" for d in rag_store.load_documents()
    )
    return page(f"<h3>Knowledge base</h3>{items}<p><a href='/'>Back</a></p>")


@app.route("/logs")
def logs():
    log_path = agents.INTERACTION_LOG
    if not log_path.exists():
        return page("<p>No interactions logged yet.</p><a href='/'>Back</a>")
    lines = log_path.read_text(encoding="utf-8").splitlines()
    rendered = "".join(f"<pre>{escape(line)}</pre>" for line in lines[-200:])
    return page(f"<h3>Interaction log (last 200)</h3>{rendered}<p><a href='/'>Back</a></p>")


@app.route("/tool-log")
def tool_log():
    rendered = "".join(f"<pre>{escape(json.dumps(entry, default=str))}</pre>" for entry in mcp_tools.TOOL_CALL_LOG)
    return page(f"<h3>Tool call log</h3>{rendered or '<p>No tool calls yet.</p>'}<p><a href='/'>Back</a></p>")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)