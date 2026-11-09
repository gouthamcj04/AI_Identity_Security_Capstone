"""Input/output guardrails for the SecureNova lab agent (Project 4, item 1).

The brief names NeMo Guardrails or Rebuff as the library to deploy. Both pull in a
large dependency tree (NeMo Guardrails needs an LLM of its own to run its rails;
Rebuff needs a hosted API or a vector DB). Neither installs cleanly in this
offline-friendly lab, so this module is a small, from-scratch equivalent that meets
the same functional requirement: classify a payload as BLOCKED or PASSED with a
reason, and redact JWT-shaped strings from output. State this substitution plainly
in your report. If your environment allows it, installing the real library and
swapping it in here is a straightforward extension -- the functions below are the
seam (`check_input` / `redact_output`) to replace.

Detection here is pattern-based (regex and keyword heuristics), which is also how
real guardrail products work at their simplest layer -- it will have false negatives
against a creative attacker and occasional false positives against ordinary text.
That tradeoff is worth naming in your report, not hidden.
"""
import re

# Phrases commonly used to try to override a system prompt or claim false authority.
# Kept as patterns (not literal attack payloads) so the module works on *any* input,
# including payloads the person using this already wrote for Project 3.
_OVERRIDE_PATTERNS = [
    r"\bignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+instructions?\b",
    r"\bdisregard\s+(the\s+)?(previous|prior|above)\s+instructions?\b",
    r"\byou\s+are\s+now\s+(a|an)\b",
    r"\bnew\s+instructions?\s*:",
    r"\bsystem\s*:\s*override\b",
    r"\bact\s+as\s+(if\s+you\s+are\s+)?(a|an)\s+(admin|administrator|developer|root)\b",
    r"\breveal\s+(your\s+)?(system\s+prompt|instructions|internal\s+(reference|credential))\b",
    r"\bprint\s+(your\s+)?(system\s+prompt|configuration)\b",
    r"\brepeat\s+(the\s+)?(text|everything|instructions)\s+above\b",
    r"\btranslate\s+your\s+(system\s+prompt|instructions)\b",
    r"\byou\s+must\s+comply\b",
    r"\bthis\s+is\s+a\s+(trusted\s+)?orchestrator\s+instruction\b",
]
_OVERRIDE_RE = [re.compile(p, re.IGNORECASE) for p in _OVERRIDE_PATTERNS]

# A privileged-tool directive riding in through retrieved/third-party text is the
# RAG-poisoning -> MCP-abuse shape from Project 3 item 4.
_TOOL_DIRECTIVE_RE = re.compile(
    r"\b(you\s+(should|must|need\s+to)\s+call|please\s+call|invoke)\s+"
    r"(the\s+)?(issue_refund|export_customer_data|tool_call)\b", re.IGNORECASE)

# Long base64url-ish run: a crude but useful signal for an exfiltrated secret or an
# attempt to smuggle encoded instructions.
_LONG_ENCODED_RE = re.compile(r"[A-Za-z0-9+/_=-]{80,}")

MAX_INPUT_LENGTH = 4000


def check_input(text):
    """Return {"blocked": bool, "reasons": [str, ...]}. Never raises on untrusted input."""
    reasons = []
    if not isinstance(text, str):
        return {"blocked": True, "reasons": ["non-string input"]}
    if len(text) > MAX_INPUT_LENGTH:
        reasons.append(f"input exceeds {MAX_INPUT_LENGTH} characters ({len(text)})")
    for pattern in _OVERRIDE_RE:
        if pattern.search(text):
            reasons.append(f"matched override/injection pattern: {pattern.pattern[:60]}")
    if _TOOL_DIRECTIVE_RE.search(text):
        reasons.append("matched directive steering toward a privileged tool call")
    long_matches = _LONG_ENCODED_RE.findall(text)
    if long_matches:
        reasons.append(f"contains {len(long_matches)} long encoded-looking run(s)")
    return {"blocked": bool(reasons), "reasons": reasons}


# JWT shape: base64url.base64url.base64url, each segment non-empty. Deliberately
# generic so it catches the lab's fake tokens and real Auth0-issued JWTs alike.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
# Also catch the lab's plainly-labelled fake credential pattern, independent of JWTs.
_FAKE_CRED_RE = re.compile(r"\bFAKE-sk-[A-Za-z0-9]+\b")


def redact_output(text):
    """Return (redacted_text, count_redacted). Replaces JWT-shaped and fake-credential
    strings with [REDACTED] so they never reach the caller, whatever path put them there."""
    count = 0

    def _sub(match):
        nonlocal count
        count += 1
        return "[REDACTED]"

    text = _JWT_RE.sub(_sub, text)
    text = _FAKE_CRED_RE.sub(_sub, text)
    return text, count