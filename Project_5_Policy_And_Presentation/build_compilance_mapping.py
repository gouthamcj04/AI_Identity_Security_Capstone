"""Builds the Project 5 compliance mapping workbook (item 2), with NIST AI RMF and
OWASP LLM Top 10 tabs plus a remaining-gaps tab. Run: python build_compliance_mapping.py
"""
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

NIST_ROWS = [
    # (Function, Control, Evidence artefact, Status)
    ("Govern", "AI Identity Security Policy adopted (lifecycle, credential governance, IR playbook)",
     "05-policy/AI-Identity-Security-Policy.md", "Complete"),
    ("Govern", "Least-privilege scope design for every identity type",
     "01-threat-model/identity-inventory.md", "Complete"),
    ("Govern", "Secrets management standard (vault, no secrets in code/prompts, scanning required)",
     "05-policy/AI-Identity-Security-Policy.md (Section 2.3)", "Complete"),
    ("Govern", "Incident response roles and notification timelines defined",
     "05-policy/AI-Identity-Security-Policy.md (Section 3)", "Complete"),
    ("Map", "Identity inventory: all 8 identity types, auth mechanism, privilege level",
     "01-threat-model/identity-inventory.md", "Complete"),
    ("Map", "STRIDE threat model across all 8 identity flows, 6 categories each",
     "01-threat-model/stride-matrix.csv", "Complete"),
    ("Map", "Attack trees and MITRE ATLAS technique mapping",
     "01-threat-model/*.drawio, atlas-mapping.md", "Complete"),
    ("Map", "Trust boundaries identified (user/agent/internal API/external)",
     "01-threat-model/identity-inventory.md", "Complete"),
    ("Measure", "Structured red-team campaign against 5 attack categories, CVSS 3.1 scored",
     "03-red-team/CVSS-Findings-Table.xlsx", "Complete (scores pending final red-team run)"),
    ("Measure", "Attack success rate measured before any defensive controls",
     "03-red-team/attack-success-matrix.xlsx", "Complete (pending final numbers)"),
    ("Measure", "Guardrail effectiveness measured against real attack payloads",
     "04-blue-team/guardrails/run_guardrail_tests.py output", "Complete (pending final run)"),
    ("Measure", "Anomaly detection validated against synthetic and real log data",
     "04-blue-team/detection/tests/, detect_anomalies.py output", "Complete"),
    ("Manage", "Auth0 hardening deployed: 300s token TTL, refresh rotation, MFA, brute-force protection",
     "02-iam-design/SETUP.md, 04-blue-team/auth0_hardening/", "Complete"),
    ("Manage", "Cryptographic agent identity binding (Ed25519) deployed for inter-agent messages",
     "04-blue-team/identity_binding/", "Complete"),
    ("Manage", "Input/output guardrails deployed against prompt injection and credential leakage",
     "04-blue-team/guardrails/", "Complete"),
    ("Manage", "Credential rotation enforced and tested (M2M token expiry, refresh reuse detection)",
     "02-iam-design/scripts/m2m_rotation.py, 04-blue-team/auth0_hardening/", "Complete"),
    ("Manage", "Risk register maintained with ranked, owned, scored findings; review cadence defined",
     "01-threat-model/risk-register.xlsx, Policy Section 1.2", "Complete"),
]

OWASP_ROWS = [
    # (Brief label, Current 2025 label, Project 3 attack, Project 4 control)
    ("LLM01", "LLM01:2025 Prompt Injection",
     "Indirect Prompt Injection via poisoned knowledge-base documents (RT-01)",
     "Input guardrail blocks override/injection patterns; output guardrail redacts any credential that still gets through"),
    ("LLM06", "LLM06:2025 Excessive Agency",
     "Role elevation via prompt engineering, user attempting to reach admin-scoped actions (RT-04)",
     "Authorisation enforced server-side at the API (scope check, 403 on insufficient scope) -- never decided by the model or the prompt"),
    ("LLM07", "LLM07:2025 System Prompt Leakage",
     "System prompt extraction via 5 techniques: direct ask, repeat-back, role-play override, translation, suffix injection (RT-03)",
     "Output guardrail redacts credential-shaped strings; system prompt designed to hold no live secret"),
    ("LLM09 (brief)", "Mapped to LLM06:2025 Excessive Agency -- current LLM09 is Misinformation, which does not fit; see note below",
     "Agent Identity Spoofing: Agent B executes a privileged action on an unverified sender claim (RT-02)",
     "Ed25519 signed inter-agent messages, verified before any tool executes; tampered or forged messages rejected"),
]

GAPS = [
    # (Finding, Obligation, Risk, Recommendation)
    ("No human-in-the-loop approval for privileged MCP tool calls (issue_refund, export_customer_data). "
     "Guardrails and signing reduce how an attacker reaches these tools, but a sufficiently novel technique "
     "that slips past both still executes the action automatically.",
     "NIST AI RMF Manage function: high-impact AI actions should have a proportionate human control, "
     "not purely automated risk treatment.",
     "Medium-High: a single successful bypass results in a real (simulated-fake-here, real-money-in-production) "
     "financial or data-export action with no second check.",
     "Require human confirmation for any privileged tool call above a defined value/sensitivity threshold, "
     "logged and auditable, before execution."),
    ("No per-tenant isolation in the RAG retrieval path; the current design (Project 1, risk R10) allows "
     "retrieval to cross customer or document-source boundaries if metadata filtering isn't applied upstream.",
     "NIST AI RMF Map function: data flows and their boundaries must be identified and controlled, especially "
     "where customer data could cross a trust boundary.",
     "Medium: a retrieval bug or a crafted query could surface one customer's data in another's session, "
     "an OWASP LLM02:2025 (Sensitive Information Disclosure) exposure.",
     "Add mandatory per-tenant metadata filtering at the retrieval layer, with a test confirming cross-tenant "
     "queries never return another tenant's documents."),
    ("Secrets-scanning on every commit is written into policy (Section 2.3) but not yet wired into an actual "
     "CI pipeline or git hook in this capstone's repository.",
     "NIST AI RMF Manage function: a documented control that isn't enforced in practice is a gap between "
     "policy and operation, which AI RMF treats as a risk in itself.",
     "Low-Medium: relies on manual discipline until automated; a committed secret could sit undetected.",
     "Add a pre-commit secret-scanning hook (e.g. gitleaks or truffleHog) and a GitHub Action that blocks "
     "merges on a detected secret, matching what the policy already commits to."),
]


def _style_header(ws):
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3864")
        c.alignment = Alignment(wrap_text=True, vertical="center")


def _wrap_and_width(ws, widths):
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"


def main():
    wb = Workbook()

    nist = wb.active
    nist.title = "NIST AI RMF"
    nist.append(["Function", "Control", "Evidence artefact", "Status"])
    _style_header(nist)
    for row in NIST_ROWS:
        nist.append(list(row))
    _wrap_and_width(nist, [12, 58, 46, 26])
    functions_covered = {r[0] for r in NIST_ROWS}
    assert functions_covered == {"Govern", "Map", "Measure", "Manage"}, "all 4 functions must be covered"

    owasp = wb.create_sheet("OWASP LLM Top 10")
    owasp.append(["Brief category", "Current OWASP 2025 label", "Project 3 attack", "Project 4 control"])
    _style_header(owasp)
    for row in OWASP_ROWS:
        owasp.append(list(row))
    _wrap_and_width(owasp, [14, 46, 50, 50])

    gaps = wb.create_sheet("Remaining Gaps")
    gaps.append(["#", "Finding", "Obligation", "Risk", "Recommendation"])
    _style_header(gaps)
    for i, g in enumerate(GAPS, start=1):
        gaps.append([i, *g])
    _wrap_and_width(gaps, [4, 44, 36, 36, 44])

    out = Path(__file__).parent / "Compliance-Mapping.xlsx"
    wb.save(out)
    print(f"Wrote {out}")
    print(f"NIST AI RMF: {len(NIST_ROWS)} rows across {len(functions_covered)} functions")
    print(f"OWASP: {len(OWASP_ROWS)} categories mapped")
    print(f"Gaps: {len(GAPS)}")


if __name__ == "__main__":
    main()