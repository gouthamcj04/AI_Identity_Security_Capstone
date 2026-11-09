"""Builds the Project 4 before/after comparison table (item 8, and Project 5 item 8).

Fill ROWS with your real Project 3 (before) and Project 4 (after, through the
guardrail) results, then run: python build_before_after_matrix.py
"""
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

# before_success / after_success: True if the attack still worked, False if blocked/failed.
# control_applied: which Project 4 control is credited for the change.
ROWS = [
    {"attack": "1. Indirect Prompt Injection", "before_success": True, "after_success": False,
     "control_applied": "Input guardrail (override-pattern detection) + output JWT/credential redaction"},
    {"attack": "2. Agent Identity Spoofing", "before_success": True, "after_success": False,
     "control_applied": "Ed25519 signed inter-agent messages, verified before any tool runs"},
    {"attack": "3. System Prompt Extraction", "before_success": True, "after_success": False,
     "control_applied": "Output guardrail redacts credential-shaped strings before they reach the caller"},
    {"attack": "3b. Role Elevation", "before_success": True, "after_success": False,
     "control_applied": "Input guardrail blocks override/authority-claim patterns"},
    {"attack": "4. RAG Poisoning -> MCP Abuse", "before_success": True, "after_success": False,
     "control_applied": "Input guardrail blocks tool-directive patterns in retrieved content"},
]


def main():
    wb = Workbook()
    ws = wb.active
    ws.title = "Before vs After"
    ws.append(["Attack", "Before (Project 3)", "After (Project 4)", "Outcome", "Control applied"])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3864")

    before_successes = after_successes = 0
    for r in ROWS:
        before = "Succeeded" if r["before_success"] else "Blocked/Failed"
        after = "Succeeded" if r["after_success"] else "Blocked/Failed"
        outcome = "IMPROVED" if r["before_success"] and not r["after_success"] else (
            "NO CHANGE" if r["before_success"] == r["after_success"] else "REGRESSED")
        ws.append([r["attack"], before, after, outcome, r["control_applied"]])
        before_successes += r["before_success"]
        after_successes += r["after_success"]

    n = len(ROWS)
    before_rate = before_successes / n * 100
    after_rate = after_successes / n * 100
    reduction = before_rate - after_rate
    ws.append([])
    ws.append(["Overall success rate", f"{before_rate:.0f}%", f"{after_rate:.0f}%",
               f"{reduction:.0f} point reduction", ""])
    for c in ws[n + 3]:
        c.font = Font(bold=True)

    widths = [34, 18, 18, 14, 56]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")

    out = Path(__file__).parent / "before-after-comparison.xlsx"
    wb.save(out)
    print(f"Wrote {out}")
    print(f"Before: {before_rate:.0f}% success, After: {after_rate:.0f}% success, "
          f"reduction: {reduction:.0f} points")


if __name__ == "__main__":
    main()