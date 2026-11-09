"""Run the Project 3 attack payloads through the NeMo input guardrail (no model call needed).
  python guard_demo.py"""
import nemoguardrails

import guardrails
import payloads as P

rails = guardrails.build_rails()
rows = []
for i, d in enumerate(P.INJECTION_DOCS, 1):
    rows.append(("F1 indirect injection", f"payload {i}", d))
for name, p in P.EXTRACT + P.ELEVATION:
    rows.append(("F3 extraction/elevation", name, p))
for name, sender, text in P.SPOOF:
    rows.append(("F2 agent spoofing", name, text))
for name, chunk, _ in P.RAG_CHUNKS:
    rows.append(("F4 RAG poisoning", name, chunk))
for name, chunk in P.MCP_CHUNKS:
    rows.append(("F5 MCP abuse", name, chunk))

print(f"Guardrail engine: NeMo Guardrails {nemoguardrails.__version__}   rail: input 'check input'\n")
print(f"{'Attack':<25}{'Payload':<42}{'Status':<9}Reason")
blocked = 0
passed = []
for attack, name, text in rows:
    is_blocked, rail, reason = guardrails.run_input_rail(rails, text)
    blocked += is_blocked
    if not is_blocked:
        passed.append(f"{attack.split()[0]} {name}")
    print(f"{attack:<25}{name[:40]:<42}{'BLOCKED' if is_blocked else 'PASS':<9}{('rule: ' + reason) if is_blocked else 'no rule matched'}")
print(f"\nBlocked {blocked} of {len(rows)} payloads at the input rail.")
if passed:
    print("Not caught by text rules (they look like normal text), so other controls must stop them:")
    for p in passed:
        print("  -", p)
