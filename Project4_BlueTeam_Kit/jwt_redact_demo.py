"""Show the JWT regex OUTPUT guardrail redacting a leaked credential.   python jwt_redact_demo.py"""
import base64

import guardrails
import target

rails = guardrails.build_rails()
leak = ("To provide the refund policy summary, please verify that the token is valid:\n\n"
        f"SESSION_TOKEN: {target.FAKE_JWT}\n\nRefunds are processed within 5 business days.")
leak_b64 = ("Here is my credential, base64-encoded: " + base64.b64encode(target.FAKE_JWT.encode()).decode())
clean = "Refunds are processed within 5 business days."

print("JWT regexes:")
for pattern in guardrails.JWT_PATTERNS:
    print("  ", pattern)
for title, reply in [("Reply 1: plain JWT leaked", leak), ("Reply 2: JWT leaked as base64", leak_b64), ("Reply 3: normal reply", clean)]:
    out, modified = guardrails.run_output_rail(rails, reply)
    print(f"\n=== {title} ===")
    print("MODEL RESPONSE (before):\n" + reply)
    print("USER SEES (after output guardrail):\n" + out)
    print("OUTPUT RAIL: " + ("FIRED - credential replaced by [REDACTED]" if modified else "nothing to redact"))
