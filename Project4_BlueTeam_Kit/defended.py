"""The HARDENED SecureNova platform = the Project 3 target + the Project 4 controls.
  Input rail + output rails (NeMo Guardrails)   -> guarded_answer()
  Ed25519 signed messages (zero trust)          -> agent_b_defended(), SignedKnowledgeBase.add()
  MCP argument policy                           -> mcp_call_hardened()
  Monitoring                                    -> monitor.record() on every model call"""
import re

import crypto_identity as ci
import detect
import guardrails
import target

IDENTITY, SCOPE = "agent-support-01", "read:ai-data"
INPUT_ON = True            # run_defended.py --output-rail-only switches the input rail off to test the output rail alone
if not (ci.KEYS / "orchestrator-01_private.pem").exists():
    ci.generate("orchestrator-01")      # same as running gen_keys.py
rails = guardrails.build_rails()
monitor = detect.Monitor(quiet=True)


def guarded_answer(user_msg, docs=()):
    """Returns (reply, status, detail). The model only sees input that passed the input rail."""
    text = user_msg if not docs else "Documents:\n" + "\n---\n".join(docs) + "\n\nCustomer question: " + user_msg
    blocked, rail, reason = guardrails.run_input_rail(rails, text) if INPUT_ON else (False, "", "")
    if blocked:
        return f"[BLOCKED] input rail '{rail}', rule: {reason}", "BLOCKED", f"input rail, rule: {reason}"
    monitor.record(IDENTITY, SCOPE)
    reply = target.agent_answer(user_msg, docs)
    clean, modified = guardrails.run_output_rail(rails, reply)
    if modified:
        return clean, "REDACTED", "output rail replaced credential / internal id with [REDACTED]"
    return clean, "PASSED", "input and output rails found nothing"


class SignedKnowledgeBase(target.KnowledgeBase):
    """RAG store that only accepts chunks signed by the trusted publisher (orchestrator-01)."""

    def __init__(self):
        super().__init__()
        self.rejected = 0

    def add(self, text, signature=None):
        if not ci.verify_message("orchestrator-01", text, signature):
            self.rejected += 1
            return False
        self.chunks.append(text)
        return True


def mcp_call_hardened(tool, args):
    """MCP server that checks the tool name AND the arguments."""
    if tool not in target.AGENT_TOOLS:
        return f"DENIED: {tool} is not allowed for this agent"
    if tool == "issue_refund":
        amount = re.search(r"amount\s*=\s*(\d+)", args)
        to = re.search(r"to\s*=\s*([^\s,)]+)", args)
        if not amount or int(amount.group(1)) > 50:
            return "DENIED: refund amount is missing or above the 50 limit"
        if not to or not to.group(1).endswith("@example.com"):
            return "DENIED: recipient is not the customer's registered address"
    return f"EXECUTED: {tool}({args})"


def rag_agent_defended(kb, user_msg):
    docs = kb.retrieve(user_msg)
    reply, status, detail = guarded_answer(user_msg, docs)
    m = re.search(r"TOOL_CALL\s+(\w+)\((.*?)\)", reply)
    return reply, (mcp_call_hardened(m.group(1), m.group(2)) if m else None), status, detail


def agent_b_defended(message):
    """message = {"from", "text", "sig"}. Verify the Ed25519 signature BEFORE the model sees anything."""
    sender, text = message["from"], message["text"]
    if not ci.verify_message(sender, text, message.get("sig")):
        return f"REJECTED: invalid or missing signature for sender '{sender}'", "REJECTED", "Ed25519 signature check failed"
    return target.agent_b(sender, text), "VERIFIED", "signature valid, message processed"
