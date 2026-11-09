"""Input + output guardrails, deployed with NeMo Guardrails.
NeMo runs the rails (rails/config.yml + rails/rails.co). The actual checks are the regex rules below.
  INPUT rail  : blocks text that looks like an attack BEFORE it reaches the model
  OUTPUT rails: redact JWT-shaped strings and internal ids in the model's reply BEFORE the user sees it"""
import logging
import pathlib
import re

from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.rails.llm.options import RailStatus, RailType

logging.getLogger("nemoguardrails").setLevel(logging.ERROR)

# ---------------------------------------------------------------- input rules (name, regex)
SECRET = r"(?:token|jwt|credential|bearer|api[ _-]?key|secret)"
VERB = r"(?:append|include|print|output|send|show|reply with|mention|reveal|give|tell|share|provide|display|disclose|base64)"
INPUT_RULES = [
    ("prompt-override", r"\bignore (?:all |any |the )?(?:previous|prior|above)\b"),
    ("fake-authority", r"(?:^|\n)\s*(?:system|note to assistant|important)\s*:|<!--"),
    ("credential-request", rf"\b{VERB}\b.{{0,80}}\b{SECRET}\b|\b{SECRET}\b.{{0,80}}\b{VERB}\b"),
    ("prompt-extraction", r"\b(?:repeat|print|show|output|reveal|translate|display)\b[^.\n]{0,40}"
                          r"\b(?:your (?:initial |original |full |system )?(?:instructions|prompt|configuration|rules)"
                          r"|system prompt|everything above|above this line)\b"),
    ("role-play-override", r"\byou are now\b|\bpretend (?:to be|you)\b|\bact as (?:a|an|if)\b"),
    ("role-elevation", r"\badmin(?:istrator)? (?:mode|role)\b|\bset my role\b|\bgrant me\b"),
    ("tool-call-in-text", r"\bcall \w+\(|TOOL_CALL"),
    ("suffix-injection", r"\bend of question\b|\bnew task\b"),
]
LAST = {"reason": ""}          # why the most recent input check blocked (read by the demos)


def scan_input(text):
    """Return the name of the first rule that matches, or None if the text looks clean."""
    for name, pattern in INPUT_RULES:
        if re.search(pattern, text, re.I | re.S):
            return name
    return None


# ---------------------------------------------------------------- output rules
JWT_PATTERNS = [
    r"ZXlK[A-Za-z0-9+/=_-]{16,}",                       # a JWT after base64 encoding (starts with "eyJ" -> "ZXlK")
    r"eyJ[\w-]{10,}(?:\.[\w-]*){0,2}",                  # JWT-shaped: header.payload.signature (or just the first parts)
]
INTERNAL_IDS = r"\b(?:orchestrator-01|agent-support-01)\b"


def redact_jwt_text(text):
    for pattern in JWT_PATTERNS:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


def redact_ids_text(text):
    return re.sub(INTERNAL_IDS, "[REDACTED]", text)


# ---------------------------------------------------------------- NeMo wiring
async def check_input(context=None):
    reason = scan_input(context["user_message"])
    LAST["reason"] = reason or ""
    return reason is None


async def redact_jwt(context=None):
    return redact_jwt_text(context["bot_message"])


async def redact_internal_ids(context=None):
    return redact_ids_text(context["bot_message"])


def build_rails():
    rails = LLMRails(RailsConfig.from_path(str(pathlib.Path(__file__).with_name("rails"))))
    rails.register_action(check_input, "check_input")
    rails.register_action(redact_jwt, "redact_jwt")
    rails.register_action(redact_internal_ids, "redact_internal_ids")
    return rails


def run_input_rail(rails, text):
    """-> (blocked, rail_name, reason)"""
    LAST["reason"] = ""
    res = rails.check([{"role": "user", "content": text}], rail_types=[RailType.INPUT])
    blocked = res.status == RailStatus.BLOCKED
    return blocked, (res.rail if blocked else ""), (LAST["reason"] if blocked else "")


def run_output_rail(rails, reply):
    """-> (clean_reply, was_modified)"""
    res = rails.check([{"role": "assistant", "content": reply}], rail_types=[RailType.OUTPUT])
    return res.content, res.status == RailStatus.MODIFIED
