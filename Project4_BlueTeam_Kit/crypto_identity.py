"""Ed25519 agent identity: every agent message is signed with the agent's PRIVATE key;
the receiver checks it with the agent's PUBLIC key before doing anything."""
import base64
import hashlib
import json
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEYS = pathlib.Path(__file__).with_name("keys")


def generate(agent_id):
    """Create keys/<agent_id>_private.pem and keys/<agent_id>_public.pem"""
    KEYS.mkdir(exist_ok=True)
    private = Ed25519PrivateKey.generate()
    (KEYS / f"{agent_id}_private.pem").write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (KEYS / f"{agent_id}_public.pem").write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return KEYS / f"{agent_id}_private.pem", KEYS / f"{agent_id}_public.pem"


def fingerprint(agent_id):
    raw = load_public(agent_id).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_private(agent_id):
    return serialization.load_pem_private_key((KEYS / f"{agent_id}_private.pem").read_bytes(), password=None)


def load_public(agent_id):
    return serialization.load_pem_public_key((KEYS / f"{agent_id}_public.pem").read_bytes())


def canonical(sender, text):
    """The exact bytes that get signed. Changing even one character changes them."""
    return json.dumps({"from": sender, "text": text}, sort_keys=True).encode()


def sign_message(sender, text, private_key=None):
    key = private_key or load_private(sender)
    return base64.b64encode(key.sign(canonical(sender, text))).decode()


def verify_message(sender, text, signature, public_key=None):
    """True only if `signature` was made by sender's private key over exactly this text."""
    try:
        key = public_key or load_public(sender)
        key.verify(base64.b64decode(signature or ""), canonical(sender, text))
        return True
    except (InvalidSignature, ValueError, FileNotFoundError, TypeError):
        return False
