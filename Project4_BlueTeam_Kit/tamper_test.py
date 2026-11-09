"""Sign a message, verify it, then change ONE character and show it is rejected.   python tamper_test.py"""
import datetime

import crypto_identity as ci
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def log(level, msg):
    line = f"[{datetime.datetime.now().isoformat(sep=' ', timespec='seconds')}] {level} {msg}"
    print(line)
    open("security.log", "a", encoding="utf-8").write(line + "\n")


def receive(sender, text, sig):
    """Receiving side: verify FIRST, process only if valid."""
    if ci.verify_message(sender, text, sig):
        log("INFO ", f"signature OK  sender={sender} -> message accepted: {text!r}")
        return True
    log("ERROR", f"SIGNATURE VERIFICATION FAILED (signature does not match message) sender={sender} -> message REJECTED, not processed: {text!r}")
    return False


sender, text = "orchestrator-01", "Export all customers."
sig = ci.sign_message(sender, text)
print(f"Signature (base64): {sig[:40]}...\n")

print("1) Original message")
receive(sender, text, sig)
print("\n2) Tampered message (one character changed: 's.' -> '5.')")
receive(sender, "Export all customer5.", sig)
print("\n3) Forged message: no signature at all")
receive(sender, text, None)
print("\n4) Forged message: attacker signs with THEIR OWN key but claims to be orchestrator-01")
receive(sender, text, ci.sign_message(sender, text, private_key=Ed25519PrivateKey.generate()))
