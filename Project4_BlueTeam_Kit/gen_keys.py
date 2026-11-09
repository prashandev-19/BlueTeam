"""Generate the Ed25519 key pair for the orchestrator agent.   python gen_keys.py"""
import crypto_identity as ci

AGENT = "orchestrator-01"
private_file, public_file = ci.generate(AGENT)
print(f"Generated Ed25519 key pair for {AGENT} using the Python 'cryptography' library:")
for f in (private_file, public_file):
    print(f"  created  {f.relative_to(f.parent.parent)}   ({f.stat().st_size} bytes)")
print(f"Public key fingerprint (SHA-256, first 16 hex): {ci.fingerprint(AGENT)}")
print("The PRIVATE key stays with the orchestrator only. The PUBLIC key is shared with every agent that must verify it.")
