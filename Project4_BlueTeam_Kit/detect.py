"""Anomaly detection for the AI platform: 3 alerts, each with timestamp, identity and event type.
  1) LLM_API_VOLUME_SPIKE   more than 20 requests in 60 seconds from one identity
  2) SCOPE_CHANGE           an identity's scope differs from its previous request
  3) EXPIRED_TOKEN_REUSE    a request arrives with a token that has already expired
Run:  python detect.py replay      (replays the Project 3 attacks through the detector)"""
import collections
import datetime
import json
import sys
import time

LOG_FILE = "alerts.log"


def iso(t):
    return datetime.datetime.fromtimestamp(t).isoformat(sep=" ", timespec="seconds")


class Monitor:
    def __init__(self, quiet=False, limit=20, window=60):
        self.quiet, self.limit, self.window = quiet, limit, window
        self.times = collections.defaultdict(collections.deque)   # recent request times per identity
        self.last_scope = {}                                      # previous scope per identity
        self.alerts = []

    def alert(self, now, identity, event, detail):
        a = {"timestamp": iso(now), "identity": identity, "event_type": event, "detail": detail}
        self.alerts.append(a)
        open(LOG_FILE, "a", encoding="utf-8").write(json.dumps(a) + "\n")
        if not self.quiet:
            print(f"ALERT  time={a['timestamp']}  identity={identity}  event={event}  ({detail})")

    def record(self, identity, scope, token_exp=None, now=None):
        """Call this for every request the platform receives."""
        now = time.time() if now is None else now

        q = self.times[identity]                                  # 1) volume spike
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) == self.limit + 1:
            self.alert(now, identity, "LLM_API_VOLUME_SPIKE", f"{len(q)} requests in {self.window}s, limit is {self.limit}")

        prev = self.last_scope.get(identity)                      # 2) scope change
        if prev is not None and prev != scope:
            self.alert(now, identity, "SCOPE_CHANGE", f"scope '{prev}' -> '{scope}' between consecutive requests")
        self.last_scope[identity] = scope

        if token_exp is not None and token_exp < now:             # 3) expired token reuse
            self.alert(now, identity, "EXPIRED_TOKEN_REUSE", f"token expired {int(now - token_exp)}s ago but was used again")


def replay():
    m = Monitor()
    t0 = time.time() - 30
    print("Replaying Project 3 attacks through the detector...\n")

    print("Attack run 1: automated payload flood (F1 injection + F3 extraction), 25 requests in 10 seconds")
    for i in range(25):
        m.record("agent-support-01", "read:ai-data", now=t0 + i * 0.4)

    print("\nAttack run 2: poisoned RAG chunk makes the agent ask for more power (F5 MCP abuse)")
    m.record("agent-support-02", "read:ai-data", now=t0 + 12)
    m.record("agent-support-02", "write:admin", now=t0 + 13)

    print("\nAttack run 3: attacker replays the leaked JWT after it expired (F1 credential theft)")
    m.record("agent-support-03", "read:ai-data", token_exp=t0 + 5, now=t0 + 20)

    print(f"\n{len(m.alerts)} alerts fired and saved in {LOG_FILE}:")
    print(f"{'Timestamp':<21}{'Identity':<20}{'Event type'}")
    for a in m.alerts:
        print(f"{a['timestamp']:<21}{a['identity']:<20}{a['event_type']}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "replay":
        replay()
    else:
        print("Use: python detect.py replay")
