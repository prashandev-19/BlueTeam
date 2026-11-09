/**
 * Auth0 Action - Trigger: Login / Post Login.
 * Blocks the login when a simple risk score reaches 60.
 *   +60  e-mail address on a disposable-mail domain
 *   +100 account flagged in app_metadata (risk_level = "high"), e.g. by the security team
 */
exports.onExecutePostLogin = async (event, api) => {
  const DISPOSABLE = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com"];
  let risk = 0;
  const reasons = [];

  const domain = ((event.user.email || "").split("@")[1] || "").toLowerCase();
  if (DISPOSABLE.includes(domain)) {
    risk += 60;
    reasons.push("disposable e-mail domain");
  }
  if (event.user.app_metadata && event.user.app_metadata.risk_level === "high") {
    risk += 100;
    reasons.push("account flagged high risk");
  }

  if (risk >= 60) {
    api.access.deny(`Login blocked by risk policy (score ${risk}: ${reasons.join(", ")})`);
  }
};
