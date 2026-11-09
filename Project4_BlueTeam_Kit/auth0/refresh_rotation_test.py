"""Refresh token rotation: the old refresh token must stop working after it is used once.
Put this file in your Project 2 folder (it uses config.py and tokens.json from there).
Steps: log in again with pkce_login.py (after adding offline_access to its scope) so tokens.json has a refresh_token."""
import datetime
import json

import requests

import config


def say(msg):
    print(f"[{datetime.datetime.now().isoformat(sep=' ', timespec='seconds')}] {msg}", flush=True)


def refresh(refresh_token):
    return requests.post(f"https://{config.DOMAIN}/oauth/token", data={
        "grant_type": "refresh_token", "client_id": config.WEB_CLIENT_ID,
        "client_secret": config.WEB_CLIENT_SECRET, "refresh_token": refresh_token}).json()


tokens = json.load(open("tokens.json"))
old_rt = tokens.get("refresh_token")
if not old_rt:
    raise SystemExit("No refresh_token in tokens.json. Add offline_access to the scope in pkce_login.py and log in again.")
say(f"Access token lifetime from the last login: expires_in = {tokens.get('expires_in')} seconds (should be 300)")

say("1) Use the refresh token ONCE -> Auth0 should give a new access token AND a new refresh token")
new = refresh(old_rt)
if "access_token" not in new:
    raise SystemExit(f"Refresh failed: {new}")
say(f"   OK. New access token issued, expires_in = {new['expires_in']} seconds")
say(f"   Refresh token rotated: {'YES, a new one was issued' if new.get('refresh_token') and new['refresh_token'] != old_rt else 'NO (rotation is not enabled)'}")
tokens.update(new)
json.dump(tokens, open("tokens.json", "w"), indent=2)

say("2) Replay the OLD refresh token -> must be rejected")
replay = refresh(old_rt)
if "access_token" in replay:
    say("   PROBLEM: the old refresh token still works. Turn on Refresh Token Rotation in the application settings.")
else:
    say(f"   REJECTED: error = {replay.get('error')}, description = {replay.get('error_description')}")
    say("   (Auth0 also treats this as a stolen-token signal and revokes the new refresh token too.)")
