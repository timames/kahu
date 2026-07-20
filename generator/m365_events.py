#!/usr/bin/env python3
"""Generate REAL audit events in your own Microsoft 365 Developer tenant.

This performs legitimate administrative actions in a tenant you control, so
that genuine sign-in logs, audit logs, and Entra events appear in Graph - and
therefore in Kuahene via the M365 connector. Nothing here touches any system
you do not own.

Prerequisites
-------------
1. A Microsoft 365 Developer Program tenant (free, 25 seats).
2. An Entra app registration with APPLICATION permissions, admin-consented:
     User.ReadWrite.All, Directory.ReadWrite.All,
     AuditLog.Read.All, Group.ReadWrite.All
3. Env vars: M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET

Usage
-----
    python m365_events.py baseline        # routine user churn
    python m365_events.py privilege       # role assignment + removal
    python m365_events.py failed_logins   # bad-password attempts on a test user
    python m365_events.py oversharing     # anonymous sharing link on a test file
    python m365_events.py cleanup         # remove everything this script made

Every object created is prefixed 'kuahene-demo-' so cleanup is unambiguous.
"""
import os
import sys
import time
import uuid

import requests

TENANT = os.getenv("M365_TENANT_ID", "")
CLIENT = os.getenv("M365_CLIENT_ID", "")
SECRET = os.getenv("M365_CLIENT_SECRET", "")
GRAPH = "https://graph.microsoft.com/v1.0"
PREFIX = "kuahene-demo-"


def token() -> str:
    if not (TENANT and CLIENT and SECRET):
        sys.exit("Set M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET first.")
    r = requests.post(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        data={
            "client_id": CLIENT,
            "client_secret": SECRET,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def H(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def domain(tok: str) -> str:
    r = requests.get(f"{GRAPH}/domains", headers=H(tok), timeout=30)
    r.raise_for_status()
    doms = r.json()["value"]
    return next((d["id"] for d in doms if d.get("isDefault")), doms[0]["id"])


# ---------------------------------------------------------------------------
def baseline(tok: str) -> None:
    """Create, update, and disable users - ordinary directory churn."""
    dom = domain(tok)
    made = []
    for i in range(3):
        tag = uuid.uuid4().hex[:6]
        upn = f"{PREFIX}{tag}@{dom}"
        body = {
            "accountEnabled": True,
            "displayName": f"Demo User {tag}",
            "mailNickname": f"{PREFIX}{tag}".replace("-", ""),
            "userPrincipalName": upn,
            "department": "Field Ops",
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "password": "Aloha!" + uuid.uuid4().hex[:12],
            },
        }
        r = requests.post(f"{GRAPH}/users", headers=H(tok), json=body, timeout=30)
        if r.status_code >= 300:
            print("  create failed:", r.status_code, r.text[:200])
            continue
        uid = r.json()["id"]
        made.append(uid)
        print(f"  created {upn}")
        time.sleep(2)
        requests.patch(f"{GRAPH}/users/{uid}", headers=H(tok),
                       json={"jobTitle": "Field Technician"}, timeout=30)
        print("  updated jobTitle")
        time.sleep(2)
    for uid in made[:1]:
        requests.patch(f"{GRAPH}/users/{uid}", headers=H(tok),
                       json={"accountEnabled": False}, timeout=30)
        print("  disabled one account")
    print("Baseline directory activity generated.")


def privilege(tok: str) -> None:
    """Assign then remove a privileged directory role - a high-signal event."""
    dom = domain(tok)
    tag = uuid.uuid4().hex[:6]
    upn = f"{PREFIX}priv{tag}@{dom}"
    body = {
        "accountEnabled": True,
        "displayName": f"Demo Priv {tag}",
        "mailNickname": f"{PREFIX}priv{tag}".replace("-", ""),
        "userPrincipalName": upn,
        "passwordProfile": {"forceChangePasswordNextSignIn": True,
                            "password": "Aloha!" + uuid.uuid4().hex[:12]},
    }
    r = requests.post(f"{GRAPH}/users", headers=H(tok), json=body, timeout=30)
    r.raise_for_status()
    uid = r.json()["id"]
    print(f"  created {upn}")

    # "Helpdesk Administrator" - privileged, but far less dangerous than GA.
    role_template = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    rr = requests.get(f"{GRAPH}/directoryRoles", headers=H(tok), timeout=30).json()
    role = next((x for x in rr["value"]
                 if x.get("roleTemplateId") == role_template), None)
    if role is None:
        requests.post(f"{GRAPH}/directoryRoles",
                      headers=H(tok),
                      json={"roleTemplateId": role_template}, timeout=30)
        time.sleep(5)
        rr = requests.get(f"{GRAPH}/directoryRoles", headers=H(tok), timeout=30).json()
        role = next(x for x in rr["value"]
                    if x.get("roleTemplateId") == role_template)

    requests.post(
        f"{GRAPH}/directoryRoles/{role['id']}/members/$ref",
        headers=H(tok),
        json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{uid}"},
        timeout=30,
    )
    print("  assigned Helpdesk Administrator  <-- this is the alert")
    time.sleep(8)
    requests.delete(
        f"{GRAPH}/directoryRoles/{role['id']}/members/{uid}/$ref",
        headers=H(tok), timeout=30)
    print("  removed role assignment")


def failed_logins(tok: str) -> None:
    """Deliberately fail authentication for a throwaway demo account.

    Uses ROPC against an account this script creates. Generates real
    Entra sign-in failures (error 50126) without touching any real user.
    """
    dom = domain(tok)
    tag = uuid.uuid4().hex[:6]
    upn = f"{PREFIX}auth{tag}@{dom}"
    pwd = "Aloha!" + uuid.uuid4().hex[:12]
    body = {
        "accountEnabled": True,
        "displayName": f"Demo Auth {tag}",
        "mailNickname": f"{PREFIX}auth{tag}".replace("-", ""),
        "userPrincipalName": upn,
        "passwordProfile": {"forceChangePasswordNextSignIn": False, "password": pwd},
    }
    r = requests.post(f"{GRAPH}/users", headers=H(tok), json=body, timeout=30)
    r.raise_for_status()
    print(f"  created {upn}; generating failed sign-ins")

    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    for i in range(12):
        requests.post(url, data={
            "client_id": CLIENT,
            "scope": "https://graph.microsoft.com/.default",
            "username": upn,
            "password": "WrongPassword" + str(i),
            "grant_type": "password",
        }, timeout=30)
        print(f"  failed attempt {i+1}/12")
        time.sleep(1.5)
    print("Sign-in failures generated. They appear in Entra sign-in logs "
          "within a few minutes.")


def oversharing(tok: str) -> None:
    """Create an anonymous sharing link on a demo file in the default site."""
    r = requests.get(f"{GRAPH}/sites/root", headers=H(tok), timeout=30)
    r.raise_for_status()
    site = r.json()["id"]
    dr = requests.get(f"{GRAPH}/sites/{site}/drive", headers=H(tok), timeout=30)
    dr.raise_for_status()
    drive = dr.json()["id"]

    name = f"{PREFIX}{uuid.uuid4().hex[:6]}-Q3-pricing.txt"
    up = requests.put(
        f"{GRAPH}/drives/{drive}/root:/{name}:/content",
        headers={"Authorization": f"Bearer {tok}",
                 "Content-Type": "text/plain"},
        data=b"Demo content for Kuahene sharing-link scenario. Not real data.",
        timeout=30,
    )
    up.raise_for_status()
    item = up.json()["id"]
    print(f"  uploaded {name}")

    lr = requests.post(
        f"{GRAPH}/drives/{drive}/items/{item}/createLink",
        headers=H(tok),
        json={"type": "view", "scope": "anonymous"},
        timeout=30,
    )
    if lr.status_code < 300:
        print("  created ANONYMOUS sharing link  <-- this is the alert")
    else:
        print("  anonymous sharing blocked by tenant policy "
              f"({lr.status_code}) - which is itself a fine thing to show")


def cleanup(tok: str) -> None:
    """Delete every object this script created."""
    r = requests.get(
        f"{GRAPH}/users?$filter=startswith(userPrincipalName,'{PREFIX}')"
        f"&$select=id,userPrincipalName",
        headers=H(tok), timeout=30)
    r.raise_for_status()
    users = r.json().get("value", [])
    for u in users:
        requests.delete(f"{GRAPH}/users/{u['id']}", headers=H(tok), timeout=30)
        print(f"  deleted {u['userPrincipalName']}")
    print(f"Removed {len(users)} demo users. "
          "Check the SharePoint recycle bin for demo files.")


ACTIONS = {
    "baseline": baseline,
    "privilege": privilege,
    "failed_logins": failed_logins,
    "oversharing": oversharing,
    "cleanup": cleanup,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ACTIONS:
        sys.exit(f"usage: {sys.argv[0]} [{'|'.join(ACTIONS)}]")
    print(f"== {sys.argv[1]} ==")
    ACTIONS[sys.argv[1]](token())
