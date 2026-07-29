"""Control-tag mapping — translates Wazuh rule groups to compliance control IDs.

When a Wazuh alert arrives, its ``rule.groups`` list is mapped to framework
control tags so the triage pipeline can stamp ``control_tags`` on each alert
and evidence record automatically.
"""

from __future__ import annotations

# Wazuh rule-group → compliance control tags.
# A single group can satisfy multiple controls across frameworks.
WAZUH_GROUP_CONTROLS: dict[str, list[str]] = {
    # Authentication / access
    "authentication_success": [
        "800-171:3.1.1", "800-171:3.5.1", "800-171:3.5.2",
        "HIPAA:164.312(d)", "CIS:6.1", "SOC2:CC6.1", "SOC2:CC6.2",
    ],
    "authentication_failed": [
        "800-171:3.1.1", "800-171:3.5.2",
        "HIPAA:164.312(d)", "CIS:6.1", "SOC2:CC6.1",
    ],
    "authentication_failures": [
        "800-171:3.1.1", "800-171:3.5.2",
        "HIPAA:164.312(d)", "CIS:6.1", "SOC2:CC6.1",
    ],
    "invalid_login": [
        "800-171:3.1.1", "800-171:3.14.7",
        "SOC2:CC6.1", "SOC2:CC7.2",
    ],
    "login_denied": [
        "800-171:3.1.1", "800-171:3.1.7",
        "SOC2:CC6.1",
    ],
    "adduser": [
        "800-171:3.1.1", "800-171:3.1.2",
        "HIPAA:164.312(a)(2)(i)", "SOC2:CC6.2",
    ],
    "account_changed": [
        "800-171:3.1.2", "SOC2:CC6.2", "SOC2:CC8.1",
    ],
    # Privilege escalation
    "priv_esc": [
        "800-171:3.1.5", "800-171:3.1.7",
        "CIS:6.1", "SOC2:CC6.3",
    ],
    "sudo": [
        "800-171:3.1.5", "800-171:3.1.7",
        "SOC2:CC6.3",
    ],
    # Audit / logging
    "audit": [
        "800-171:3.3.1", "800-171:3.3.2",
        "HIPAA:164.312(b)", "CIS:8.1", "CIS:8.2",
        "SOC2:CC2.1", "SOC2:CC7.1",
    ],
    "syslog": [
        "800-171:3.3.1",
        "CIS:8.2", "SOC2:CC2.1",
    ],
    "audit_command": [
        "800-171:3.3.1", "800-171:3.3.2",
        "CIS:8.5", "SOC2:CC7.1",
    ],
    "audit_watch": [
        "800-171:3.3.1", "800-171:3.4.1",
        "CIS:8.5",
    ],
    # Integrity / configuration
    "syscheck": [
        "800-171:3.4.1", "800-171:3.14.1",
        "HIPAA:164.312(c)(1)", "CIS:4.1",
        "SOC2:CC5.1", "SOC2:CC8.1",
    ],
    "config_changed": [
        "800-171:3.4.2",
        "CIS:4.1", "SOC2:CC8.1",
    ],
    "rootcheck": [
        "800-171:3.4.2", "800-171:3.14.2",
        "CIS:4.1", "CIS:10.1",
    ],
    # Malware / endpoint
    "virus": [
        "800-171:3.14.2",
        "CIS:10.1", "SOC2:CC6.8",
    ],
    "trojan": [
        "800-171:3.14.2",
        "CIS:10.1", "SOC2:CC6.8",
    ],
    "rootkit": [
        "800-171:3.14.2",
        "CIS:10.1", "SOC2:CC6.8",
    ],
    # Network
    "firewall": [
        "800-171:3.13.1", "800-171:3.13.5",
        "CIS:13.1", "CIS:13.6", "SOC2:CC6.6",
    ],
    "ids": [
        "800-171:3.13.1", "800-171:3.14.6",
        "CIS:13.1", "SOC2:CC7.1", "SOC2:CC7.2",
    ],
    "network": [
        "800-171:3.13.1",
        "CIS:13.6", "SOC2:CC6.6",
    ],
    # Vulnerability / patching
    "vulnerability-detector": [
        "800-171:3.11.2", "800-171:3.14.1",
        "CIS:4.1", "SOC2:CC3.2", "SOC2:CC9.1",
    ],
    # Incident response (Wazuh active response)
    "active_response": [
        "800-171:3.6.1",
        "CIS:17.4", "SOC2:CC7.4", "SOC2:CC7.5",
    ],
    # Web attacks
    "web": [
        "800-171:3.14.6", "800-171:3.14.7",
        "SOC2:CC7.1", "SOC2:CC7.2",
    ],
    "attack": [
        "800-171:3.14.6", "800-171:3.14.7",
        "CIS:13.1", "SOC2:CC7.2",
    ],
    # Encryption / TLS
    "tls": [
        "800-171:3.13.11",
        "HIPAA:164.312(e)(2)(ii)", "SOC2:CC6.7",
    ],
    "ssl": [
        "800-171:3.13.11",
        "HIPAA:164.312(e)(1)", "SOC2:CC6.7",
    ],
}


def tags_for_alert(raw_alert: dict) -> list[str]:
    """Derive compliance control tags from a Wazuh alert's rule groups.

    Returns a deduplicated, sorted list of control tag strings.
    """
    groups: list[str] = raw_alert.get("rule", {}).get("groups", [])
    tags: set[str] = set()
    for group in groups:
        group_lower = group.lower()
        if group_lower in WAZUH_GROUP_CONTROLS:
            tags.update(WAZUH_GROUP_CONTROLS[group_lower])
    return sorted(tags)
