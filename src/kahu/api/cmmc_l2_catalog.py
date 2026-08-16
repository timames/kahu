"""CMMC Level 2 practice catalog — 110 practices across 14 domains.

Reference data for the compliance/GRC subsystem. CMMC Level 2 aligns 1:1 with
the 110 security requirements of NIST SP 800-171 Rev 2; practice identifiers use
the CMMC scheme (``DD.Ln-3.x.y``), where ``L1`` marks the 17 practices inherited
from CMMC Level 1 (FCI) and ``L2`` marks the remaining Level 2-only practices.

This is the CMMC unit of measure (110 practices). It is distinct from NIST SP
800-171A, which decomposes the same requirements into ~320 assessment objectives
for scoring — a separate catalog, not represented here.

Each practice carries ``tags`` that the coverage engine matches against
``KAHU_CAPABILITIES`` / ``MANUAL_RECOMMENDATIONS`` to decide met / ready / gap.
"""

from __future__ import annotations

CMMC_L2_FRAMEWORK: dict = {
    "name": "CMMC Level 2",
    "description": (
        "Cybersecurity Maturity Model Certification — Advanced (Level 2)."
        " 110 practices across 14 domains, aligned to NIST SP 800-171 Rev 2."
    ),
    "version": "2.0",
    "families": {
        "AC": {
            "name": "Access Control",
            "controls": [
                {
                    "id": "AC.L1-3.1.1",
                    "title": "Authorized Access Control",
                    "tags": ["access_control", "authentication"],
                },
                {
                    "id": "AC.L1-3.1.2",
                    "title": "Transaction & Function Control",
                    "tags": ["access_control", "least_privilege"],
                },
                {
                    "id": "AC.L2-3.1.3",
                    "title": "Control CUI Flow",
                    "tags": ["boundary_protection", "network_monitoring"],
                },
                {
                    "id": "AC.L2-3.1.4",
                    "title": "Separation of Duties",
                    "tags": ["least_privilege", "governance"],
                },
                {"id": "AC.L2-3.1.5", "title": "Least Privilege", "tags": ["least_privilege"]},
                {
                    "id": "AC.L2-3.1.6",
                    "title": "Non-Privileged Account Use",
                    "tags": ["least_privilege", "access_control"],
                },
                {
                    "id": "AC.L2-3.1.7",
                    "title": "Privileged Functions",
                    "tags": ["privilege_escalation", "audit_logging"],
                },
                {
                    "id": "AC.L2-3.1.8",
                    "title": "Unsuccessful Logon Attempts",
                    "tags": ["authentication", "monitoring"],
                },
                {
                    "id": "AC.L2-3.1.9",
                    "title": "Privacy & Security Notices",
                    "tags": ["governance"],
                },
                {"id": "AC.L2-3.1.10", "title": "Session Lock", "tags": ["session_management"]},
                {
                    "id": "AC.L2-3.1.11",
                    "title": "Session Termination",
                    "tags": ["session_management"],
                },
                {
                    "id": "AC.L2-3.1.12",
                    "title": "Control Remote Access",
                    "tags": ["access_control", "monitoring"],
                },
                {
                    "id": "AC.L2-3.1.13",
                    "title": "Remote Access Confidentiality",
                    "tags": ["encryption", "access_control"],
                },
                {
                    "id": "AC.L2-3.1.14",
                    "title": "Remote Access Routing",
                    "tags": ["network_segmentation", "boundary_protection"],
                },
                {
                    "id": "AC.L2-3.1.15",
                    "title": "Privileged Remote Access",
                    "tags": ["privilege_escalation", "access_control"],
                },
                {
                    "id": "AC.L2-3.1.16",
                    "title": "Wireless Access Authorization",
                    "tags": ["access_control", "authentication"],
                },
                {
                    "id": "AC.L2-3.1.17",
                    "title": "Wireless Access Protection",
                    "tags": ["encryption", "authentication"],
                },
                {
                    "id": "AC.L2-3.1.18",
                    "title": "Mobile Device Connection",
                    "tags": ["access_control", "endpoint_protection"],
                },
                {
                    "id": "AC.L2-3.1.19",
                    "title": "Encrypt CUI on Mobile",
                    "tags": ["encryption", "data_protection"],
                },
                {
                    "id": "AC.L1-3.1.20",
                    "title": "External Connections",
                    "tags": ["boundary_protection", "network_monitoring"],
                },
                {
                    "id": "AC.L2-3.1.21",
                    "title": "Portable Storage Use",
                    "tags": ["data_protection", "access_control"],
                },
                {
                    "id": "AC.L1-3.1.22",
                    "title": "Control Public Information",
                    "tags": ["governance", "data_protection"],
                },
            ],
        },
        "AT": {
            "name": "Awareness & Training",
            "controls": [
                {"id": "AT.L2-3.2.1", "title": "Role-Based Risk Awareness", "tags": ["training"]},
                {"id": "AT.L2-3.2.2", "title": "Role-Based Training", "tags": ["training"]},
                {
                    "id": "AT.L2-3.2.3",
                    "title": "Insider Threat Awareness",
                    "tags": ["training", "governance"],
                },
            ],
        },
        "AU": {
            "name": "Audit & Accountability",
            "controls": [
                {
                    "id": "AU.L2-3.3.1",
                    "title": "System Auditing",
                    "tags": ["audit_logging", "siem"],
                },
                {
                    "id": "AU.L2-3.3.2",
                    "title": "User Accountability",
                    "tags": ["audit_logging", "attribution"],
                },
                {
                    "id": "AU.L2-3.3.3",
                    "title": "Event Review",
                    "tags": ["audit_logging", "monitoring"],
                },
                {
                    "id": "AU.L2-3.3.4",
                    "title": "Audit Failure Alerting",
                    "tags": ["monitoring", "audit_logging"],
                },
                {
                    "id": "AU.L2-3.3.5",
                    "title": "Audit Correlation",
                    "tags": ["correlation", "siem"],
                },
                {
                    "id": "AU.L2-3.3.6",
                    "title": "Reduction & Reporting",
                    "tags": ["audit_logging", "siem"],
                },
                {
                    "id": "AU.L2-3.3.7",
                    "title": "Authoritative Time Source",
                    "tags": ["configuration"],
                },
                {
                    "id": "AU.L2-3.3.8",
                    "title": "Audit Protection",
                    "tags": ["audit_logging", "log_retention"],
                },
                {
                    "id": "AU.L2-3.3.9",
                    "title": "Audit Management",
                    "tags": ["audit_logging", "access_control"],
                },
            ],
        },
        "CM": {
            "name": "Configuration Management",
            "controls": [
                {
                    "id": "CM.L2-3.4.1",
                    "title": "System Baselining",
                    "tags": ["baseline", "configuration"],
                },
                {
                    "id": "CM.L2-3.4.2",
                    "title": "Security Configuration Enforcement",
                    "tags": ["hardening", "configuration"],
                },
                {
                    "id": "CM.L2-3.4.3",
                    "title": "System Change Management",
                    "tags": ["change_management", "configuration"],
                },
                {
                    "id": "CM.L2-3.4.4",
                    "title": "Security Impact Analysis",
                    "tags": ["change_management", "security_assessment"],
                },
                {
                    "id": "CM.L2-3.4.5",
                    "title": "Access Restrictions for Change",
                    "tags": ["change_management", "access_control"],
                },
                {
                    "id": "CM.L2-3.4.6",
                    "title": "Least Functionality",
                    "tags": ["hardening", "configuration"],
                },
                {
                    "id": "CM.L2-3.4.7",
                    "title": "Nonessential Functionality",
                    "tags": ["hardening", "configuration"],
                },
                {
                    "id": "CM.L2-3.4.8",
                    "title": "Application Execution Policy",
                    "tags": ["configuration", "hardening"],
                },
                {
                    "id": "CM.L2-3.4.9",
                    "title": "User-Installed Software",
                    "tags": ["configuration", "monitoring"],
                },
            ],
        },
        "IA": {
            "name": "Identification & Authentication",
            "controls": [
                {
                    "id": "IA.L1-3.5.1",
                    "title": "Identification",
                    "tags": ["authentication", "identity"],
                },
                {"id": "IA.L1-3.5.2", "title": "Authentication", "tags": ["authentication"]},
                {
                    "id": "IA.L2-3.5.3",
                    "title": "Multifactor Authentication",
                    "tags": ["mfa", "authentication"],
                },
                {
                    "id": "IA.L2-3.5.4",
                    "title": "Replay-Resistant Authentication",
                    "tags": ["authentication"],
                },
                {"id": "IA.L2-3.5.5", "title": "Identifier Reuse", "tags": ["identity"]},
                {"id": "IA.L2-3.5.6", "title": "Identifier Handling", "tags": ["identity"]},
                {
                    "id": "IA.L2-3.5.7",
                    "title": "Password Complexity",
                    "tags": ["authentication", "identity"],
                },
                {
                    "id": "IA.L2-3.5.8",
                    "title": "Password Reuse",
                    "tags": ["authentication", "identity"],
                },
                {"id": "IA.L2-3.5.9", "title": "Temporary Passwords", "tags": ["authentication"]},
                {
                    "id": "IA.L2-3.5.10",
                    "title": "Cryptographically-Protected Passwords",
                    "tags": ["cryptography", "authentication"],
                },
                {"id": "IA.L2-3.5.11", "title": "Obscure Feedback", "tags": ["authentication"]},
            ],
        },
        "IR": {
            "name": "Incident Response",
            "controls": [
                {
                    "id": "IR.L2-3.6.1",
                    "title": "Incident Handling",
                    "tags": ["incident_response", "triage"],
                },
                {
                    "id": "IR.L2-3.6.2",
                    "title": "Incident Reporting",
                    "tags": ["incident_response", "evidence"],
                },
                {
                    "id": "IR.L2-3.6.3",
                    "title": "Incident Response Testing",
                    "tags": ["testing", "incident_response"],
                },
            ],
        },
        "MA": {
            "name": "Maintenance",
            "controls": [
                {
                    "id": "MA.L2-3.7.1",
                    "title": "Perform Maintenance",
                    "tags": ["configuration", "governance"],
                },
                {
                    "id": "MA.L2-3.7.2",
                    "title": "System Maintenance Control",
                    "tags": ["configuration", "access_control"],
                },
                {
                    "id": "MA.L2-3.7.3",
                    "title": "Equipment Sanitization",
                    "tags": ["data_protection"],
                },
                {
                    "id": "MA.L2-3.7.4",
                    "title": "Media Inspection",
                    "tags": ["antimalware", "endpoint_protection"],
                },
                {
                    "id": "MA.L2-3.7.5",
                    "title": "Nonlocal Maintenance",
                    "tags": ["access_control", "authentication"],
                },
                {"id": "MA.L2-3.7.6", "title": "Maintenance Personnel", "tags": ["governance"]},
            ],
        },
        "MP": {
            "name": "Media Protection",
            "controls": [
                {"id": "MP.L2-3.8.1", "title": "Media Protection", "tags": ["data_protection"]},
                {
                    "id": "MP.L2-3.8.2",
                    "title": "Media Access",
                    "tags": ["access_control", "data_protection"],
                },
                {"id": "MP.L1-3.8.3", "title": "Media Disposal", "tags": ["data_protection"]},
                {
                    "id": "MP.L2-3.8.4",
                    "title": "Media Markings",
                    "tags": ["data_protection", "governance"],
                },
                {
                    "id": "MP.L2-3.8.5",
                    "title": "Media Accountability",
                    "tags": ["data_protection", "asset_inventory"],
                },
                {
                    "id": "MP.L2-3.8.6",
                    "title": "Portable Storage Encryption",
                    "tags": ["encryption", "data_protection"],
                },
                {
                    "id": "MP.L2-3.8.7",
                    "title": "Removable Media",
                    "tags": ["data_protection", "access_control"],
                },
                {
                    "id": "MP.L2-3.8.8",
                    "title": "Shared Media",
                    "tags": ["data_protection", "access_control"],
                },
                {
                    "id": "MP.L2-3.8.9",
                    "title": "Protect Backups",
                    "tags": ["data_protection", "encryption"],
                },
            ],
        },
        "PS": {
            "name": "Personnel Security",
            "controls": [
                {"id": "PS.L2-3.9.1", "title": "Screen Individuals", "tags": ["governance"]},
                {
                    "id": "PS.L2-3.9.2",
                    "title": "Personnel Actions",
                    "tags": ["governance", "access_control"],
                },
            ],
        },
        "PE": {
            "name": "Physical Protection",
            "controls": [
                {"id": "PE.L1-3.10.1", "title": "Limit Physical Access", "tags": ["governance"]},
                {"id": "PE.L2-3.10.2", "title": "Monitor Facility", "tags": ["monitoring"]},
                {"id": "PE.L1-3.10.3", "title": "Escort Visitors", "tags": ["governance"]},
                {
                    "id": "PE.L1-3.10.4",
                    "title": "Physical Access Logs",
                    "tags": ["audit_logging", "governance"],
                },
                {
                    "id": "PE.L1-3.10.5",
                    "title": "Manage Physical Access",
                    "tags": ["access_control", "governance"],
                },
                {
                    "id": "PE.L2-3.10.6",
                    "title": "Alternative Work Sites",
                    "tags": ["governance", "access_control"],
                },
            ],
        },
        "RA": {
            "name": "Risk Assessment",
            "controls": [
                {"id": "RA.L2-3.11.1", "title": "Risk Assessments", "tags": ["risk_assessment"]},
                {
                    "id": "RA.L2-3.11.2",
                    "title": "Vulnerability Scan",
                    "tags": ["vulnerability_scan", "vulnerability_management"],
                },
                {
                    "id": "RA.L2-3.11.3",
                    "title": "Vulnerability Remediation",
                    "tags": ["remediation", "vulnerability_management"],
                },
            ],
        },
        "CA": {
            "name": "Security Assessment",
            "controls": [
                {
                    "id": "CA.L2-3.12.1",
                    "title": "Security Control Assessment",
                    "tags": ["security_assessment"],
                },
                {
                    "id": "CA.L2-3.12.2",
                    "title": "Plan of Action",
                    "tags": ["security_assessment", "remediation"],
                },
                {
                    "id": "CA.L2-3.12.3",
                    "title": "Security Control Monitoring",
                    "tags": ["continuous_monitoring", "monitoring"],
                },
                {"id": "CA.L2-3.12.4", "title": "System Security Plan", "tags": ["governance"]},
            ],
        },
        "SC": {
            "name": "System & Communications Protection",
            "controls": [
                {
                    "id": "SC.L1-3.13.1",
                    "title": "Boundary Protection",
                    "tags": ["boundary_protection", "network_monitoring"],
                },
                {
                    "id": "SC.L2-3.13.2",
                    "title": "Security Engineering",
                    "tags": ["governance", "configuration"],
                },
                {
                    "id": "SC.L2-3.13.3",
                    "title": "Role Separation",
                    "tags": ["least_privilege", "configuration"],
                },
                {
                    "id": "SC.L2-3.13.4",
                    "title": "Shared Resource Control",
                    "tags": ["configuration", "data_protection"],
                },
                {
                    "id": "SC.L1-3.13.5",
                    "title": "Public-Access System Separation",
                    "tags": ["network_segmentation", "boundary_protection"],
                },
                {
                    "id": "SC.L2-3.13.6",
                    "title": "Network Communication by Exception",
                    "tags": ["boundary_protection", "network_monitoring"],
                },
                {
                    "id": "SC.L2-3.13.7",
                    "title": "Split Tunneling",
                    "tags": ["network_segmentation", "boundary_protection"],
                },
                {
                    "id": "SC.L2-3.13.8",
                    "title": "Data in Transit",
                    "tags": ["encryption", "data_protection"],
                },
                {
                    "id": "SC.L2-3.13.9",
                    "title": "Connections Termination",
                    "tags": ["session_management", "network_monitoring"],
                },
                {
                    "id": "SC.L2-3.13.10",
                    "title": "Key Management",
                    "tags": ["cryptography", "encryption"],
                },
                {
                    "id": "SC.L2-3.13.11",
                    "title": "CUI Encryption",
                    "tags": ["encryption", "cryptography"],
                },
                {
                    "id": "SC.L2-3.13.12",
                    "title": "Collaborative Device Control",
                    "tags": ["configuration", "access_control"],
                },
                {
                    "id": "SC.L2-3.13.13",
                    "title": "Mobile Code",
                    "tags": ["configuration", "antimalware"],
                },
                {
                    "id": "SC.L2-3.13.14",
                    "title": "Voice over Internet Protocol",
                    "tags": ["configuration", "network_monitoring"],
                },
                {
                    "id": "SC.L2-3.13.15",
                    "title": "Communications Authenticity",
                    "tags": ["encryption", "integrity"],
                },
                {
                    "id": "SC.L2-3.13.16",
                    "title": "Data at Rest",
                    "tags": ["encryption", "data_protection"],
                },
            ],
        },
        "SI": {
            "name": "System & Information Integrity",
            "controls": [
                {
                    "id": "SI.L1-3.14.1",
                    "title": "Flaw Remediation",
                    "tags": ["patching", "vulnerability_management"],
                },
                {
                    "id": "SI.L1-3.14.2",
                    "title": "Malicious Code Protection",
                    "tags": ["antimalware", "endpoint_protection"],
                },
                {
                    "id": "SI.L2-3.14.3",
                    "title": "Security Alerts & Advisories",
                    "tags": ["monitoring", "siem"],
                },
                {
                    "id": "SI.L1-3.14.4",
                    "title": "Update Malicious Code Protection",
                    "tags": ["antimalware", "patching"],
                },
                {
                    "id": "SI.L1-3.14.5",
                    "title": "System & File Scanning",
                    "tags": ["antimalware", "endpoint_protection"],
                },
                {
                    "id": "SI.L2-3.14.6",
                    "title": "Monitor Communications for Attacks",
                    "tags": ["monitoring", "network_monitoring"],
                },
                {
                    "id": "SI.L2-3.14.7",
                    "title": "Identify Unauthorized Use",
                    "tags": ["anomaly_detection", "monitoring"],
                },
            ],
        },
    },
}
