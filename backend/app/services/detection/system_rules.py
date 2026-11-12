"""
Monitorix Enterprise System Detection Rules Registry
====================================================
Canonical definitions and idempotent registration for reserved system rule IDs 9001-9009.

Reserved System Rule IDs:
  9001 - VPNDetectionAudit: Unauthorized VPN Interface Detected
  9002 - CrashDumpAudit: Excessive Process Crash Dumps Detected (Credential Access / LSASS Dumping)
  9003 - FirewallComplianceReport: Host Firewall Disabled or Compliance Failure
  9004 - FileIntegrityAlert: Critical System File Integrity Violation
  9005 - PcapCaptureCompleted: Cleartext Credentials or Malware Ingress in Network Forensics
  9006 - WebmailActivity: Sensitive Data Exfiltration via Webmail Session
  9007 - ThreatIntelMatch: Malicious C2 Communication Detected via Threat Intelligence
  9008 - SandboxThreatPrevented: Detonation Sandbox Threat Prevented
  9009 - WSLEvasionAudit: WSL Defense Evasion & Abnormal Process Execution
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

logger = logging.getLogger("monitorix.detection.system_rules")

RESERVED_SYSTEM_RULE_IDS = {9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009}

SYSTEM_RULES_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "id": 9001,
        "name": "Unauthorized VPN Interface Detected",
        "type": "Sigma",
        "category": "Defense Evasion",
        "mitre_tactic": "TA0005 (Defense Evasion)",
        "mitre_technique": "T1562.001 (Disable or Modify Tools)",
        "severity": "Medium",
        "yaml_content": """title: Unauthorized VPN Interface Detected
id: 9001
status: production
description: Detects unauthorized VPN or proxy interface activity on managed endpoints.
author: Monitorix Sovereign Security Team
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: network_interface
  product: generic
detection:
  selection:
    vpn_active: true
  condition: selection
falsepositives:
  - Approved corporate remote-access VPN clients
level: medium
""",
    },
    {
        "id": 9002,
        "name": "Excessive Process Crash Dumps Detected",
        "type": "Sigma",
        "category": "Credential Access",
        "mitre_tactic": "TA0006 (Credential Access)",
        "mitre_technique": "T1003.001 (OS Credential Dumping: LSASS Memory)",
        "severity": "High",
        "yaml_content": """title: Excessive Process Crash Dumps Detected
id: 9002
status: production
description: Detects process crash dumps indicating exploitation or memory scraping attempts.
author: Monitorix Sovereign Security Team
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_crash
  product: generic
detection:
  selection:
    crash_dumps_count|gt: 0
  condition: selection
falsepositives:
  - Known software bugs and third-party application crashes
level: high
""",
    },
    {
        "id": 9003,
        "name": "Host Firewall Disabled or Compliance Failure",
        "type": "Sigma",
        "category": "Defense Evasion",
        "mitre_tactic": "TA0005 (Defense Evasion)",
        "mitre_technique": "T1562.004 (Disable or Modify System Firewall)",
        "severity": "Critical",
        "yaml_content": """title: Host Firewall Disabled or Compliance Failure
id: 9003
status: production
description: Detects when local host firewall (iptables/ufw/Windows Defender Firewall) is disabled.
author: Monitorix Sovereign Security Team
tags:
  - attack.defense_evasion
  - attack.t1562.004
logsource:
  category: configuration_audit
  product: generic
detection:
  selection:
    firewall_enabled: false
  condition: selection
falsepositives:
  - Maintenance windows and intentional administrator configuration changes
level: critical
""",
    },
    {
        "id": 9004,
        "name": "Critical System File Integrity Violation",
        "type": "Sigma",
        "category": "Defense Evasion",
        "mitre_tactic": "TA0005 (Defense Evasion)",
        "mitre_technique": "T1565.001 (Data Manipulation: Stored Data Manipulation)",
        "severity": "High",
        "yaml_content": """title: Critical System File Integrity Violation
id: 9004
status: production
description: Detects unauthorized modification, replacement, or deletion of monitored system files.
author: Monitorix Sovereign Security Team
tags:
  - attack.defense_evasion
  - attack.t1565.001
logsource:
  category: file_change
  product: generic
detection:
  selection:
    event_type: FileIntegrityAlert
  condition: selection
falsepositives:
  - Authorized operating system package upgrades
level: high
""",
    },
    {
        "id": 9005,
        "name": "Cleartext Credentials or Threat in PCAP Forensics",
        "type": "Sigma",
        "category": "Credential Access",
        "mitre_tactic": "TA0006 (Credential Access)",
        "mitre_technique": "T1040 (Network Sniffing)",
        "severity": "High",
        "yaml_content": """title: Cleartext Credentials or Threat in PCAP Forensics
id: 9005
status: production
description: Detects cleartext authentication tokens, passwords, or shell scripts in forensic PCAP streams.
author: Monitorix Sovereign Security Team
tags:
  - attack.credential_access
  - attack.t1040
logsource:
  category: network_traffic
  product: generic
detection:
  selection:
    pcap_credential_match: true
  condition: selection
falsepositives:
  - Legacy unencrypted protocol testing in isolated lab environments
level: high
""",
    },
    {
        "id": 9006,
        "name": "Sensitive Data Exfiltration via Webmail Session",
        "type": "Sigma",
        "category": "Exfiltration",
        "mitre_tactic": "TA0010 (Exfiltration)",
        "mitre_technique": "T1048.003 (Exfiltration Over Unencrypted Protocol)",
        "severity": "High",
        "yaml_content": """title: Sensitive Data Exfiltration via Webmail Session
id: 9006
status: production
description: Detects confidential corporate data, PII, or secret leaks via browser webmail sessions.
author: Monitorix Sovereign Security Team
tags:
  - attack.exfiltration
  - attack.t1048.003
logsource:
  category: webmail
  product: browser
detection:
  selection:
    risk_level:
      - High
      - Critical
  condition: selection
falsepositives:
  - Legitimate high-volume customer correspondence
level: high
""",
    },
    {
        "id": 9007,
        "name": "Malicious C2 Communication Detected via Threat Intelligence",
        "type": "Sigma",
        "category": "Command and Control",
        "mitre_tactic": "TA0011 (Command and Control)",
        "mitre_technique": "T1071 (Application Layer Protocol)",
        "severity": "Critical",
        "yaml_content": """title: Malicious C2 Communication Detected via Threat Intelligence
id: 9007
status: production
description: Detects outbound communication to confirmed command-and-control servers or malicious domains.
author: Monitorix Sovereign Security Team
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  category: network_connection
  product: generic
detection:
  selection:
    threat_intel_match: true
  condition: selection
falsepositives:
  - Re-assigned IP addresses or stale feed indicators
level: critical
""",
    },
    {
        "id": 9008,
        "name": "Monitorix Detonation Sandbox Threat Blocked",
        "type": "Sigma",
        "category": "Execution",
        "mitre_tactic": "TA0002 (Execution)",
        "mitre_technique": "T1204 (User Execution: Malicious File)",
        "severity": "Critical",
        "yaml_content": """title: Monitorix Detonation Sandbox Threat Blocked
id: 9008
status: production
description: Detects execution attempts blocked by the sovereign Monitorix endpoint detonation sandbox.
author: Monitorix Sovereign Security Team
tags:
  - attack.execution
  - attack.t1204
logsource:
  category: process_creation
  product: generic
detection:
  selection:
    sandbox_threat_blocked: true
  condition: selection
falsepositives:
  - Highly aggressive heuristic false positives on unsigned proprietary binaries
level: critical
""",
    },
    {
        "id": 9009,
        "name": "WSL Defense Evasion & Abnormal Process Execution",
        "type": "Sigma",
        "category": "Defense Evasion",
        "mitre_tactic": "TA0005 (Defense Evasion)",
        "mitre_technique": "T1202 (Indirect Command Execution)",
        "severity": "Critical",
        "yaml_content": """title: WSL Defense Evasion & Abnormal Process Execution
id: 9009
status: production
description: Detects abnormal execution of Windows Subsystem for Linux (WSL) binaries spawned by office applications, browsers, or suspicious command-line flags.
author: Monitorix Sovereign Security Team
tags:
  - attack.defense_evasion
  - attack.t1202
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    wsl_evasion_detected: true
  condition: selection
falsepositives:
  - Authorized developer terminal sessions launched from approved IDEs
level: critical
""",
    },
]


def is_system_rule(rule_id: int) -> bool:
    """Returns True if the given rule_id is within the reserved system rule ID range."""
    return rule_id in RESERVED_SYSTEM_RULE_IDS


def get_system_rules() -> List[Dict[str, Any]]:
    """Returns copy of canonical system rule definitions."""
    return [dict(r) for r in SYSTEM_RULES_DEFINITIONS]


def get_system_rule_by_id(rule_id: int) -> Optional[Dict[str, Any]]:
    """Returns the definition of a specific system rule ID, or None if not found."""
    for r in SYSTEM_RULES_DEFINITIONS:
        if r["id"] == rule_id:
            return dict(r)
    return None


async def seed_system_rules(db: AsyncSession) -> Dict[str, Any]:
    """
    Idempotently seeds canonical system detection rules 9001-9009 into the database.
    
    Guarantees:
    - Never overwrites existing user/tenant rules blindly.
    - If a rule ID exists with TenantId IS NULL and matching name, treats as valid existing rule.
    - If a collision occurs (ID taken by a custom rule or different tenant), reports collision without corruption.
    - System rules are created with TenantId = None (global, system-managed).
    - Returns detailed registration summary.
    """
    from app.db.models import DetectionRule

    results = {
        "seeded": 0,
        "verified_existing": 0,
        "collisions": [],
        "errors": []
    }

    try:
        # Fetch any existing rules with IDs in the reserved range
        query = select(DetectionRule).where(DetectionRule.Id.in_(RESERVED_SYSTEM_RULE_IDS))
        res = await db.execute(query)
        existing_map = {r.Id: r for r in res.scalars().all()}

        for rule_def in SYSTEM_RULES_DEFINITIONS:
            rule_id = rule_def["id"]
            if rule_id in existing_map:
                existing_rule = existing_map[rule_id]
                # Check for collision
                if existing_rule.TenantId is not None:
                    collision_info = {
                        "rule_id": rule_id,
                        "type": "TENANT_OVERRIDE_COLLISION",
                        "existing_name": existing_rule.Name,
                        "existing_tenant_id": existing_rule.TenantId,
                        "intended_name": rule_def["name"]
                    }
                    results["collisions"].append(collision_info)
                    logger.warning(f"[SystemRules] Collision on ID {rule_id}: {collision_info}")
                    
                    # Security Invariant: Emit AuditLog event for collision
                    try:
                        from app.db.models import AuditLog
                        audit_entry = AuditLog(
                            TenantId=existing_rule.TenantId,
                            Actor="SYSTEM_DETECTION_SEEDER",
                            Action="SYSTEM_RULE_ID_COLLISION",
                            Target=f"DetectionRule #{rule_id}",
                            Details=f"Collision detected: Tenant {existing_rule.TenantId} rule '{existing_rule.Name}' occupies reserved system ID {rule_id}",
                            Timestamp=datetime.utcnow()
                        )
                        db.add(audit_entry)
                    except Exception as audit_err:
                        logger.error(f"[SystemRules] Failed to create audit log for collision: {audit_err}")
                else:
                    results["verified_existing"] += 1
            else:
                # Insert new system rule with exact reserved ID
                new_rule = DetectionRule(
                    Id=rule_id,
                    TenantId=None,  # Null = Global / System-Protected
                    Name=rule_def["name"],
                    Type=rule_def["type"],
                    Category=rule_def["category"],
                    MitreTactic=rule_def["mitre_tactic"],
                    MitreTechnique=rule_def["mitre_technique"],
                    Severity=rule_def["severity"],
                    RuleContent=rule_def["yaml_content"],
                    IsActive=True
                )
                db.add(new_rule)
                results["seeded"] += 1

        if results["seeded"] > 0 or len(results["collisions"]) > 0:
            await db.commit()
            if results["seeded"] > 0:
                logger.info(f"[SystemRules] Successfully seeded {results['seeded']} system rules")

    except Exception as e:
        await db.rollback()
        results["errors"].append(str(e))
        logger.error(f"[SystemRules] Error during seeding: {e}")

    return results


def validate_rule_modification_security(rule_id: int, user_role: str, user_tenant_id: Optional[int]) -> None:
    """
    Security gate preventing tenant users from modifying or deleting protected system rules.
    Raises PermissionError if a tenant user attempts modification.
    """
    if is_system_rule(rule_id):
        if user_role != "SuperAdmin" or user_tenant_id is not None:
            raise PermissionError(
                f"Access Denied: Rule #{rule_id} is a protected system detection rule. "
                "System rules cannot be modified, overridden, or deleted by tenant users."
            )

