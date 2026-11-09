"""
Acceptance Test Suite for Advanced V1 Options 1 & 2:
1. Rust EDR Telemetry Integration Contracts (ProcessLineage, ExePath, ProcessGuid, ParentGuid, Sha256).
2. Advanced MITRE ATT&CK Streaming Correlation Rules (Rules 7, 8, 9, 10).
3. Ultra-low Latency Multi-rule Evaluation (<1000 µs per event across 10 rules).
"""

import unittest
import time
from datetime import datetime, timedelta

from app.services.edr.process_tree import ProcessTreeBuilder, ProcessNode
from app.services.correlation_service import StreamingCorrelationEngine


class TestAdvancedOptions1And2Expanded(unittest.TestCase):

    def setUp(self):
        self.engine = StreamingCorrelationEngine()

    def test_01_process_node_rich_lineage_contract(self):
        """Test ProcessNode with ProcessGuid, ParentProcessGuid, ExePath, and Sha256."""
        node = ProcessNode(
            pid=1024,
            ppid=512,
            name="svchost.exe",
            command_line="C:\\Windows\\system32\\svchost.exe -k netsvcs",
            cpu_usage=1.5,
            memory_bytes=40960000,
            status="RUNNING",
            user="NT AUTHORITY\\SYSTEM",
            process_guid="AGENT-01-1024-1710000000",
            parent_guid="AGENT-01-512-1710000000",
            exe_path="C:\\Windows\\system32\\svchost.exe",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        d = node.to_dict()
        self.assertEqual(d["pid"], 1024)
        self.assertEqual(d["ppid"], 512)
        self.assertEqual(d["process_guid"], "AGENT-01-1024-1710000000")
        self.assertEqual(d["parent_guid"], "AGENT-01-512-1710000000")
        self.assertEqual(d["exe_path"], "C:\\Windows\\system32\\svchost.exe")
        self.assertEqual(d["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_02_process_tree_builder_normalizes_rich_rust_telemetry(self):
        """Test ProcessTreeBuilder normalizes Rust agent snapshot items with GUIDs."""
        raw_rust_telemetry = [
            {
                "PID": 1,
                "PPID": 0,
                "ProcessGuid": "AGENT-01-1-1710000000",
                "ParentProcessGuid": "00000000-0000-0000-0000-000000000000",
                "Name": "systemd",
                "CommandLine": "/sbin/init",
                "ExePath": "/sbin/init",
                "User": "root",
                "Sha256": "aaaa1111",
                "CPU_Usage": 0.1,
                "Memory_Bytes": 1024000
            },
            {
                "PID": 200,
                "PPID": 1,
                "ProcessGuid": "AGENT-01-200-1710000000",
                "ParentProcessGuid": "AGENT-01-1-1710000000",
                "Name": "bash",
                "CommandLine": "/bin/bash",
                "ExePath": "/bin/bash",
                "User": "admin",
                "Sha256": "bbbb2222",
                "CPU_Usage": 0.5,
                "Memory_Bytes": 2048000
            }
        ]
        tree = ProcessTreeBuilder.build_tree_from_snapshot(raw_rust_telemetry)
        self.assertEqual(tree["pid"], 1)
        self.assertEqual(tree["process_guid"], "AGENT-01-1-1710000000")
        self.assertEqual(len(tree["children"]), 1)
        child = tree["children"][0]
        self.assertEqual(child["pid"], 200)
        self.assertEqual(child["parent_guid"], "AGENT-01-1-1710000000")
        self.assertEqual(child["sha256"], "bbbb2222")

    def test_03_engine_status_reports_all_10_rules(self):
        """Test streaming correlation engine reports all 10 active MITRE ATT&CK rules."""
        metrics = self.engine.get_metrics()
        self.assertEqual(metrics["status"], "online")
        active_rules = metrics["active_rules"]
        self.assertEqual(len(active_rules), 10)
        expected_rules = [
            "RANSOMWARE_BLAST_T1486_T1490",
            "COORDINATED_KERBEROAST_DCSYNC_T1558_T1003",
            "LATERAL_MOVEMENT_OUTBREAK_T1021_T1550",
            "EGRESS_C2_BEACONING_T1071",
            "DISTRIBUTED_BRUTE_FORCE_T1110",
            "APT_LOLBIN_C2_EGRESS_T1059_T1071",
            "DECEPTION_CANARY_BREACH_T1486_T1565",
            "VOLUME_SHADOW_DESTRUCTION_T1490",
            "LSASS_CREDENTIAL_DUMP_T1003",
            "PERSISTENCE_SUSPICIOUS_SERVICE_TASK_T1053_T1543"
        ]
        for rule in expected_rules:
            self.assertIn(rule, active_rules, f"Missing rule {rule}")

    def test_04_rule_7_canary_trap_breach(self):
        """Test Rule 7: Canary Trap File Access & Breach."""
        event = {
            "AgentId": "AGENT-SEC-01",
            "TenantId": 1,
            "EventType": "FileModification",
            "Payload": {
                "file_path": "/var/canary/passwords_decoy.xlsx.canary",
                "process_name": "malware.exe",
                "details": "Tamper detected on deception canary file"
            },
            "Timestamp": datetime.utcnow().isoformat()
        }
        correlations = self.engine.evaluate_event(event)
        self.assertEqual(len(correlations), 1)
        corr = correlations[0]
        self.assertEqual(corr["rule_id"], "DECEPTION_CANARY_BREACH_T1486_T1565")
        self.assertEqual(corr["severity"], "Critical")
        self.assertEqual(corr["confidence"], 99)
        self.assertEqual(corr["recommended_playbook_id"], 2)

    def test_05_rule_8_volume_shadow_destruction(self):
        """Test Rule 8: Volume Shadow Copy & Recovery Destruction."""
        event = {
            "AgentId": "AGENT-SEC-01",
            "TenantId": 1,
            "EventType": "ProcessExecution",
            "Payload": {
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "process_name": "vssadmin.exe",
                "details": "Volume shadow deletion command"
            },
            "Timestamp": datetime.utcnow().isoformat()
        }
        correlations = self.engine.evaluate_event(event)
        self.assertEqual(len(correlations), 1)
        corr = correlations[0]
        self.assertEqual(corr["rule_id"], "VOLUME_SHADOW_DESTRUCTION_T1490")
        self.assertEqual(corr["severity"], "Critical")
        self.assertEqual(corr["confidence"], 98)

    def test_06_rule_9_lsass_dumping(self):
        """Test Rule 9: LSASS Memory Injection & Dump."""
        event = {
            "AgentId": "AGENT-SEC-01",
            "TenantId": 1,
            "EventType": "ProcessExecution",
            "Payload": {
                "command_line": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
                "process_name": "rundll32.exe",
                "details": "comsvcs minidump against lsass"
            },
            "Timestamp": datetime.utcnow().isoformat()
        }
        correlations = self.engine.evaluate_event(event)
        self.assertEqual(len(correlations), 1)
        corr = correlations[0]
        self.assertEqual(corr["rule_id"], "LSASS_CREDENTIAL_DUMP_T1003")
        self.assertEqual(corr["severity"], "Critical")
        self.assertEqual(corr["confidence"], 98)

    def test_07_rule_10_suspicious_scheduled_task(self):
        """Test Rule 10: Suspicious Scheduled Task / Service Persistence."""
        event = {
            "AgentId": "AGENT-SEC-01",
            "TenantId": 1,
            "EventType": "ProcessExecution",
            "Payload": {
                "command_line": 'schtasks /create /tn "SecurityUpdater" /tr "powershell.exe -enc SQBFAFgA" /sc onlogon',
                "process_name": "schtasks.exe",
                "details": "Scheduled task creation with encoded powershell payload"
            },
            "Timestamp": datetime.utcnow().isoformat()
        }
        correlations = self.engine.evaluate_event(event)
        self.assertEqual(len(correlations), 1)
        corr = correlations[0]
        self.assertEqual(corr["rule_id"], "PERSISTENCE_SUSPICIOUS_SERVICE_TASK_T1053_T1543")
        self.assertEqual(corr["severity"], "High")
        self.assertEqual(corr["confidence"], 94)

    def test_08_multi_stage_attack_chain_synthesis(self):
        """Test that successive attacks synthesize a multi-stage attack chain."""
        agent_id = "AGENT-EPIC-99"
        # Step 1: LSASS dump
        ev1 = {
            "AgentId": agent_id,
            "TenantId": 1,
            "EventType": "ProcessExecution",
            "Payload": {"command_line": "procdump.exe -ma lsass.exe lsass.dmp", "process_name": "procdump.exe"},
            "Timestamp": datetime.utcnow().isoformat()
        }
        res1 = self.engine.evaluate_event(ev1)
        self.assertEqual(len(res1), 1)
        chain1 = res1[0]["attack_chain"]
        self.assertEqual(len(chain1["stages"]), 1)

        # Step 2: Shadow destruction
        ev2 = {
            "AgentId": agent_id,
            "TenantId": 1,
            "EventType": "ProcessExecution",
            "Payload": {"command_line": "wmic shadowcopy delete", "process_name": "wmic.exe"},
            "Timestamp": datetime.utcnow().isoformat()
        }
        res2 = self.engine.evaluate_event(ev2)
        self.assertEqual(len(res2), 1)
        chain2 = res2[0]["attack_chain"]
        self.assertEqual(len(chain2["stages"]), 2)
        self.assertEqual(chain1["id"], chain2["id"])

    def test_09_evaluation_latency_performance_budget(self):
        """Benchmark: average evaluation latency across all 10 rules must be under 1000 µs."""
        t_start = time.perf_counter()
        iterations = 500
        for i in range(iterations):
            ev = {
                "AgentId": f"AGENT-PERF-{i % 10}",
                "TenantId": 1,
                "EventType": "ProcessExecution",
                "Payload": {
                    "command_line": f"svchost.exe -k netsvcs -p {i}",
                    "process_name": "svchost.exe"
                },
                "Timestamp": datetime.utcnow().isoformat()
            }
            self.engine.evaluate_event(ev)

        total_sec = time.perf_counter() - t_start
        avg_us = (total_sec / iterations) * 1_000_000.0
        self.assertLess(avg_us, 1000.0, f"Average latency {avg_us:.2f} µs exceeded 1000 µs budget")
        print(f"\n[Performance Benchmark] Average latency across 10 rules: {avg_us:.2f} µs/event ({iterations} events)")


if __name__ == "__main__":
    unittest.main()
