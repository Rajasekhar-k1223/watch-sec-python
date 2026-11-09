"""
Automated Comprehensive Test Suite for Monitorix Advanced V1 Implementation:
Option 1: Advanced EDR & Dynamic Process Lineage
Option 2: Threat Hunting & Safe AST Query Engine
Option 3: Production Maintenance & 90-Day Retention TTL
"""

import unittest
from datetime import datetime
from typing import Dict, Any

from app.services.edr.process_tree import ProcessTreeBuilder, ProcessNode
from app.services.edr.risk_scoring import calculate_endpoint_risk
from app.services.hunting.ast_parser import parse_query, BinaryNode, UnaryNode, ComparisonNode, FreeTextNode
from app.services.hunting.clickhouse_compiler import ClickHouseQueryCompiler, compile_threat_hunt_query
from app.db.clickhouse import clickhouse_db


class TestOption1DynamicProcessTree(unittest.TestCase):
    """Test Suite for Option 1: Dynamic Process Tree & Cycle Protection."""

    def test_process_tree_hierarchical_assembly(self):
        """Verify multi-level process parent-child assembly."""
        records = [
            {"PID": 100, "PPID": 0, "Name": "System", "CommandLine": "System"},
            {"PID": 200, "PPID": 100, "Name": "services.exe", "CommandLine": "services.exe"},
            {"PID": 300, "PPID": 200, "Name": "svchost.exe", "CommandLine": "svchost.exe -k netsvcs"},
            {"PID": 400, "PPID": 300, "Name": "powershell.exe", "CommandLine": "powershell.exe -enc ..."},
        ]
        tree = ProcessTreeBuilder.build_from_telemetry(records)
        self.assertEqual(tree["pid"], 100)
        self.assertEqual(tree["name"], "System")
        self.assertEqual(len(tree["children"]), 1)
        self.assertEqual(tree["children"][0]["pid"], 200)
        self.assertEqual(tree["children"][0]["children"][0]["pid"], 300)
        self.assertEqual(tree["children"][0]["children"][0]["children"][0]["pid"], 400)
        self.assertEqual(tree["total_nodes"], 4)
        self.assertEqual(tree["max_depth"], 4)

    def test_process_tree_cycle_detection(self):
        """Verify cycle detection (A -> B -> A) does not trigger infinite loops or crash."""
        cyclic_records = [
            {"PID": 10, "PPID": 30, "Name": "procA.exe"},
            {"PID": 20, "PPID": 10, "Name": "procB.exe"},
            {"PID": 30, "PPID": 20, "Name": "procC.exe"},  # Cycle: 10 -> 30 -> 20 -> 10
            {"PID": 40, "PPID": 10, "Name": "procD.exe"},
        ]
        tree = ProcessTreeBuilder.build_from_telemetry(cyclic_records)
        self.assertIsNotNone(tree)
        self.assertIn("children", tree)
        # Cycle should be broken and nodes promoted to roots safely
        self.assertEqual(tree["total_nodes"], 4)

    def test_process_tree_self_parent_cycle(self):
        """Verify self-parenting process (PID == PPID) is handled safely."""
        self_parent = [
            {"PID": 55, "PPID": 55, "Name": "loop_proc.exe"}
        ]
        tree = ProcessTreeBuilder.build_from_telemetry(self_parent)
        self.assertEqual(tree["pid"], 55)
        self.assertEqual(len(tree["children"]), 0)

    def test_process_tree_empty_and_malformed(self):
        """Verify handling of empty lists and non-dict records."""
        empty_tree = ProcessTreeBuilder.build_from_telemetry([])
        self.assertEqual(empty_tree["total_nodes"], 0)

        malformed = [{"invalid": True}, "not a dict", None, {"PID": "invalid_pid"}]
        tree = ProcessTreeBuilder.build_from_telemetry(malformed)
        self.assertEqual(tree["total_nodes"], 0)


class TestOption1ExplainableRiskEngine(unittest.TestCase):
    """Test Suite for Option 1: Explainable Dynamic Endpoint Risk Scoring."""

    class MockAlert:
        def __init__(self, severity: str, title: str = "", rule_title: str = "", desc: str = ""):
            self.Severity = severity
            self.Title = title
            self.RuleTitle = rule_title
            self.Description = desc

    def test_clean_baseline_risk(self):
        """Verify clean baseline endpoint produces low risk tier."""
        res = calculate_endpoint_risk(agent_id="test-clean-01", alerts=[], ioc_matches_count=0)
        self.assertLess(res["device_risk_score"], 40.0)
        self.assertEqual(res["fleet_risk_tier"], "Low Risk (Compliant)")
        self.assertTrue(res["is_explainable"])
        self.assertGreater(len(res["factors"]), 0)

    def test_critical_attack_chain_risk(self):
        """Verify critical attack chain produces critical tier and transparent factor list."""
        alerts = [
            self.MockAlert("Critical", "LSASS Memory Credential Access", "Rule 9002", "Dumping lsass.exe"),
            self.MockAlert("High", "C2 Beaconing via HTTPS", "Rule 9005", "Periodic beaconing to known C2"),
            self.MockAlert("High", "Suspicious LOLBin PowerShell Execution", "Rule 9001", "Encoded powershell")
        ]
        res = calculate_endpoint_risk(
            agent_id="compromised-host-01",
            alerts=alerts,
            ioc_matches_count=4,
            posture_issues_count=2,
            is_isolated=False
        )
        self.assertGreaterEqual(res["device_risk_score"], 80.0)
        self.assertEqual(res["fleet_risk_tier"], "Critical Threat Exposure")
        # Factors must explain why the score was computed
        factor_text = " ".join(res["factors"])
        self.assertIn("active IOC", factor_text)
        self.assertIn("Critical detection alert", factor_text)
        self.assertIn("Credential access attempt", factor_text)

    def test_containment_mitigates_blast_radius(self):
        """Verify active network containment discounts the blast radius and overall score."""
        alerts = [self.MockAlert("Critical", "Ransomware Ingress")]
        active = calculate_endpoint_risk("host-01", alerts=alerts, ioc_matches_count=2, is_isolated=False)
        isolated = calculate_endpoint_risk("host-01", alerts=alerts, ioc_matches_count=2, is_isolated=True)

        self.assertLess(isolated["device_risk_score"], active["device_risk_score"])
        self.assertLess(isolated["blast_radius_score"], active["blast_radius_score"])
        factor_text = " ".join(isolated["factors"])
        self.assertIn("Network Containment", factor_text)


class TestOption2ASTParserAndCompiler(unittest.TestCase):
    """Test Suite for Option 2: Safe AST Lexer, Parser & ClickHouse Compiler."""

    def test_simple_comparison_parse(self):
        """Verify simple field comparisons parse into ComparisonNode."""
        ast = parse_query('process_name = "powershell.exe"')
        self.assertIsInstance(ast, ComparisonNode)
        self.assertEqual(ast.field, "process_name")
        self.assertEqual(ast.op, "=")
        self.assertEqual(ast.value, "powershell.exe")

    def test_boolean_and_or_nested_parse(self):
        """Verify boolean AND/OR expressions parse into BinaryNode hierarchy."""
        ast = parse_query('process_name = "cmd.exe" AND (dest_port = 443 OR cmd contains "download")')
        self.assertIsInstance(ast, BinaryNode)
        self.assertEqual(ast.op, "AND")
        self.assertIsInstance(ast.right, BinaryNode)
        self.assertEqual(ast.right.op, "OR")

    def test_unary_not_parse(self):
        """Verify unary NOT operator parses into UnaryNode."""
        ast = parse_query('NOT agent_id = "trusted-host"')
        self.assertIsInstance(ast, UnaryNode)
        self.assertEqual(ast.op, "NOT")
        self.assertIsInstance(ast.child, ComparisonNode)

    def test_clickhouse_query_compiler_parameterization(self):
        """Verify query compiler compiles to valid parameterized SQL with zero string concatenation."""
        sql, params = compile_threat_hunt_query(
            query_str='process_name = "procdump.exe" AND cmd contains "lsass"',
            tenant_id=1,
            limit=25,
            time_range_hours=12
        )
        self.assertIn("SELECT event_id, agent_id, event_type, timestamp, payload", sql)
        self.assertIn("FROM monitorix.monitorix_telemetry_raw", sql)
        self.assertIn("tenant_id = %(tenant_id)s", sql)
        self.assertIn("JSONExtractString(payload,", sql)
        self.assertEqual(params["tenant_id"], "1")
        self.assertEqual(params["limit"], 25)
        # Ensure values are parameterized, not in raw SQL
        self.assertNotIn("'procdump.exe'", sql)
        self.assertIn("procdump.exe", params.values())

    def test_tenant_isolation_enforcement(self):
        """Verify compiler strictly binds the caller tenant ID."""
        sql, params = compile_threat_hunt_query("anything", tenant_id=42)
        self.assertIn("tenant_id = %(tenant_id)s", sql)
        self.assertEqual(params["tenant_id"], "42")

    def test_sql_injection_immunity(self):
        """Verify malicious injection attempts are treated as literal strings in parameters."""
        malicious_input = "'; DROP TABLE monitorix_telemetry_raw; --"
        sql, params = compile_threat_hunt_query(malicious_input, tenant_id=1)
        self.assertNotIn("DROP TABLE", sql)
        self.assertIn(malicious_input, params.values())


class TestOption3ClickHouseRetentionTTL(unittest.TestCase):
    """Test Suite for Option 3: ClickHouse 90-Day Retention TTL."""

    def test_retention_ttl_present_in_clickhouse_schema(self):
        """Verify monitorix_telemetry_raw on live ClickHouse has active 90-day retention TTL."""
        if not clickhouse_db.client:
            clickhouse_db.connect()

        if clickhouse_db.client:
            rows = clickhouse_db.client.execute("SHOW CREATE TABLE monitorix.monitorix_telemetry_raw")
            self.assertTrue(len(rows) > 0)
            create_stmt = rows[0][0]
            self.assertIn("TTL", create_stmt)
            self.assertIn("toIntervalDay(90)", create_stmt)


if __name__ == "__main__":
    unittest.main()
