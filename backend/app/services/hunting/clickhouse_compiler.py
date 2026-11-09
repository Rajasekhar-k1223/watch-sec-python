"""
ClickHouse AST Query Compiler for Monitorix Threat Hunting.
Safely compiles an ASTNode into a parameterized ClickHouse SQL query
with strict tenant isolation, column mapping, and bounds enforcement.
"""

from typing import Dict, Any, Tuple, Optional
from .ast_parser import ASTNode, BinaryNode, UnaryNode, ComparisonNode, FreeTextNode, parse_query


# Known top-level table columns in monitorix_telemetry_raw
TOP_LEVEL_COLUMNS = {
    "event_id": "event_id",
    "agent_id": "agent_id",
    "tenant_id": "tenant_id",
    "event_type": "event_type",
    "timestamp": "timestamp",
}

# Common field aliases mapped to JSON payload extraction paths
PAYLOAD_FIELD_ALIASES = {
    "process": "ProcessName",
    "process_name": "ProcessName",
    "processname": "ProcessName",
    "cmd": "CommandLine",
    "cmdline": "CommandLine",
    "command_line": "CommandLine",
    "commandline": "CommandLine",
    "ip": "dest_ip",
    "dst_ip": "dest_ip",
    "dest_ip": "dest_ip",
    "src_ip": "src_ip",
    "port": "dest_port",
    "dest_port": "dest_port",
    "file": "path",
    "filename": "path",
    "file_path": "path",
    "hash": "sha256",
    "sha256": "sha256",
    "user": "user",
    "username": "user",
}


class ClickHouseQueryCompiler:
    """
    Compiles an AST into a parameterized ClickHouse SQL query.
    """

    def __init__(self, tenant_id: int = 1, limit: int = 100, time_range_hours: Optional[int] = 24):
        self.tenant_id = str(tenant_id)
        self.limit = min(max(1, limit), 500)  # Bound between 1 and 500
        self.time_range_hours = time_range_hours
        self.params: Dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "limit": self.limit,
        }
        self._param_counter = 0

    def _next_param(self, prefix: str, val: Any) -> str:
        self._param_counter += 1
        name = f"{prefix}_{self._param_counter}"
        self.params[name] = val
        return name

    def compile(self, ast: ASTNode) -> Tuple[str, Dict[str, Any]]:
        """
        Compiles the AST into SQL and returns (query_sql, params_dict).
        """
        user_sql = self._compile_node(ast)

        # Enforce tenant isolation condition
        where_clauses = ["tenant_id = %(tenant_id)s"]

        # Time range restriction
        if self.time_range_hours and self.time_range_hours > 0:
            tr_param = self._next_param("hours", self.time_range_hours)
            where_clauses.append(f"timestamp >= now() - INTERVAL %({tr_param})s HOUR")

        # User filter condition
        if user_sql and user_sql.strip():
            where_clauses.append(f"({user_sql})")

        where_expr = " AND ".join(where_clauses)

        sql = f"""
            SELECT event_id, agent_id, event_type, timestamp, payload
            FROM monitorix.monitorix_telemetry_raw
            WHERE {where_expr}
            ORDER BY timestamp DESC
            LIMIT %(limit)s
        """.strip()

        return sql, self.params

    def _compile_node(self, node: ASTNode) -> str:
        if isinstance(node, BinaryNode):
            left_sql = self._compile_node(node.left)
            right_sql = self._compile_node(node.right)
            if left_sql and right_sql:
                return f"({left_sql} {node.op} {right_sql})"
            return left_sql or right_sql or "1=1"

        elif isinstance(node, UnaryNode):
            child_sql = self._compile_node(node.child)
            if child_sql:
                return f"NOT ({child_sql})"
            return "1=1"

        elif isinstance(node, ComparisonNode):
            return self._compile_comparison(node)

        elif isinstance(node, FreeTextNode):
            if not node.text:
                return "1=1"
            p_name = self._next_param("kw", node.text)
            return f"positionCaseInsensitive(payload, %({p_name})s) > 0"

        return "1=1"

    def _compile_comparison(self, node: ComparisonNode) -> str:
        field_lower = node.field.lower()

        # Check if top-level table column
        if field_lower in TOP_LEVEL_COLUMNS:
            col_name = TOP_LEVEL_COLUMNS[field_lower]
            p_name = self._next_param("val", node.value)

            if node.op in ("=", "=="):
                return f"{col_name} = %({p_name})s"
            elif node.op == "!=":
                return f"{col_name} != %({p_name})s"
            elif node.op in (">", "<", ">=", "<="):
                return f"{col_name} {node.op} %({p_name})s"
            elif node.op == "contains":
                return f"positionCaseInsensitive({col_name}, %({p_name})s) > 0"
            elif node.op == "like":
                return f"{col_name} ILIKE %({p_name})s"
            elif node.op == "in":
                return f"{col_name} IN %({p_name})s"

        # Otherwise map to JSON payload extraction
        json_key = PAYLOAD_FIELD_ALIASES.get(field_lower, node.field)
        p_val = self._next_param("val", node.value)
        p_key = self._next_param("key", json_key)

        if node.op in ("=", "=="):
            return f"JSONExtractString(payload, %({p_key})s) = %({p_val})s"
        elif node.op == "!=":
            return f"JSONExtractString(payload, %({p_key})s) != %({p_val})s"
        elif node.op in (">", "<", ">=", "<="):
            return f"JSONExtractFloat(payload, %({p_key})s) {node.op} %({p_val})s"
        elif node.op == "contains":
            # Highly optimized ClickHouse substring scan inside extracted key or whole payload
            return f"(positionCaseInsensitive(JSONExtractString(payload, %({p_key})s), %({p_val})s) > 0 OR positionCaseInsensitive(payload, %({p_val})s) > 0)"
        elif node.op == "like":
            return f"JSONExtractString(payload, %({p_key})s) ILIKE %({p_val})s"
        elif node.op == "in":
            return f"JSONExtractString(payload, %({p_key})s) IN %({p_val})s"

        return f"positionCaseInsensitive(payload, %({p_val})s) > 0"


def compile_threat_hunt_query(
    query_str: str,
    tenant_id: int = 1,
    limit: int = 100,
    time_range_hours: Optional[int] = 24
) -> Tuple[str, Dict[str, Any]]:
    """Convenience helper to parse and compile a threat hunt query into ClickHouse SQL."""
    ast = parse_query(query_str)
    compiler = ClickHouseQueryCompiler(tenant_id=tenant_id, limit=limit, time_range_hours=time_range_hours)
    return compiler.compile(ast)
