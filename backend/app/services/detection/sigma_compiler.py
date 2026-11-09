"""
Monitorix Enterprise Native Sigma YAML Compiler & Evaluation Engine
===================================================================
Module: backend/app/services/detection/sigma_compiler.py
Phase: 5.4.3A Foundation

Features:
1. Safe YAML loading (yaml.safe_load) with strict schema validation.
2. Complete Sigma field modifier support:
   - contains, endswith, startswith, equals, exists, re, contains|all, endswith|all
3. Pure Abstract Syntax Tree (AST) condition parser (recursive descent):
   - AND, OR, NOT, Parenthesized grouping, Quantifiers (1 of X, all of X, 1 of them).
   - Strictly ZERO eval(), exec(), or arbitrary code execution.
4. Compiled Rule Registry with content-hash invalidation and sub-millisecond evaluation.
5. Strict Multi-Tenant Isolation: Global system rules vs. Tenant-scoped rules.
6. Robust event normalization across Agent, SIEM, and ECS telemetry formats.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import math
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml

logger = logging.getLogger("SigmaCompiler")


# ===========================================================================
# 1. Custom Exceptions
# ===========================================================================

class SigmaCompilationError(Exception):
    """Raised when a Sigma rule fails syntax, schema, or condition validation."""

    def __init__(
        self,
        message: str,
        rule_title: Optional[str] = None,
        field: Optional[str] = None,
        error_type: str = "ValidationError"
    ):
        super().__init__(message)
        self.message = message
        self.rule_title = rule_title or "Unknown"
        self.field = field
        self.error_type = error_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.error_type,
            "message": self.message,
            "rule_title": self.rule_title,
            "field": self.field,
        }

    def __str__(self) -> str:
        ctx = f" [Rule: '{self.rule_title}']" if self.rule_title else ""
        fld = f" [Field: '{self.field}']" if self.field else ""
        return f"SigmaCompilationError({self.error_type}): {self.message}{ctx}{fld}"


class SigmaEvaluationError(Exception):
    """Raised when an unrecoverable error occurs during event evaluation."""
    pass


# ===========================================================================
# 2. Data Models & Evaluation Results
# ===========================================================================

@dataclass
class DetectionResult:
    """Standardized result emitted by evaluating an event against a compiled rule."""
    matched: bool
    rule_id: Union[int, str]
    rule_name: str
    severity: str
    category: str
    matched_selections: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    event_identifier: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evaluation_error: Optional[str] = None
    evaluation_time_us: float = 0.0

    @property
    def rule_title(self) -> str:
        return self.rule_name

    @property
    def matched_fields(self) -> Dict[str, Any]:
        return self.details

    @property
    def mitre_tactic(self) -> str:
        return ", ".join(self.mitre_tactics) if self.mitre_tactics else ""

    @property
    def mitre_technique(self) -> str:
        return ", ".join(self.mitre_techniques) if self.mitre_techniques else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "matched_selections": self.matched_selections,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "event_identifier": self.event_identifier,
            "details": self.details,
            "evaluation_error": self.evaluation_error,
            "evaluation_time_us": self.evaluation_time_us,
        }


# ===========================================================================
# 3. Field Extraction & Aliasing
# ===========================================================================

CANONICAL_FIELD_GROUPS: List[List[str]] = [
    [
        "commandline", "cmdline", "command_line", "process.command_line",
        "CommandLine", "triggering_event.command_line"
    ],
    [
        "image", "targetimage", "process_name", "processname", "process.executable",
        "Image", "TargetImage", "file_name"
    ],
    [
        "parentimage", "parent_process_name", "parentprocessname",
        "process.parent.executable", "ParentImage"
    ],
    [
        "parentcommandline", "parent_cmdline", "parent_command_line",
        "ParentCommandLine"
    ],
    [
        "user", "username", "user_name", "user.name", "ActiveUser", "active_user", "User"
    ],
    [
        "destinationport", "destination_port", "dst_port", "remote_port",
        "DestinationPort"
    ],
    [
        "destinationip", "destination_ip", "dst_ip", "remote_ip", "RemoteIp",
        "DestinationIp"
    ],
    [
        "sourceport", "source_port", "src_port", "SourcePort"
    ],
    [
        "sourceip", "source_ip", "src_ip", "SourceIp"
    ],
    [
        "targetfilename", "filepath", "file_path", "path", "file.path",
        "TargetFilename", "FilePath"
    ],
    [
        "hashes", "sha256", "SHA256", "md5", "MD5", "hash"
    ],
]

# Inverted index: maps any known alias (lowercase) to its entire synonym family
FIELD_ALIASES: Dict[str, List[str]] = {}
for group in CANONICAL_FIELD_GROUPS:
    for item in group:
        FIELD_ALIASES[item.lower()] = group


def extract_field_value(event: Any, field_name: str) -> Tuple[bool, Any]:
    """
    Safely resolves field values from raw or normalized event dictionaries.
    Returns (field_exists: bool, resolved_value: Any).
    """
    if not isinstance(event, dict):
        return False, None

    # 1. Direct exact key match
    if field_name in event:
        return True, event[field_name]

    # 2. Case-insensitive direct match
    lower_map = {k.lower(): k for k in event.keys()}
    f_lower = field_name.lower()
    if f_lower in lower_map:
        return True, event[lower_map[f_lower]]

    # 3. Canonical alias resolution
    aliases = FIELD_ALIASES.get(f_lower, [])
    for alias in aliases:
        if alias in event:
            return True, event[alias]
        a_lower = alias.lower()
        if a_lower in lower_map:
            return True, event[lower_map[a_lower]]
        if "." in alias:
            parts = alias.split(".")
            curr = event
            nested_found = True
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                elif isinstance(curr, dict) and p.lower() in {k.lower(): k for k in curr.keys()}:
                    curr = curr[{k.lower(): k for k in curr.keys()}[p.lower()]]
                else:
                    nested_found = False
                    break
            if nested_found:
                return True, curr

    # 4. Inspection of nested sub-dictionaries (Payload, triggering_event, Details)
    for container_key in ("Payload", "payload", "triggering_event", "Details"):
        sub = event.get(container_key)
        if isinstance(sub, dict):
            found, val = extract_field_value(sub, field_name)
            if found:
                return True, val

    # 5. Dot-separated path lookup (e.g. process.name)
    if "." in field_name:
        parts = field_name.split(".")
        curr = event
        found = True
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                found = False
                break
        if found:
            return True, curr

    return False, None


# ===========================================================================
# 4. Field Matcher Hierarchy
# ===========================================================================

class Matcher(ABC):
    """Abstract base class for a field value condition."""

    @abstractmethod
    def matches(self, actual_value: Any, exists: bool) -> bool:
        """Evaluates whether the actual event value satisfies this matcher."""
        pass


class ExistsMatcher(Matcher):
    def __init__(self, should_exist: bool):
        self.should_exist = should_exist

    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists:
            return not self.should_exist
        if actual_value is None:
            return not self.should_exist
        if isinstance(actual_value, str) and not actual_value.strip():
            return not self.should_exist
        return self.should_exist


class StringMatcher(Matcher):
    """Base class for string operations with case-insensitivity."""

    def __init__(self, target_values: List[str], case_sensitive: bool = False):
        self.case_sensitive = case_sensitive
        if case_sensitive:
            self.targets = [str(t) for t in target_values]
        else:
            self.targets = [str(t).lower() for t in target_values]

    def _normalize(self, val: Any) -> Optional[str]:
        if val is None:
            return None
        s = str(val)
        return s if self.case_sensitive else s.lower()


class ContainsMatcher(StringMatcher):
    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists:
            return False
        norm = self._normalize(actual_value)
        if norm is None:
            return False
        # Disjunction (OR) over targets
        return any(t in norm for t in self.targets)


class ContainsAllMatcher(StringMatcher):
    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists:
            return False
        norm = self._normalize(actual_value)
        if norm is None:
            return False
        # Conjunction (AND) over targets
        return all(t in norm for t in self.targets)


class EndsWithMatcher(StringMatcher):
    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists:
            return False
        norm = self._normalize(actual_value)
        if norm is None:
            return False
        return any(norm.endswith(t) for t in self.targets)


class EndsWithAllMatcher(StringMatcher):
    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists:
            return False
        norm = self._normalize(actual_value)
        if norm is None:
            return False
        return all(norm.endswith(t) for t in self.targets)


class StartsWithMatcher(StringMatcher):
    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists:
            return False
        norm = self._normalize(actual_value)
        if norm is None:
            return False
        return any(norm.startswith(t) for t in self.targets)


class EqualsMatcher(Matcher):
    """Exact equality matcher with wildcard/glob support."""

    def __init__(self, target_values: List[Any], case_sensitive: bool = False):
        self.case_sensitive = case_sensitive
        self.raw_targets = target_values
        self.patterns = []
        for t in target_values:
            if isinstance(t, str) and ("*" in t or "?" in t):
                pat = t if case_sensitive else t.lower()
                self.patterns.append(("glob", pat))
            elif isinstance(t, str):
                self.patterns.append(("str", t if case_sensitive else t.lower()))
            else:
                self.patterns.append(("val", t))

    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists or actual_value is None:
            return False

        for kind, expected in self.patterns:
            if kind == "glob":
                actual_str = str(actual_value) if self.case_sensitive else str(actual_value).lower()
                if fnmatch.fnmatch(actual_str, expected):
                    return True
            elif kind == "str":
                actual_str = str(actual_value) if self.case_sensitive else str(actual_value).lower()
                if actual_str == expected:
                    return True
            elif kind == "val":
                if actual_value == expected:
                    return True
                # Numeric string fallback
                try:
                    if str(actual_value) == str(expected):
                        return True
                except Exception:
                    pass
        return False


class RegexMatcher(Matcher):
    def __init__(self, patterns: List[str]):
        self.compiled = []
        for p in patterns:
            try:
                self.compiled.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                raise SigmaCompilationError(f"Invalid regular expression '{p}': {e}", error_type="RegexSyntaxError")

    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists or actual_value is None:
            return False
        val_str = str(actual_value)
        return any(rx.search(val_str) is not None for rx in self.compiled)


class NumericCompareMatcher(Matcher):
    """Handles comparison expressions such as '>50', '>=9.0', '<100'."""

    def __init__(self, op: str, threshold: float):
        self.op = op
        self.threshold = threshold

    def matches(self, actual_value: Any, exists: bool) -> bool:
        if not exists or actual_value is None:
            return False
        # Security Guard: Booleans must NEVER be treated as numeric values (Python: isinstance(True, int) is True)
        if isinstance(actual_value, bool):
            return False
        # Security Guard: Filter special string representations of non-finite numbers
        if isinstance(actual_value, str) and actual_value.strip().lower() in ("nan", "inf", "-inf", "+inf"):
            return False
        try:
            val = float(actual_value)
            if math.isnan(val) or math.isinf(val):
                return False
            if self.op == ">":
                return val > self.threshold
            elif self.op == ">=":
                return val >= self.threshold
            elif self.op == "<":
                return val < self.threshold
            elif self.op == "<=":
                return val <= self.threshold
            elif self.op == "==":
                return val == self.threshold
        except (ValueError, TypeError):
            return False
        return False


# ===========================================================================
# 5. Selection Matcher
# ===========================================================================

class SelectionMatcher:
    """Evaluates a single named Sigma selection block against an event."""

    def __init__(self, name: str, field_matchers: List[Tuple[str, Matcher]]):
        self.name = name
        self.field_matchers = field_matchers  # AND across all field conditions in block

    def matches(self, event: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        details = {}
        for field_name, matcher in self.field_matchers:
            exists, actual_val = extract_field_value(event, field_name)
            if not matcher.matches(actual_val, exists):
                return False, {}
            details[field_name] = actual_val
        return True, details


# ===========================================================================
# 6. Condition AST & Safe Recursive-Descent Parser
# ===========================================================================

class ConditionNode(ABC):
    @abstractmethod
    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        pass


class LiteralNode(ConditionNode):
    def __init__(self, value: bool):
        self.value = value

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return self.value


class SelectionRefNode(ConditionNode):
    def __init__(self, name: str):
        self.name = name

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        if self.name not in selection_results:
            raise SigmaEvaluationError(f"Condition referenced unknown selection: '{self.name}'")
        return selection_results[self.name]


class QuantifierNode(ConditionNode):
    """Handles expressions such as '1 of selection*', 'all of selection*', '1 of them'."""

    def __init__(self, mode: str, pattern: str):
        self.mode = mode.lower()  # '1', 'all', 'any'
        self.pattern = pattern

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        if self.pattern == "them":
            # 'them' matches all selections except those starting with 'filter'
            matching_keys = [k for k in selection_results.keys() if not k.lower().startswith("filter")]
        else:
            pat = self.pattern.lower()
            matching_keys = [k for k in selection_results.keys() if fnmatch.fnmatch(k.lower(), pat)]

        if not matching_keys:
            # If no selections match the quantifier pattern, evaluate to False
            return False

        trues = sum(1 for k in matching_keys if selection_results[k])

        if self.mode in ("1", "any", "at_least_one"):
            return trues >= 1
        elif self.mode == "all":
            return trues == len(matching_keys)
        else:
            try:
                target_count = int(self.mode)
                return trues >= target_count
            except ValueError:
                return False


class NotNode(ConditionNode):
    def __init__(self, child: ConditionNode):
        self.child = child

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return not self.child.evaluate(selection_results)


class AndNode(ConditionNode):
    def __init__(self, left: ConditionNode, right: ConditionNode):
        self.left = left
        self.right = right

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return self.left.evaluate(selection_results) and self.right.evaluate(selection_results)


class OrNode(ConditionNode):
    def __init__(self, left: ConditionNode, right: ConditionNode):
        self.left = left
        self.right = right

    def evaluate(self, selection_results: Dict[str, bool]) -> bool:
        return self.left.evaluate(selection_results) or self.right.evaluate(selection_results)


class ConditionParser:
    """
    Pure Python recursive descent parser for Sigma condition expressions.
    Grammar:
      expr   := or_expr
      or_expr  := and_expr ('or' and_expr)*
      and_expr := not_expr ('and' not_expr)*
      not_expr := 'not' not_expr | primary
      primary  := '(' expr ')' | quantifier | selection_ref
    """

    def __init__(self, raw_condition: str, available_selections: Set[str], rule_title: str):
        self.raw = raw_condition.strip()
        self.available_selections = set(available_selections)
        self.rule_title = rule_title
        self.tokens: List[Tuple[str, str]] = []
        self.pos = 0

    def parse(self) -> ConditionNode:
        self.tokens = self._tokenize(self.raw)
        self.pos = 0
        if not self.tokens:
            raise SigmaCompilationError("Empty condition expression", rule_title=self.rule_title, field="condition")

        ast = self._parse_or()
        if self.pos < len(self.tokens):
            unexpected = self.tokens[self.pos][1]
            raise SigmaCompilationError(
                f"Unexpected token '{unexpected}' in condition at position {self.pos}",
                rule_title=self.rule_title,
                field="condition"
            )
        return ast

    def _tokenize(self, text: str) -> List[Tuple[str, str]]:
        tokens: List[Tuple[str, str]] = []
        i = 0
        n = len(text)

        while i < n:
            c = text[i]
            if c.isspace():
                i += 1
                continue
            if c == '(':
                tokens.append(('LPAREN', '('))
                i += 1
            elif c == ')':
                tokens.append(('RPAREN', ')'))
                i += 1
            else:
                # Read word / quantifier phrase
                start = i
                while i < n and not text[i].isspace() and text[i] not in '()':
                    i += 1
                word = text[start:i]

                # Check for quantifier phrase: '1 of ...', 'all of ...', 'any of ...'
                lower_word = word.lower()
                if lower_word in ("1", "all", "any") and i < n:
                    # Look ahead for 'of'
                    rest = text[i:].lstrip()
                    if rest.lower().startswith("of ") or rest.lower().startswith("of\t"):
                        # Consume 'of' and target
                        parts = rest.split(None, 2)
                        if len(parts) >= 2 and parts[0].lower() == "of":
                            target = parts[1]
                            # Clean target if it ends with parenthesis
                            if target.endswith(")"):
                                target = target.rstrip(")")
                                offset = len(rest) - len(rest[len(parts[0]):].lstrip()[len(target):])
                                i += offset
                            else:
                                i += len(text[i:]) - len(rest[len(parts[0]):].lstrip()[len(target):])
                            tokens.append(('QUANTIFIER', f"{lower_word} of {target}"))
                            continue

                if lower_word == "and":
                    tokens.append(('AND', 'and'))
                elif lower_word == "or":
                    tokens.append(('OR', 'or'))
                elif lower_word == "not":
                    tokens.append(('NOT', 'not'))
                else:
                    tokens.append(('IDENTIFIER', word))
        return tokens

    def _peek(self) -> Optional[Tuple[str, str]]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _consume(self, expected_type: Optional[str] = None) -> Tuple[str, str]:
        if self.pos >= len(self.tokens):
            raise SigmaCompilationError(
                f"Unexpected end of condition expression in '{self.raw}'",
                rule_title=self.rule_title,
                field="condition"
            )
        tok = self.tokens[self.pos]
        if expected_type and tok[0] != expected_type:
            raise SigmaCompilationError(
                f"Expected {expected_type} but found '{tok[1]}' in condition",
                rule_title=self.rule_title,
                field="condition"
            )
        self.pos += 1
        return tok

    def _parse_or(self) -> ConditionNode:
        node = self._parse_and()
        while self._peek() and self._peek()[0] == 'OR':
            self._consume('OR')
            right = self._parse_and()
            node = OrNode(node, right)
        return node

    def _parse_and(self) -> ConditionNode:
        node = self._parse_not()
        while self._peek() and self._peek()[0] == 'AND':
            self._consume('AND')
            right = self._parse_not()
            node = AndNode(node, right)
        return node

    def _parse_not(self) -> ConditionNode:
        if self._peek() and self._peek()[0] == 'NOT':
            self._consume('NOT')
            child = self._parse_not()
            return NotNode(child)
        return self._parse_primary()

    def _parse_primary(self) -> ConditionNode:
        tok = self._peek()
        if not tok:
            raise SigmaCompilationError(
                "Incomplete expression in condition",
                rule_title=self.rule_title,
                field="condition"
            )

        if tok[0] == 'LPAREN':
            self._consume('LPAREN')
            sub = self._parse_or()
            self._consume('RPAREN')
            return sub

        if tok[0] == 'QUANTIFIER':
            self._consume('QUANTIFIER')
            # Format: 'mode of target'
            parts = tok[1].split(" of ")
            mode = parts[0].strip()
            target = parts[1].strip()
            return QuantifierNode(mode, target)

        if tok[0] == 'IDENTIFIER':
            self._consume('IDENTIFIER')
            val = tok[1]
            # Check wildcard shorthand, e.g. 'selection_*' -> 1 of selection_*
            if "*" in val:
                return QuantifierNode("1", val)

            # Strict verification of defined selections
            if val not in self.available_selections:
                raise SigmaCompilationError(
                    f"Condition references undefined selection '{val}'. Available: {sorted(list(self.available_selections))}",
                    rule_title=self.rule_title,
                    field="condition"
                )
            return SelectionRefNode(val)

        raise SigmaCompilationError(
            f"Invalid condition token: '{tok[1]}'",
            rule_title=self.rule_title,
            field="condition"
        )


# ===========================================================================
# 7. Compiled Sigma Rule Model
# ===========================================================================

@dataclass
class CompiledSigmaRule:
    """Represents an in-memory, pre-compiled, and validated Sigma detection rule."""
    id: Union[int, str]
    name: str
    severity: str
    category: str
    logsource: Dict[str, Any]
    selections: Dict[str, SelectionMatcher]
    condition_ast: ConditionNode
    raw_condition: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    tenant_id: Optional[int] = None
    is_active: bool = True
    content_hash: str = ""
    compiled_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)

    @property
    def mitre_tactics(self) -> List[str]:
        if self.mitre_tactic:
            return [self.mitre_tactic]
        return [t for t in self.tags if "attack." in t]

    @property
    def mitre_techniques(self) -> List[str]:
        if self.mitre_technique:
            return [self.mitre_technique]
        return [t for t in self.tags if "attack.t" in t]


# ===========================================================================
# 8. Sigma Compiler Engine
# ===========================================================================

class SigmaCompiler:
    """
    Validates, parses, and compiles Sigma YAML documents into executable detection ASTs.
    """

    MANDATORY_FIELDS = ["title", "detection"]
    SUPPORTED_MODIFIERS = {
        "contains", "endswith", "startswith", "equals", "exists", "re",
        "all", "cased", "gt", "gte", "lt", "lte", "min", "max"
    }

    def compile(
        self,
        yaml_content: str,
        rule_id: Optional[Union[int, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CompiledSigmaRule:
        """Compiles raw Sigma YAML string into a CompiledSigmaRule."""
        if not yaml_content or not yaml_content.strip():
            raise SigmaCompilationError("Rule content is empty", error_type="EmptyRuleError")

        # 1. Safe YAML Ingestion (with fallback sanitization for unquoted asterisk globs)
        try:
            doc = yaml.safe_load(yaml_content)
        except yaml.YAMLError as y_err:
            # Check if failure was caused by unquoted asterisk glob (e.g. TargetImage: *\lsass.exe)
            if "scanning an alias" in str(y_err) or "found unknown escape character" in str(y_err):
                try:
                    sanitized_content = re.sub(r'(:\s*)(\*[^\s\"\'\#][^\r\n]*)', r"\1'\2'", yaml_content)
                    doc = yaml.safe_load(sanitized_content)
                except Exception:
                    raise SigmaCompilationError(f"YAML Syntax Error: {y_err}", error_type="YAMLParseError")
            else:
                raise SigmaCompilationError(f"YAML Syntax Error: {y_err}", error_type="YAMLParseError")

        if not isinstance(doc, dict):
            raise SigmaCompilationError("Sigma rule must be a top-level YAML mapping/dictionary", error_type="SchemaError")

        # 2. Mandatory Fields Validation
        for req in self.MANDATORY_FIELDS:
            if req not in doc or not doc[req]:
                raise SigmaCompilationError(
                    f"Missing mandatory Sigma field: '{req}'",
                    rule_title=doc.get("title", "Unknown"),
                    field=req,
                    error_type="MissingMandatoryField"
                )

        title = str(doc["title"]).strip()
        detection = doc["detection"]
        if not isinstance(detection, dict):
            raise SigmaCompilationError(
                "'detection' must be a YAML mapping containing selections and a 'condition'",
                rule_title=title,
                field="detection",
                error_type="SchemaError"
            )

        if "condition" not in detection or not detection["condition"]:
            raise SigmaCompilationError(
                "Missing mandatory 'condition' field within 'detection'",
                rule_title=title,
                field="condition",
                error_type="MissingCondition"
            )

        # 3. Metadata Extraction & Synthesis
        r_id = rule_id or doc.get("id") or doc.get("rule_id") or hashlib.sha256(title.encode()).hexdigest()[:12]
        severity = doc.get("level", "Medium").capitalize()
        category = "Threat Detection"
        logsource = doc.get("logsource", {})
        if isinstance(logsource, dict):
            category = logsource.get("category", logsource.get("product", "Threat Detection"))

        mitre_tactic = None
        mitre_technique = None
        tags = doc.get("tags", [])
        if isinstance(tags, list):
            for t in tags:
                t_str = str(t).lower()
                if t_str.startswith("attack.t"):
                    mitre_technique = t_str.replace("attack.", "").upper()
                elif t_str.startswith("attack."):
                    mitre_tactic = t_str.replace("attack.", "").capitalize()

        # Database metadata override if provided
        tenant_id = None
        is_active = True
        if metadata:
            if "Id" in metadata:
                r_id = metadata["Id"]
            elif "id" in metadata:
                r_id = metadata["id"]

            if "Name" in metadata and metadata["Name"]:
                title = metadata["Name"]
            elif "name" in metadata and metadata["name"]:
                title = metadata["name"]

            if "Severity" in metadata and metadata["Severity"]:
                severity = metadata["Severity"]
            elif "severity" in metadata and metadata["severity"]:
                severity = metadata["severity"]

            if "Category" in metadata and metadata["Category"]:
                category = metadata["Category"]
            elif "category" in metadata and metadata["category"]:
                category = metadata["category"]

            if "MitreTactic" in metadata and metadata["MitreTactic"]:
                mitre_tactic = metadata["MitreTactic"]
            elif "mitre_tactic" in metadata and metadata["mitre_tactic"]:
                mitre_tactic = metadata["mitre_tactic"]

            if "MitreTechnique" in metadata and metadata["MitreTechnique"]:
                mitre_technique = metadata["MitreTechnique"]
            elif "mitre_technique" in metadata and metadata["mitre_technique"]:
                mitre_technique = metadata["mitre_technique"]

            if "TenantId" in metadata:
                tenant_id = metadata["TenantId"]
            elif "tenant_id" in metadata:
                tenant_id = metadata["tenant_id"]

            if "IsActive" in metadata:
                is_active = bool(metadata["IsActive"])
            elif "is_active" in metadata:
                is_active = bool(metadata["is_active"])

        # 4. Selection Compilation
        selections: Dict[str, SelectionMatcher] = {}
        for sel_name, sel_content in detection.items():
            if sel_name == "condition":
                continue

            matcher = self._compile_selection(sel_name, sel_content, title)
            selections[sel_name] = matcher

        if not selections:
            raise SigmaCompilationError(
                "Rule contains no valid detection selections",
                rule_title=title,
                field="detection",
                error_type="EmptySelectionsError"
            )

        # 5. Condition AST Compilation
        raw_cond = str(detection["condition"]).strip()
        cond_parser = ConditionParser(raw_cond, set(selections.keys()), title)
        cond_ast = cond_parser.parse()

        # 6. Content Hash for Cache Invalidation
        content_hash = hashlib.sha256(yaml_content.encode("utf-8")).hexdigest()

        return CompiledSigmaRule(
            id=r_id,
            name=title,
            severity=severity,
            category=category,
            logsource=logsource if isinstance(logsource, dict) else {},
            selections=selections,
            condition_ast=cond_ast,
            raw_condition=raw_cond,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            tenant_id=tenant_id,
            is_active=is_active,
            content_hash=content_hash,
            compiled_at=datetime.utcnow(),
            tags=tags if isinstance(tags, list) else []
        )

    def _compile_selection(self, name: str, content: Any, rule_title: str) -> SelectionMatcher:
        """Parses a single selection dictionary or list into an executable SelectionMatcher."""
        matchers: List[Tuple[str, Matcher]] = []

        if isinstance(content, dict):
            for field_spec, val in content.items():
                parsed_field, matcher = self._build_matcher(field_spec, val, rule_title)
                matchers.append((parsed_field, matcher))
        elif isinstance(content, list):
            # Keyword search across default commandline/image
            keywords = [str(x) for x in content]
            matcher = ContainsMatcher(keywords)
            matchers.append(("CommandLine", matcher))
        else:
            raise SigmaCompilationError(
                f"Selection '{name}' must be a mapping of fields or list of keywords, got {type(content).__name__}",
                rule_title=rule_title,
                field=name,
                error_type="SelectionSchemaError"
            )

        return SelectionMatcher(name, matchers)

    def _build_matcher(self, field_spec: str, value: Any, rule_title: str) -> Tuple[str, Matcher]:
        """Constructs the appropriate Matcher for a field|modifier expression."""
        parts = field_spec.split("|")
        base_field = parts[0].strip()
        modifiers = [p.strip().lower() for p in parts[1:]]

        # Validate modifiers
        for m in modifiers:
            if m not in self.SUPPORTED_MODIFIERS:
                raise SigmaCompilationError(
                    f"Unsupported Sigma modifier '{m}' in field '{field_spec}'",
                    rule_title=rule_title,
                    field=base_field,
                    error_type="UnsupportedModifier"
                )

        # Check 'exists' modifier
        if "exists" in modifiers:
            bool_val = True
            if isinstance(value, bool):
                bool_val = value
            elif isinstance(value, str):
                bool_val = value.lower() in ("true", "1", "yes")
            return base_field, ExistsMatcher(bool_val)

        # Check numeric modifier in field specifier (e.g. |gt, |gte, |lt, |lte, |min, |max)
        num_mod_map = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "min": ">=", "max": "<="}
        for mod, op in num_mod_map.items():
            if mod in modifiers:
                if isinstance(value, bool):
                    raise SigmaCompilationError(
                        f"Numeric modifier '{mod}' cannot accept boolean value '{value}' in field '{field_spec}'",
                        rule_title=rule_title,
                        field=base_field,
                        error_type="InvalidNumericThreshold"
                    )
                try:
                    thresh = float(value)
                    if math.isnan(thresh) or math.isinf(thresh):
                        raise ValueError("Threshold cannot be NaN or Infinite")
                except (ValueError, TypeError) as ve:
                    raise SigmaCompilationError(
                        f"Invalid numeric threshold '{value}' for modifier '{mod}' in field '{field_spec}': {ve}",
                        rule_title=rule_title,
                        field=base_field,
                        error_type="InvalidNumericThreshold"
                    )
                return base_field, NumericCompareMatcher(op, thresh)

        # Check numeric comparison in plain value (e.g. ">50", ">=9.0")
        if isinstance(value, str) and re.match(r"^(>=|<=|>|<|==)\s*([0-9\.]+)$", value.strip()):
            m_comp = re.match(r"^(>=|<=|>|<|==)\s*([0-9\.]+)$", value.strip())
            op = m_comp.group(1)
            try:
                thresh = float(m_comp.group(2))
                if math.isnan(thresh) or math.isinf(thresh):
                    raise ValueError("Threshold cannot be NaN or Infinite")
                return base_field, NumericCompareMatcher(op, thresh)
            except (ValueError, TypeError) as ve:
                raise SigmaCompilationError(
                    f"Invalid numeric threshold '{m_comp.group(2)}' in expression '{value}': {ve}",
                    rule_title=rule_title,
                    field=base_field,
                    error_type="InvalidNumericThreshold"
                )

        # Normalize target values to list
        if isinstance(value, list):
            target_vals = value
        else:
            target_vals = [value]

        # 'all' combination modifier
        is_all = "all" in modifiers
        case_sensitive = "cased" in modifiers

        if "re" in modifiers:
            str_pats = [str(v) for v in target_vals]
            return base_field, RegexMatcher(str_pats)

        if "contains" in modifiers:
            str_vals = [str(v) for v in target_vals]
            if is_all:
                return base_field, ContainsAllMatcher(str_vals, case_sensitive)
            return base_field, ContainsMatcher(str_vals, case_sensitive)

        if "endswith" in modifiers:
            str_vals = [str(v) for v in target_vals]
            if is_all:
                return base_field, EndsWithAllMatcher(str_vals, case_sensitive)
            return base_field, EndsWithMatcher(str_vals, case_sensitive)

        if "startswith" in modifiers:
            str_vals = [str(v) for v in target_vals]
            return base_field, StartsWithMatcher(str_vals, case_sensitive)

        if "equals" in modifiers:
            return base_field, EqualsMatcher(target_vals, case_sensitive)

        # Default: EqualsMatcher (supports glob wildcards like * and ?)
        return base_field, EqualsMatcher(target_vals, case_sensitive)


# ===========================================================================
# 9. Detection Evaluation Interface
# ===========================================================================

def evaluate_event(
    event: Dict[str, Any],
    rule: CompiledSigmaRule,
    authoritative_tenant_id: Optional[int] = None
) -> DetectionResult:
    """
    Evaluates a single normalized telemetry event against a compiled Sigma rule.
    Safe: guaranteed never to throw an unhandled exception or crash the caller.
    """
    t0 = time.perf_counter()

    # Multi-tenant isolation check
    if authoritative_tenant_id is not None and rule.tenant_id is not None:
        if rule.tenant_id != authoritative_tenant_id:
            # Rule does not belong to the event's tenant
            return DetectionResult(
                matched=False,
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                category=rule.category,
                evaluation_time_us=(time.perf_counter() - t0) * 1_000_000
            )

    if not rule.is_active:
        return DetectionResult(
            matched=False,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            evaluation_time_us=(time.perf_counter() - t0) * 1_000_000
        )

    # Malformed event guard
    if not isinstance(event, dict):
        return DetectionResult(
            matched=False,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            evaluation_error="Malformed event: expected dictionary",
            evaluation_time_us=(time.perf_counter() - t0) * 1_000_000
        )

    try:
        # Evaluate each selection
        selection_results: Dict[str, bool] = {}
        matched_details: Dict[str, Any] = {}
        matched_sel_names: List[str] = []

        for sel_name, sel_matcher in rule.selections.items():
            sel_matched, details = sel_matcher.matches(event)
            selection_results[sel_name] = sel_matched
            if sel_matched:
                matched_sel_names.append(sel_name)
                matched_details[sel_name] = details

        # Evaluate condition AST
        matched = rule.condition_ast.evaluate(selection_results)

        ev_id = str(event.get("event_id") or event.get("Id") or event.get("id") or "")
        dur_us = (time.perf_counter() - t0) * 1_000_000

        tactics = [rule.mitre_tactic] if rule.mitre_tactic else []
        techniques = [rule.mitre_technique] if rule.mitre_technique else []

        return DetectionResult(
            matched=matched,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            matched_selections=matched_sel_names if matched else [],
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            event_identifier=ev_id,
            details=matched_details if matched else {},
            evaluation_time_us=dur_us
        )

    except Exception as eval_err:
        dur_us = (time.perf_counter() - t0) * 1_000_000
        logger.warning(f"[SigmaEvaluator] Evaluation exception on rule '{rule.name}' (#{rule.id}): {eval_err}")
        return DetectionResult(
            matched=False,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            evaluation_error=str(eval_err),
            evaluation_time_us=dur_us
        )


def evaluate_all(
    event: Dict[str, Any],
    rules: List[CompiledSigmaRule],
    authoritative_tenant_id: Optional[int] = None
) -> List[DetectionResult]:
    """Evaluates an event across an ordered list of compiled rules."""
    results: List[DetectionResult] = []
    for r in rules:
        res = evaluate_event(event, r, authoritative_tenant_id)
        if res.matched:
            results.append(res)
    return results


# ===========================================================================
# 10. Compiled Rule Registry & Lifecycle Cache
# ===========================================================================

class SigmaRuleRegistry:
    """
    High-throughput in-memory cache and registry for compiled Sigma rules.
    Features:
    - Content-hash invalidation avoiding unnecessary recompilation.
    - Tenant partitioning (Global vs. Tenant-specific).
    - Failure tracking and metrics reporting.
    """

    def __init__(self):
        self._rules: Dict[Union[int, str], CompiledSigmaRule] = {}
        self._compiler = SigmaCompiler()
        self.compilation_errors: Dict[Union[int, str], str] = {}
        self.total_evaluations: int = 0
        self.total_matches: int = 0

    def register_rule(
        self,
        yaml_content: str,
        rule_id: Optional[Union[int, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CompiledSigmaRule:
        """Compiles and registers a rule, or returns the cached instance if content unchanged."""
        calc_hash = hashlib.sha256(yaml_content.encode("utf-8")).hexdigest()
        lookup_id = rule_id or (metadata.get("Id") if metadata else None)

        # Check existing cached instance with same content hash
        if lookup_id is not None and lookup_id in self._rules:
            existing = self._rules[lookup_id]
            if existing.content_hash == calc_hash:
                # Update metadata if changed without recompilation
                if metadata:
                    if "IsActive" in metadata:
                        existing.is_active = bool(metadata["IsActive"])
                    elif "is_active" in metadata:
                        existing.is_active = bool(metadata["is_active"])
                    if "TenantId" in metadata:
                        existing.tenant_id = metadata["TenantId"]
                    elif "tenant_id" in metadata:
                        existing.tenant_id = metadata["tenant_id"]
                    if "Severity" in metadata and metadata["Severity"]:
                        existing.severity = metadata["Severity"]
                    elif "severity" in metadata and metadata["severity"]:
                        existing.severity = metadata["severity"]
                return existing

        # Compile rule
        try:
            compiled = self._compiler.compile(yaml_content, rule_id=lookup_id, metadata=metadata)
            self._rules[compiled.id] = compiled
            if compiled.id in self.compilation_errors:
                del self.compilation_errors[compiled.id]
            return compiled
        except SigmaCompilationError as comp_err:
            key = lookup_id or "unnamed_rule"
            self.compilation_errors[key] = comp_err.message
            raise

    def invalidate_rule(self, rule_id: Union[int, str]):
        """Removes a rule from the cache."""
        if rule_id in self._rules:
            del self._rules[rule_id]
        if rule_id in self.compilation_errors:
            del self.compilation_errors[rule_id]

    def clear(self):
        """Clears all cached rules."""
        self._rules.clear()
        self.compilation_errors.clear()

    def get_rule(self, rule_id: Union[int, str]) -> Optional[CompiledSigmaRule]:
        return self._rules.get(rule_id)

    def get_active_rules(self, tenant_id: Optional[int] = None) -> List[CompiledSigmaRule]:
        """Returns active rules matching the requested tenant scope."""
        active: List[CompiledSigmaRule] = []
        for r in self._rules.values():
            if not r.is_active:
                continue
            if tenant_id is None:
                # All rules
                active.append(r)
            else:
                # Global rules + tenant's own rules
                if r.tenant_id is None or r.tenant_id == tenant_id:
                    active.append(r)
        return active

    def get_rules_for_tenant(self, tenant_id: Optional[int] = None) -> List[CompiledSigmaRule]:
        """Alias for get_active_rules."""
        return self.get_active_rules(tenant_id=tenant_id)

    def evaluate_all(self, event: Dict[str, Any], tenant_id: Optional[int] = None) -> List[DetectionResult]:
        """Evaluates event across all active rules registered for the given tenant."""
        rules = self.get_active_rules(tenant_id=tenant_id)
        return evaluate_all(event, rules, authoritative_tenant_id=tenant_id)

    def register(
        self,
        rule: Union[CompiledSigmaRule, str],
        rule_id: Optional[Union[int, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CompiledSigmaRule:
        """Convenience registration accepting either an already-compiled CompiledSigmaRule or raw YAML string."""
        if isinstance(rule, CompiledSigmaRule):
            self._rules[rule.id] = rule
            return rule
        return self.register_rule(rule, rule_id=rule_id, metadata=metadata)

    def count(self) -> int:
        return len(self._rules)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "cached_rules_count": len(self._rules),
            "failed_rules_count": len(self.compilation_errors),
            "total_evaluations": self.total_evaluations,
            "total_matches": self.total_matches,
        }


# Global singleton instances
sigma_compiler = SigmaCompiler()
sigma_registry = SigmaRuleRegistry()
