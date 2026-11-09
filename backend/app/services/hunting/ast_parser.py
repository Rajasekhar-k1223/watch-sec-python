"""
Safe Query AST Lexer and Parser for Monitorix Threat Hunting.
Supports boolean expressions (AND, OR, NOT), field comparisons (=, !=, >, <, contains, like, in),
nested parentheses, and safe free-text search fallback.
"""

from typing import List, Optional, Any, Union
import re


# AST Node Definitions
class ASTNode:
    pass


class BinaryNode(ASTNode):
    def __init__(self, left: ASTNode, op: str, right: ASTNode):
        self.left = left
        self.op = op.upper()  # AND, OR
        self.right = right

    def __repr__(self):
        return f"BinaryNode({self.left!r}, {self.op}, {self.right!r})"


class UnaryNode(ASTNode):
    def __init__(self, op: str, child: ASTNode):
        self.op = op.upper()  # NOT
        self.child = child

    def __repr__(self):
        return f"UnaryNode({self.op}, {self.child!r})"


class ComparisonNode(ASTNode):
    def __init__(self, field: str, op: str, value: Any):
        self.field = field.strip()
        self.op = op.lower()  # =, !=, >, <, >=, <=, contains, like, in
        self.value = value

    def __repr__(self):
        return f"ComparisonNode({self.field}, {self.op}, {self.value!r})"


class FreeTextNode(ASTNode):
    def __init__(self, text: str):
        self.text = text.strip()

    def __repr__(self):
        return f"FreeTextNode({self.text!r})"


# Tokenizer
TOKEN_SPEC = [
    ("LPAREN",      r"\("),
    ("RPAREN",      r"\)"),
    ("AND",         r"\bAND\b|\band\b"),
    ("OR",          r"\bOR\b|\bor\b"),
    ("NOT",         r"\bNOT\b|\bnot\b"),
    ("CONTAINS",    r"\bCONTAINS\b|\bcontains\b"),
    ("LIKE",        r"\bLIKE\b|\blike\b"),
    ("IN",          r"\bIN\b|\bin\b"),
    ("GTE",         r">="),
    ("LTE",         r"<="),
    ("NEQ",         r"!="),
    ("EQ",          r"==|="),
    ("GT",          r">"),
    ("LT",          r"<"),
    ("STRING",      r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\''),
    ("NUMBER",      r"\b\d+(\.\d+)?\b"),
    ("IDENTIFIER",  r"[a-zA-Z_][a-zA-Z0-9_\.]*"),
    ("WS",          r"\s+"),
    ("OTHER",       r"[^\s()=><!]+"),
]

TOKEN_REGEX = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPEC))


class Token:
    __slots__ = ("type", "value")

    def __init__(self, type_: str, value: str):
        self.type = type_
        self.value = value

    def __repr__(self):
        return f"Token({self.type}, {self.value!r})"


def tokenize(query_str: str) -> List[Token]:
    tokens = []
    for mo in TOKEN_REGEX.finditer(query_str):
        kind = mo.lastgroup
        val = mo.group()
        if kind == "WS":
            continue
        elif kind == "STRING":
            # Strip outer quotes
            val = val[1:-1].replace('\\"', '"').replace("\\'", "'")
            tokens.append(Token("STRING", val))
        else:
            tokens.append(Token(kind, val))
    return tokens


class QueryParser:
    """
    Recursive descent parser for threat hunting query syntax.
    """

    def __init__(self, query_str: str):
        self.query_str = query_str.strip()
        self.tokens = tokenize(self.query_str)
        self.pos = 0

    def current_token(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self, expected_type: Optional[str] = None) -> Optional[Token]:
        tok = self.current_token()
        if not tok:
            return None
        if expected_type and tok.type != expected_type:
            return None
        self.pos += 1
        return tok

    def parse(self) -> ASTNode:
        if not self.tokens:
            return FreeTextNode("")
        try:
            node = self._parse_or()
            if self.pos < len(self.tokens):
                # Unparsed tokens remaining, treat whole query as free text
                return FreeTextNode(self.query_str)
            return node
        except Exception:
            return FreeTextNode(self.query_str)

    def _parse_or(self) -> ASTNode:
        left = self._parse_and()
        while True:
            tok = self.current_token()
            if tok and tok.type == "OR":
                self.consume("OR")
                right = self._parse_and()
                left = BinaryNode(left, "OR", right)
            else:
                break
        return left

    def _parse_and(self) -> ASTNode:
        left = self._parse_not()
        while True:
            tok = self.current_token()
            if tok and tok.type == "AND":
                self.consume("AND")
                right = self._parse_not()
                left = BinaryNode(left, "AND", right)
            else:
                break
        return left

    def _parse_not(self) -> ASTNode:
        tok = self.current_token()
        if tok and tok.type == "NOT":
            self.consume("NOT")
            child = self._parse_not()
            return UnaryNode("NOT", child)
        return self._parse_primary()

    def _parse_primary(self) -> ASTNode:
        tok = self.current_token()
        if not tok:
            return FreeTextNode("")

        if tok.type == "LPAREN":
            self.consume("LPAREN")
            expr = self._parse_or()
            self.consume("RPAREN")
            return expr

        if tok.type in ("IDENTIFIER", "OTHER"):
            # Check if next token is a comparison operator
            if self.pos + 1 < len(self.tokens):
                next_tok = self.tokens[self.pos + 1]
                if next_tok.type in ("EQ", "NEQ", "GT", "LT", "GTE", "LTE", "CONTAINS", "LIKE", "IN"):
                    field_tok = self.consume()
                    op_tok = self.consume()
                    val_tok = self.consume()
                    val = val_tok.value if val_tok else ""
                    if val_tok and val_tok.type == "NUMBER":
                        val = float(val) if "." in val else int(val)
                    op_norm = "=" if op_tok.type == "EQ" else op_tok.value.lower()
                    return ComparisonNode(field_tok.value, op_norm, val)

            # Not a comparison, consume as free text
            self.consume()
            return FreeTextNode(tok.value)

        # Fallback
        self.consume()
        return FreeTextNode(tok.value)


def parse_query(query_str: str) -> ASTNode:
    """Convenience helper to parse a query string into an AST."""
    parser = QueryParser(query_str)
    return parser.parse()

