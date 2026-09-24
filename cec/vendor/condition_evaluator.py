"""MIT donor adaptation: bounded, fully parsed condition expressions.

September 2026 modifications, Copyright RUSSELL PHILIP SMITHSON.
The upstream MIT license is retained alongside this file.
"""
import ast
import math
import re
from typing import Any


class ExpressionError(Exception):
    pass


_LEX = re.compile(
    r"\s*(?:(?P<var>\{\{\w+(?:\.\w+)*\}\})|"
    r"(?P<string>'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")|"
    r"(?P<op>==|!=)|(?P<word>[A-Za-z0-9_.+-]+))"
)


def _scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if type(value) in (int, float) and (not isinstance(value, float) or math.isfinite(value)):
        return str(value)
    raise ExpressionError("condition values must be finite JSON scalars")


def evaluate_condition(expression: str, context: dict[str, Any]) -> bool:
    if not isinstance(expression, str) or not expression.strip():
        raise ExpressionError("condition must be a non-empty string")
    if len(expression) > 4096 or not isinstance(context, dict):
        raise ExpressionError("invalid or oversized condition input")
    tokens, pos = [], 0
    while pos < len(expression.rstrip()):
        match = _LEX.match(expression, pos)
        if not match:
            raise ExpressionError(f"invalid condition syntax at position {pos}")
        tokens.append((match.lastgroup, match.group(match.lastgroup)))
        pos = match.end()
    if len(tokens) > 512:
        raise ExpressionError("too many condition tokens")
    cursor = 0

    def value():
        nonlocal cursor
        if cursor >= len(tokens):
            raise ExpressionError("missing condition operand")
        kind, text = tokens[cursor]
        cursor += 1
        if kind == "op" or (kind == "word" and text in ("and", "or")):
            raise ExpressionError("unexpected condition operator")
        if kind == "var":
            result = context
            for part in text[2:-2].split("."):
                if not isinstance(result, dict) or part not in result:
                    raise ExpressionError("undefined condition variable")
                result = result[part]
            return _scalar(result)
        if kind == "string":
            try:
                return _scalar(ast.literal_eval(text))
            except (ValueError, SyntaxError) as exc:
                raise ExpressionError("invalid quoted string") from exc
        return text.lower() if text.lower() in ("true", "false") else text

    def comparison():
        nonlocal cursor
        left = value()
        if cursor < len(tokens) and tokens[cursor][0] == "op":
            op = tokens[cursor][1]
            cursor += 1
            right = value()
            return left == right if op == "==" else left != right
        if left not in ("true", "false"):
            raise ExpressionError("boolean expression or comparison required")
        return left == "true"

    def conjunction():
        nonlocal cursor
        result = comparison()
        while cursor < len(tokens) and tokens[cursor] == ("word", "and"):
            cursor += 1
            right = comparison()  # Always parse/validate both sides.
            result = result and right
        return result

    result = conjunction()
    while cursor < len(tokens) and tokens[cursor] == ("word", "or"):
        cursor += 1
        right = conjunction()
        result = result or right
    if cursor != len(tokens):
        raise ExpressionError("unexpected trailing condition tokens")
    return result
