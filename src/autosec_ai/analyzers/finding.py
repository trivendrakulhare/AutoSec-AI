from dataclasses import dataclass


@dataclass
class SecurityFinding:
    """Tool-independent normalized representation of a security finding."""

    rule_id: str
    message: str
    severity: str
    file: str
    line: int | None
    category: str
    cwe: str | None
    source_tool: str