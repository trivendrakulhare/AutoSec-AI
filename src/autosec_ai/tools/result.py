from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    """Normalized result returned by a security tool."""

    tool_name: str
    target: str
    status: str
    data: Any = None
    error: str | None = None
