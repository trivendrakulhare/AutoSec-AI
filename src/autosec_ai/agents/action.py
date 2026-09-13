from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentAction:
    """Represents a structured action selected by the security agent."""

    tool_name: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
