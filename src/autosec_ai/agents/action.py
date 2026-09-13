from dataclasses import dataclass


@dataclass
class AgentAction:
    """Represents an action selected by the security agent."""

    tool_name: str
    target: str
