from dataclasses import dataclass

from .action import AgentAction
from ..tools.registry import ToolRegistry


@dataclass
class ValidationResult:
    """Result of validating an agent action."""

    allowed: bool
    code: str
    reason: str


class ActionValidator:
    """Validates actions proposed by the security agent."""

    def validate(
        self,
        action: AgentAction,
        registry: ToolRegistry,
    ) -> ValidationResult:
        """Validate whether an agent action may be executed."""

        try:
            registry.get(action.tool_name)
        except KeyError:
            return ValidationResult(
                allowed=False,
                code="UNKNOWN_TOOL",
                reason=f"Tool is not registered: {action.tool_name}",
            )

        return ValidationResult(
            allowed=True,
            code="VALID",
            reason="Action is permitted.",
        )