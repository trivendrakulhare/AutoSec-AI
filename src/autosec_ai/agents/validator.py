from dataclasses import dataclass
from numbers import Real

from .action import AgentAction
from .policy import SecurityPolicy
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
        policy: SecurityPolicy,
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

        if action.tool_name not in policy.allowed_tools:
            return ValidationResult(
                allowed=False,
                code="UNAUTHORIZED_TOOL",
                reason=f"Tool is not authorized: {action.tool_name}",
            )

        if action.target not in policy.allowed_targets:
            return ValidationResult(
                allowed=False,
                code="UNAUTHORIZED_TARGET",
                reason=f"Target is not authorized: {action.target}",
            )

        tool_limits = policy.parameter_limits.get(action.tool_name, {})
        if isinstance(tool_limits, dict):
            for parameter_name, value in action.parameters.items():
                maximum = tool_limits.get(parameter_name)
                if not isinstance(maximum, Real) or isinstance(maximum, bool):
                    continue
                if not isinstance(value, Real) or isinstance(value, bool):
                    continue
                try:
                    exceeds_limit = value > maximum
                except TypeError:
                    continue
                if exceeds_limit:
                    return ValidationResult(
                        allowed=False,
                        code="RESOURCE_LIMIT_EXCEEDED",
                        reason=(
                            f"Parameter exceeds limit: {action.tool_name}."
                            f"{parameter_name}"
                        ),
                    )

        return ValidationResult(
            allowed=True,
            code="VALID",
            reason="Action is permitted.",
        )
