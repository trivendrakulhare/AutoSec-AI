from .action import AgentAction
from .state import AgentState
from .validator import ActionValidator
from ..tools.registry import ToolRegistry


class AgentOrchestrator:
    """Execute validated agent actions and update the agent state."""

    def __init__(
        self,
        state: AgentState,
        registry: ToolRegistry,
        validator: ActionValidator,
    ) -> None:
        self.state = state
        self.registry = registry
        self.validator = validator

    def execute(self, action: AgentAction) -> AgentState:
        """Validate and execute an action, returning the updated state."""
        action_record = f"{action.tool_name}:{action.target}"

        validation = self.validator.validate(action, self.registry)
        if not validation.allowed:
            self.state.observations.append(
                f"Action rejected ({validation.code}): {validation.reason}"
            )
            return self.state

        try:
            tool = self.registry.get(action.tool_name)
            self.state.actions_taken.append(action_record)
            result = tool.execute(action.target)
        except Exception as error:
            self.state.observations.append(
                f"Tool execution failed for {action.tool_name}: {error}"
            )
            return self.state

        if result.error is not None or result.status != "success":
            detail = result.error or f"status={result.status}"
            self.state.observations.append(
                f"Tool execution failed for {action.tool_name}: {detail}"
            )
        else:
            self.state.observations.append(
                f"Tool {action.tool_name} executed successfully for {action.target}."
            )

        return self.state