from dataclasses import dataclass
from enum import Enum

from autosec_ai.tools.result import ToolResult

from .investigation import InvestigationState
from .investigation_orchestrator import InvestigationOrchestrator


MAX_INVESTIGATION_STEPS = 10


@dataclass(frozen=True)
class InvestigationRunConfig:
    """Immutable bound for new steps in one investigation run."""

    max_steps: int

    def __post_init__(self) -> None:
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int):
            raise TypeError("max_steps must be an integer")
        if self.max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if self.max_steps > MAX_INVESTIGATION_STEPS:
            raise ValueError(
                f"max_steps cannot exceed {MAX_INVESTIGATION_STEPS}"
            )


class InvestigationTerminationReason(Enum):
    MAX_STEPS_REACHED = "MAX_STEPS_REACHED"
    ACTION_REJECTED = "ACTION_REJECTED"
    TOOL_ERROR = "TOOL_ERROR"


@dataclass(frozen=True)
class InvestigationRunResult:
    """Immutable final state and deterministic reason for run termination."""

    state: InvestigationState
    termination_reason: InvestigationTerminationReason

    def __post_init__(self) -> None:
        if not isinstance(self.state, InvestigationState):
            raise TypeError("state must be an InvestigationState")
        if not isinstance(
            self.termination_reason, InvestigationTerminationReason
        ):
            raise TypeError(
                "termination_reason must be an InvestigationTerminationReason"
            )


class BoundedInvestigationRunner:
    """Run the existing secure single-step primitive within a hard bound."""

    def __init__(
        self,
        orchestrator: InvestigationOrchestrator,
        config: InvestigationRunConfig,
    ) -> None:
        self.orchestrator = orchestrator
        self.config = config

    def run(self, initial_state: InvestigationState) -> InvestigationRunResult:
        if not isinstance(initial_state, InvestigationState):
            raise TypeError("initial_state must be an InvestigationState")

        state = initial_state
        for _ in range(self.config.max_steps):
            state = self.orchestrator.advance(state)
            step = state.steps[-1]
            if not step.validation_allowed:
                return InvestigationRunResult(
                    state=state,
                    termination_reason=InvestigationTerminationReason.ACTION_REJECTED,
                )
            if step.tool_result is not None and _is_tool_error(step.tool_result):
                return InvestigationRunResult(
                    state=state,
                    termination_reason=InvestigationTerminationReason.TOOL_ERROR,
                )

        return InvestigationRunResult(
            state=state,
            termination_reason=InvestigationTerminationReason.MAX_STEPS_REACHED,
        )


def _is_tool_error(result: ToolResult) -> bool:
    return result.status != "success"