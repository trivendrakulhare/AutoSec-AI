from abc import ABC, abstractmethod

from autosec_ai.analyzers.context import FindingContext
from autosec_ai.tools.result import ToolResult

from .action import AgentAction


class InvestigationResultProcessor(ABC):
    """Convert one trusted tool result into normalized deterministic evidence."""

    @abstractmethod
    def process(
        self, action: AgentAction, result: ToolResult
    ) -> FindingContext | None:
        raise NotImplementedError


class InvestigationResultProcessorRegistry:
    """Exact application-configured mapping from tool names to processors."""

    def __init__(self) -> None:
        self._processors: dict[str, InvestigationResultProcessor] = {}

    def register(
        self, tool_name: str, processor: InvestigationResultProcessor
    ) -> None:
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(processor, InvestigationResultProcessor):
            raise TypeError(
                "processor must be an InvestigationResultProcessor"
            )
        if tool_name in self._processors:
            raise ValueError(f"Processor already registered: {tool_name}")
        self._processors[tool_name] = processor

    def get(self, tool_name: str) -> InvestigationResultProcessor | None:
        return self._processors.get(tool_name)