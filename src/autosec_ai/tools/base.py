from abc import ABC, abstractmethod
from .result import ToolResult


class SecurityTool(ABC):
    """Base interface for tools available to the security agent."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the security tool."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a human-readable description of the tool."""
        raise NotImplementedError

    @abstractmethod
    def execute(self, target: str) -> "ToolResult":
        """Execute the tool against a controlled target."""
        raise NotImplementedError
