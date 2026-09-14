from abc import ABC, abstractmethod

from autosec_ai.analyzers.finding import SecurityFinding


class SourceCodeAnalyzer(ABC):
    """Analyze source-code targets and return normalized security findings."""

    @abstractmethod
    def analyze(self, target: str) -> list[SecurityFinding]:
        """Analyze a source-code target and return its security findings."""
        raise NotImplementedError