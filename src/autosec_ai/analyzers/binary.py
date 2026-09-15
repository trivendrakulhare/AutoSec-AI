from abc import ABC, abstractmethod

from autosec_ai.analyzers.finding import SecurityFinding


class BinaryAnalyzer(ABC):
    """Analyze binary targets and return normalized security findings."""

    @abstractmethod
    def analyze(self, target: str) -> list[SecurityFinding]:
        """Analyze a binary target and return its security findings."""
        raise NotImplementedError