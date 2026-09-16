from abc import ABC, abstractmethod

from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.automotive.models import ECU


class VehicleAnalyzer(ABC):
    """Analyze an automotive target and return normalized security findings."""

    @abstractmethod
    def analyze(self, target: ECU) -> list[SecurityFinding]:
        """Analyze an ECU target without prescribing vehicle-specific tools."""
        raise NotImplementedError