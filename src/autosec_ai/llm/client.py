from abc import ABC, abstractmethod


class LLMClient(ABC):
    """Provider-neutral interface for generating text from a prompt."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate a text response for the supplied prompt."""
        raise NotImplementedError

