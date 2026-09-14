from .client import LLMClient


class MockLLMClient(LLMClient):
    """Deterministic LLM client that returns a predefined response."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.last_prompt: str | None = None

    def generate(self, prompt: str) -> str:
        """Return the configured response without using the prompt or network."""
        self.last_prompt = prompt
        return self.response

