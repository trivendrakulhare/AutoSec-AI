import os
from typing import Any

from openai import OpenAI

from .client import LLMClient


class OpenAIConfigurationError(ValueError):
    """Raised when the OpenAI client configuration is incomplete."""


class OpenAIRequestError(RuntimeError):
    """Raised when an OpenAI request cannot be completed."""


class OpenAIClient(LLMClient):
    """Generate text through OpenAI's Responses API."""

    DEFAULT_MODEL = "gpt-5.6-luna"

    def __init__(self, model: str | None = None, sdk_client: Any | None = None) -> None:
        self.model = (
            model if model is not None else os.getenv("OPENAI_MODEL") or self.DEFAULT_MODEL
        )

        if sdk_client is not None:
            self._client = sdk_client
            return

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise OpenAIConfigurationError(
                "OPENAI_API_KEY is required to create an OpenAI client."
            )
        self._client = OpenAI(api_key=api_key)

    def generate(self, prompt: str) -> str:
        """Send a prompt to the Responses API and return its text output."""
        try:
            response = self._client.responses.create(
                model=self.model,
                input=prompt,
            )
            return response.output_text
        except Exception:
            raise OpenAIRequestError("OpenAI request failed.")