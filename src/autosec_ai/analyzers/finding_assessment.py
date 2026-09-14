import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any

from autosec_ai.llm.client import LLMClient

from .finding import SecurityFinding


class FindingAssessmentValidationError(ValueError):
    """Raised when an assessment contains invalid structured values."""


class FindingAssessmentParsingError(ValueError):
    """Raised when an LLM response is not a complete valid assessment."""


@dataclass
class FindingAssessment:
    """Structured AI assessment separate from scanner evidence."""

    classification: str
    confidence: str
    rationale: str
    impact: str
    recommendations: list[str]

    VALID_CLASSIFICATIONS = frozenset(
        {
            "confirmed_vulnerability",
            "likely_vulnerability",
            "needs_review",
            "likely_false_positive",
        }
    )
    VALID_CONFIDENCES = frozenset({"high", "medium", "low"})

    def __post_init__(self) -> None:
        if self.classification not in self.VALID_CLASSIFICATIONS:
            raise FindingAssessmentValidationError(
                f"Invalid classification: {self.classification}"
            )
        if self.confidence not in self.VALID_CONFIDENCES:
            raise FindingAssessmentValidationError(
                f"Invalid confidence: {self.confidence}"
            )
        if not isinstance(self.rationale, str) or not self.rationale:
            raise FindingAssessmentValidationError("Rationale must be a non-empty string.")
        if not isinstance(self.impact, str) or not self.impact:
            raise FindingAssessmentValidationError("Impact must be a non-empty string.")
        if not isinstance(self.recommendations, list) or not all(
            isinstance(recommendation, str) for recommendation in self.recommendations
        ):
            raise FindingAssessmentValidationError(
                "Recommendations must be a list of strings."
            )


class FindingAssessor(ABC):
    """Provider-neutral interface for assessing scanner findings."""

    @abstractmethod
    def assess(
        self, finding: SecurityFinding, context: str | None = None
    ) -> FindingAssessment:
        """Assess a finding using only the supplied evidence and context."""
        raise NotImplementedError


class LLMFindingAssessor(FindingAssessor):
    """Assess findings through a provider-neutral language-model client."""

    _REQUIRED_FIELDS = frozenset(
        {"classification", "confidence", "rationale", "impact", "recommendations"}
    )

    def __init__(self, llm_client: LLMClient) -> None:
        self.llm_client = llm_client

    def assess(
        self, finding: SecurityFinding, context: str | None = None
    ) -> FindingAssessment:
        response = self.llm_client.generate(self._build_prompt(finding, context))
        try:
            payload = json.loads(response)
            if not isinstance(payload, dict):
                raise TypeError("assessment must be an object")
            if set(payload) != self._REQUIRED_FIELDS:
                raise ValueError("assessment fields do not match the required schema")
            return FindingAssessment(
                classification=payload["classification"],
                confidence=payload["confidence"],
                rationale=payload["rationale"],
                impact=payload["impact"],
                recommendations=payload["recommendations"],
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            if isinstance(error, FindingAssessmentValidationError):
                detail = str(error)
            else:
                detail = "Malformed assessment response."
            raise FindingAssessmentParsingError(detail) from error

    @staticmethod
    def _build_prompt(
        finding: SecurityFinding, context: str | None
    ) -> str:
        supplied_context = context if context is not None else "<none supplied>"
        return (
            "Assess the security finding below and return only a JSON object with "
            "the fields classification, confidence, rationale, impact, and "
            "recommendations.\n\n"
            "OBSERVED EVIDENCE (scanner/tool finding fields):\n"
            f"{json.dumps(asdict(finding), sort_keys=True)}\n\n"
            "OBSERVED EVIDENCE (supplied source-code/context):\n"
            f"{supplied_context}\n\n"
            "INFERENCE (your assessment only):\n"
            "classification must be one of confirmed_vulnerability, "
            "likely_vulnerability, needs_review, or likely_false_positive. "
            "confidence must be high, medium, or low. Provide a rationale, "
            "impact, and descriptive string recommendations. Do not claim that "
            "anything was observed unless it appears in the supplied evidence "
            "or context. Do not execute tools or propose executable actions."
        )