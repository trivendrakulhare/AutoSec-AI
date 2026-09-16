from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.automotive.fuzzing import MutationType, UDSFuzzEvidence
from autosec_ai.automotive.policy import DiagnosticDataPolicy
from autosec_ai.automotive.simulator import (
    READ_DATA_BY_IDENTIFIER,
    SIMULATED_PROTECTED_VALUE,
)


class UDSFuzzResponseAnalyzer:
    """Interpret completed UDS fuzz evidence against the protected-data invariant."""

    def __init__(
        self,
        policy: DiagnosticDataPolicy,
        expected_protected_value: bytes = SIMULATED_PROTECTED_VALUE,
    ) -> None:
        if not isinstance(expected_protected_value, bytes):
            raise TypeError("expected_protected_value must be bytes")
        self.policy = policy
        self.expected_protected_value = expected_protected_value

    def analyze(self, evidence: list[UDSFuzzEvidence]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for item in evidence:
            if self.policy.authorization_required is not True:
                continue
            if item.mutation_type is not MutationType.VALID_DID:
                continue
            if item.request_service_id != READ_DATA_BY_IDENTIFIER:
                continue
            if item.request_payload != self.policy.data_identifier.to_bytes(
                2, byteorder="big"
            ):
                continue
            if item.response_positive is not True:
                continue
            expected = (
                bytes([READ_DATA_BY_IDENTIFIER + 0x40])
                + item.request_payload
                + self.expected_protected_value
            )
            if item.response_payload != expected:
                continue
            findings.append(
                SecurityFinding(
                    rule_id="VEH-UDS-PROTECTED-DATA-UNAUTH",
                    message=(
                        "An unauthenticated ReadDataByIdentifier request returned "
                        "data that the policy marks as authorization-required."
                    ),
                    severity="HIGH",
                    file="simulated-ecu",
                    line=None,
                    category="diagnostic-access-control",
                    cwe=None,
                    source_tool="vehicle-simulator",
                )
            )
        return findings
