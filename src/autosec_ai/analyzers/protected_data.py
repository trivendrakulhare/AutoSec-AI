from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.automotive.evidence import VehicleAnalysisEvidence
from autosec_ai.automotive.policy import DiagnosticDataPolicy
from autosec_ai.automotive.probe import perform_uds_probe
from autosec_ai.automotive.simulator import (
    READ_DATA_BY_IDENTIFIER,
    SIMULATED_PROTECTED_VALUE,
    SimulatedECU,
)
from autosec_ai.automotive.models import ECU, UDSRequest

from .vehicle import VehicleAnalyzer


class ProtectedDataVehicleAnalyzer(VehicleAnalyzer):
    """Check one diagnostic policy by making one unauthenticated UDS probe."""

    def __init__(self, simulator: SimulatedECU, policy: DiagnosticDataPolicy) -> None:
        if simulator.protected_data_policy != policy:
            raise ValueError(
                "analyzer policy must match the simulator protected-data policy"
            )
        self.simulator = simulator
        self.policy = policy
        self.last_evidence: VehicleAnalysisEvidence | None = None

    def analyze(self, target: ECU) -> list[SecurityFinding]:
        if target.identifier != self.simulator.ecu.identifier:
            raise ValueError("analysis target must match the simulator ECU identifier")
        request = UDSRequest(
            target_ecu_identifier=target.identifier,
            service_id=READ_DATA_BY_IDENTIFIER,
            payload=self.policy.data_identifier.to_bytes(2, byteorder="big"),
        )
        self.last_evidence = perform_uds_probe(
            self.simulator, request, "unauthenticated-protected-data-probe"
        )

        if not self.policy.authorization_required:
            return []
        if not self.last_evidence.response_positive:
            return []
        expected_response = (
            bytes([READ_DATA_BY_IDENTIFIER + 0x40])
            + request.payload
            + SIMULATED_PROTECTED_VALUE
        )
        if self.last_evidence.response_payload != expected_response:
            return []

        return [
            SecurityFinding(
                rule_id="VEH-UDS-PROTECTED-DATA-UNAUTH",
                message=(
                    "An unauthenticated ReadDataByIdentifier request returned "
                    "data marked as authorization-required by the diagnostic policy."
                ),
                severity="HIGH",
                file=target.name,
                line=None,
                category="diagnostic-access-control",
                cwe=None,
                source_tool="vehicle-simulator",
            )
        ]