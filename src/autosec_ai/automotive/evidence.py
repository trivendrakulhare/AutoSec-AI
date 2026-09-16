from dataclasses import dataclass

from .models import UDSRequest, UDSResponse


@dataclass(frozen=True)
class VehicleAnalysisEvidence:
    """Immutable observation from one controlled vehicle-analysis probe."""

    target_ecu_identifier: int
    service_id: int
    request_payload: bytes
    response_positive: bool
    response_payload: bytes
    analysis_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.analysis_type, str):
            raise TypeError("analysis_type must be a string")
        if not self.analysis_type:
            raise ValueError("analysis_type must be a non-empty string")

    @classmethod
    def from_exchange(
        cls,
        request: UDSRequest,
        response: UDSResponse,
        analysis_type: str,
    ) -> "VehicleAnalysisEvidence":
        return cls(
            target_ecu_identifier=request.target_ecu_identifier,
            service_id=request.service_id,
            request_payload=request.payload,
            response_positive=response.positive,
            response_payload=response.payload,
            analysis_type=analysis_type,
        )