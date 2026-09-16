from .evidence import VehicleAnalysisEvidence
from .models import UDSRequest
from .simulator import SimulatedECU


def perform_uds_probe(
    simulator: SimulatedECU,
    request: UDSRequest,
    analysis_type: str = "single-uds-probe",
) -> VehicleAnalysisEvidence:
    """Perform exactly one in-memory UDS request and retain its observation."""
    response = simulator.handle_request(request)
    return VehicleAnalysisEvidence.from_exchange(request, response, analysis_type)