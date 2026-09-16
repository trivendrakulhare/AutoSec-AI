from .models import ECU, UDSRequest, UDSResponse
from .policy import DiagnosticDataPolicy


READ_DATA_BY_IDENTIFIER = 0x22
SIMULATED_VIN_IDENTIFIER = 0xF190
SIMULATED_VIN_VALUE = b"TEST-VIN-AUTOSEC-0001"
SIMULATED_PROTECTED_IDENTIFIER = 0xF1A0
SIMULATED_PROTECTED_VALUE = b"SYNTHETIC-PROTECTED-DATA"

_NEGATIVE_RESPONSE = 0x7F
_INCORRECT_MESSAGE_LENGTH = 0x13
_REQUEST_OUT_OF_RANGE = 0x31
_SERVICE_NOT_SUPPORTED = 0x11
_SECURITY_ACCESS_DENIED = 0x33


class SimulatedECU:
    """Deterministic diagnostic ECU that operates only on in-memory values."""

    def __init__(
        self,
        ecu: ECU,
        protected_data_policy: DiagnosticDataPolicy | None = None,
        allow_unauthenticated_protected_data: bool = False,
    ) -> None:
        self.ecu = ecu
        self.protected_data_policy = protected_data_policy or DiagnosticDataPolicy(
            SIMULATED_PROTECTED_IDENTIFIER, authorization_required=True
        )
        if not isinstance(allow_unauthenticated_protected_data, bool):
            raise TypeError("allow_unauthenticated_protected_data must be a boolean")
        self.allow_unauthenticated_protected_data = (
            allow_unauthenticated_protected_data
        )

    def handle_request(self, request: UDSRequest) -> UDSResponse:
        if request.target_ecu_identifier != self.ecu.identifier:
            return self._negative(request.service_id, _REQUEST_OUT_OF_RANGE)

        if request.service_id != READ_DATA_BY_IDENTIFIER:
            return self._negative(request.service_id, _SERVICE_NOT_SUPPORTED)

        if len(request.payload) != 2:
            return self._negative(request.service_id, _INCORRECT_MESSAGE_LENGTH)

        data_identifier = int.from_bytes(request.payload, byteorder="big")
        if data_identifier == SIMULATED_VIN_IDENTIFIER:
            return self._positive_read(request, SIMULATED_VIN_VALUE)

        if data_identifier != self.protected_data_policy.data_identifier:
            return self._negative(request.service_id, _REQUEST_OUT_OF_RANGE)

        if self.protected_data_policy.authorization_required and not (
            self.allow_unauthenticated_protected_data
        ):
            # Simplified simulation decision; no real authentication is performed.
            return self._negative(request.service_id, _SECURITY_ACCESS_DENIED)

        return self._positive_read(request, SIMULATED_PROTECTED_VALUE)

    def _positive_read(self, request: UDSRequest, value: bytes) -> UDSResponse:
        return UDSResponse(
            target_ecu_identifier=self.ecu.identifier,
            positive=True,
            payload=bytes([READ_DATA_BY_IDENTIFIER + 0x40])
            + request.payload
            + value,
        )

    def _negative(self, service_id: int, negative_response_code: int) -> UDSResponse:
        return UDSResponse(
            target_ecu_identifier=self.ecu.identifier,
            positive=False,
            payload=bytes([_NEGATIVE_RESPONSE, service_id, negative_response_code]),
        )