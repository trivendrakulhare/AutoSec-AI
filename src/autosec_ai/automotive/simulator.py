from .models import ECU, UDSRequest, UDSResponse


READ_DATA_BY_IDENTIFIER = 0x22
SIMULATED_VIN_IDENTIFIER = 0xF190
SIMULATED_VIN_VALUE = b"TEST-VIN-AUTOSEC-0001"

_NEGATIVE_RESPONSE = 0x7F
_INCORRECT_MESSAGE_LENGTH = 0x13
_REQUEST_OUT_OF_RANGE = 0x31
_SERVICE_NOT_SUPPORTED = 0x11


class SimulatedECU:
    """Deterministic diagnostic ECU that operates only on in-memory values."""

    def __init__(self, ecu: ECU) -> None:
        self.ecu = ecu

    def handle_request(self, request: UDSRequest) -> UDSResponse:
        if request.target_ecu_identifier != self.ecu.identifier:
            return self._negative(request.service_id, _REQUEST_OUT_OF_RANGE)

        if request.service_id != READ_DATA_BY_IDENTIFIER:
            return self._negative(request.service_id, _SERVICE_NOT_SUPPORTED)

        if len(request.payload) != 2:
            return self._negative(request.service_id, _INCORRECT_MESSAGE_LENGTH)

        data_identifier = int.from_bytes(request.payload, byteorder="big")
        if data_identifier != SIMULATED_VIN_IDENTIFIER:
            return self._negative(request.service_id, _REQUEST_OUT_OF_RANGE)

        return UDSResponse(
            target_ecu_identifier=self.ecu.identifier,
            positive=True,
            payload=bytes(
                [READ_DATA_BY_IDENTIFIER + 0x40]
            )
            + request.payload
            + SIMULATED_VIN_VALUE,
        )

    def _negative(self, service_id: int, negative_response_code: int) -> UDSResponse:
        return UDSResponse(
            target_ecu_identifier=self.ecu.identifier,
            positive=False,
            payload=bytes([_NEGATIVE_RESPONSE, service_id, negative_response_code]),
        )