from dataclasses import dataclass


MIN_ECU_IDENTIFIER = 0x000
MAX_ECU_IDENTIFIER = 0x7FF
MAX_CAN_PAYLOAD_LENGTH = 8


def _validate_ecu_identifier(identifier: int) -> None:
    if isinstance(identifier, bool) or not isinstance(identifier, int):
        raise TypeError("ECU identifier must be an integer")
    if not MIN_ECU_IDENTIFIER <= identifier <= MAX_ECU_IDENTIFIER:
        raise ValueError("ECU identifier must fit in 11 bits")


def _validate_payload(payload: bytes, maximum_length: int | None = None) -> None:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if maximum_length is not None and len(payload) > maximum_length:
        raise ValueError(f"payload must be at most {maximum_length} bytes")


@dataclass(frozen=True)
class ECU:
    """An in-memory ECU identity."""

    identifier: int
    name: str

    def __post_init__(self) -> None:
        _validate_ecu_identifier(self.identifier)
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("ECU name must be a non-empty string")


@dataclass(frozen=True)
class CANMessage:
    """A validated classic CAN message without any transport behavior."""

    arbitration_id: int
    payload: bytes

    def __post_init__(self) -> None:
        _validate_ecu_identifier(self.arbitration_id)
        _validate_payload(self.payload, MAX_CAN_PAYLOAD_LENGTH)


@dataclass(frozen=True)
class UDSRequest:
    """A validated in-memory UDS request."""

    target_ecu_identifier: int
    service_id: int
    payload: bytes

    def __post_init__(self) -> None:
        _validate_ecu_identifier(self.target_ecu_identifier)
        if isinstance(self.service_id, bool) or not isinstance(self.service_id, int):
            raise TypeError("service_id must be an integer")
        if not 0x00 <= self.service_id <= 0xFF:
            raise ValueError("service_id must fit in one byte")
        _validate_payload(self.payload)


@dataclass(frozen=True)
class UDSResponse:
    """A validated in-memory UDS response."""

    target_ecu_identifier: int
    positive: bool
    payload: bytes

    def __post_init__(self) -> None:
        _validate_ecu_identifier(self.target_ecu_identifier)
        if not isinstance(self.positive, bool):
            raise TypeError("positive must be a boolean")
        _validate_payload(self.payload)