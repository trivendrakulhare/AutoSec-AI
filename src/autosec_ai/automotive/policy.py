from dataclasses import dataclass


MIN_DATA_IDENTIFIER = 0x0000
MAX_DATA_IDENTIFIER = 0xFFFF


@dataclass(frozen=True)
class DiagnosticDataPolicy:
    """Describes whether a diagnostic data identifier requires authorization."""

    data_identifier: int
    authorization_required: bool

    def __post_init__(self) -> None:
        if isinstance(self.data_identifier, bool) or not isinstance(
            self.data_identifier, int
        ):
            raise TypeError("data_identifier must be an integer")
        if not MIN_DATA_IDENTIFIER <= self.data_identifier <= MAX_DATA_IDENTIFIER:
            raise ValueError("data_identifier must fit in two bytes")
        if not isinstance(self.authorization_required, bool):
            raise TypeError("authorization_required must be a boolean")