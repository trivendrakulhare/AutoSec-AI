from collections.abc import Mapping


class RulePackNotFoundError(KeyError):
    """Raised when a requested rule-pack name is not registered."""


class RulePackRegistry:
    """Resolve only explicitly registered trusted rule-pack names."""

    def __init__(self, rule_packs: Mapping[str, str]) -> None:
        self._rule_packs = dict(rule_packs)

    def resolve(self, name: str) -> str:
        """Return the configured path for a registered rule-pack name."""
        try:
            return self._rule_packs[name]
        except KeyError as error:
            raise RulePackNotFoundError(
                f"Rule pack is not registered: {name}"
            ) from error