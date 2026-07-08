"""A small case-insensitive multi-valued mapping for headers and query params."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping


class MultiDict:
    """An ordered, case-insensitive mapping that allows repeated keys."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] | None = None) -> None:
        self._items: list[tuple[str, str]] = list(items) if items is not None else []

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, str]) -> MultiDict:
        return cls(mapping.items())

    def get(self, key: str, default: str | None = None) -> str | None:
        lowered = key.lower()
        for k, v in self._items:
            if k.lower() == lowered:
                return v
        return default

    def get_all(self, key: str) -> list[str]:
        lowered = key.lower()
        return [v for k, v in self._items if k.lower() == lowered]

    def add(self, key: str, value: str) -> None:
        self._items.append((key, value))

    def items(self) -> Iterator[tuple[str, str]]:
        return iter(self._items)

    def __contains__(self, key: str) -> bool:
        lowered = key.lower()
        return any(k.lower() == lowered for k, _ in self._items)

    def __iter__(self) -> Iterator[str]:
        return (k for k, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)
