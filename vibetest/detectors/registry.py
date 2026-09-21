"""Plugin registry. One vulnerability class = one file = one registered detector."""
from __future__ import annotations

from collections.abc import Iterable

from .base import BaseDetector

_REGISTRY: dict[str, type[BaseDetector]] = {}


def register(cls: type[BaseDetector]) -> type[BaseDetector]:
    if cls.id in _REGISTRY:
        raise ValueError(f"duplicate detector id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_detectors() -> dict[str, type[BaseDetector]]:
    return dict(_REGISTRY)


def enabled(ids: Iterable[str] | None = None) -> list[BaseDetector]:
    if ids is None:
        classes = _REGISTRY.values()
    else:
        classes = (_REGISTRY[i] for i in ids)  # KeyError on unknown id = loud failure, good
    return [cls() for cls in classes]
