from __future__ import annotations


class DomainError(Exception):
    """Base class for expected business errors."""


class EntityNotFoundError(DomainError):
    """Raised when a referenced domain entity does not exist."""

