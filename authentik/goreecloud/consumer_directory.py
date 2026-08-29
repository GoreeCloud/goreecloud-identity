"""GoreeCloud-owned consumer directory contract for exact handle resolution.

This module deliberately does not expose browsing, prefix search, fuzzy search,
or an administrative user listing. Consumer applications such as Maps and
Messenger can resolve a user-supplied exact handle only when the account has
explicitly opted into discovery for that requesting GoreeCloud service.

The contract is provider-independent even while the current transition host is
the Identity repository. A future native Identity runtime can preserve this
behavior without preserving any upstream provider implementation detail.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_HANDLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$")
_SERVICE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_MAX_SUBJECT_LENGTH = 255
_MAX_DISPLAY_NAME_LENGTH = 160


class InvalidDirectoryRequest(ValueError):
    """The consumer supplied a syntactically invalid exact-resolution request."""


def normalize_handle(handle: str) -> str:
    """Return the canonical lowercase handle without a leading ``@``.

    Unicode display names remain separate from handles. Restricting the
    canonical routing identifier to a small ASCII alphabet makes equality
    deterministic across clients and avoids confusable normalization being
    performed differently by each GoreeCloud application.
    """

    canonical = str(handle or "").strip()
    if canonical.startswith("@"):
        canonical = canonical[1:]
    canonical = canonical.casefold()
    if not _HANDLE_RE.fullmatch(canonical):
        raise InvalidDirectoryRequest(
            "handle must be 1-32 lowercase letters, numbers, dots, underscores, or hyphens"
        )
    return canonical


def normalize_service_id(service_id: str) -> str:
    canonical = str(service_id or "").strip().casefold()
    if not _SERVICE_ID_RE.fullmatch(canonical):
        raise InvalidDirectoryRequest("requester service id is invalid")
    return canonical


@dataclass(frozen=True, slots=True)
class DirectoryEntry:
    """Internal directory policy state for one Identity subject."""

    subject: str
    handle: str
    display_name: str = ""
    discoverable: bool = False
    allowed_services: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        subject = str(self.subject or "").strip()
        if not subject or len(subject) > _MAX_SUBJECT_LENGTH:
            raise ValueError(
                "subject must be a non-empty opaque identifier up to "
                f"{_MAX_SUBJECT_LENGTH} characters"
            )
        handle = normalize_handle(self.handle)
        display_name = str(self.display_name or "").strip()
        if len(display_name) > _MAX_DISPLAY_NAME_LENGTH:
            raise ValueError(f"display_name must be at most {_MAX_DISPLAY_NAME_LENGTH} characters")
        allowed_services = frozenset(normalize_service_id(item) for item in self.allowed_services)

        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "handle", handle)
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "allowed_services", allowed_services)


@dataclass(frozen=True, slots=True)
class ResolvedDirectoryEntry:
    """Minimum consumer projection returned after discovery policy succeeds."""

    subject: str
    handle: str
    display_name: str = ""


class ExactHandleDirectory:
    """Resolve exact handles without creating an enumerable account directory."""

    def __init__(self, entries: Iterable[DirectoryEntry] = ()) -> None:
        by_handle: dict[str, DirectoryEntry] = {}
        for entry in entries:
            if not isinstance(entry, DirectoryEntry):
                raise TypeError("directory entries must be DirectoryEntry values")
            if entry.handle in by_handle:
                raise ValueError("directory handles must be unique")
            by_handle[entry.handle] = entry
        self._by_handle = by_handle

    def resolve_exact(
        self,
        *,
        requester_service: str,
        handle: str,
    ) -> ResolvedDirectoryEntry | None:
        """Resolve one exact handle under explicit account/service discovery policy.

        ``None`` intentionally represents all non-resolvable states: unknown
        handle, discovery disabled, or requester not authorized. Consumers must
        not receive a signal that distinguishes a private account from an
        account that does not exist.
        """

        service_id = normalize_service_id(requester_service)
        canonical_handle = normalize_handle(handle)
        entry = self._by_handle.get(canonical_handle)
        if entry is None or not entry.discoverable or service_id not in entry.allowed_services:
            return None
        return ResolvedDirectoryEntry(
            subject=entry.subject,
            handle=entry.handle,
            display_name=entry.display_name,
        )
