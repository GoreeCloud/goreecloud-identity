from __future__ import annotations

import pytest

from authentik.goreecloud.consumer_directory import (
    DirectoryEntry,
    ExactHandleDirectory,
    InvalidDirectoryRequest,
    normalize_handle,
)


def test_exact_handle_resolution_returns_minimum_consumer_projection() -> None:
    directory = ExactHandleDirectory(
        [
            DirectoryEntry(
                subject="subject-123",
                handle="@Alice.Example",
                display_name="Alice",
                discoverable=True,
                allowed_services=frozenset({"goreecloud-maps", "goreecloud-messenger"}),
            )
        ]
    )

    result = directory.resolve_exact(requester_service="goreecloud-maps", handle="alice.example")

    assert result is not None
    assert result.subject == "subject-123"
    assert result.handle == "alice.example"
    assert result.display_name == "Alice"
    assert not hasattr(result, "discoverable")
    assert not hasattr(result, "allowed_services")


def test_private_unknown_and_unauthorized_accounts_are_indistinguishable() -> None:
    directory = ExactHandleDirectory(
        [
            DirectoryEntry(
                subject="private-subject",
                handle="private.user",
                discoverable=False,
                allowed_services=frozenset({"goreecloud-maps"}),
            ),
            DirectoryEntry(
                subject="maps-only-subject",
                handle="maps.only",
                discoverable=True,
                allowed_services=frozenset({"goreecloud-maps"}),
            ),
        ]
    )

    assert directory.resolve_exact(requester_service="goreecloud-messenger", handle="private.user") is None
    assert directory.resolve_exact(requester_service="goreecloud-messenger", handle="maps.only") is None
    assert directory.resolve_exact(requester_service="goreecloud-messenger", handle="missing.user") is None


def test_resolution_is_exact_not_prefix_or_fuzzy_search() -> None:
    directory = ExactHandleDirectory(
        [
            DirectoryEntry(
                subject="subject-1",
                handle="alice.example",
                discoverable=True,
                allowed_services=frozenset({"goreecloud-messenger"}),
            )
        ]
    )

    assert directory.resolve_exact(requester_service="goreecloud-messenger", handle="alice") is None
    assert directory.resolve_exact(requester_service="goreecloud-messenger", handle="alice-exampl") is None
    assert directory.resolve_exact(requester_service="goreecloud-messenger", handle="@ALICE.EXAMPLE") is not None


def test_invalid_handles_fail_before_directory_lookup() -> None:
    with pytest.raises(InvalidDirectoryRequest):
        normalize_handle("")
    with pytest.raises(InvalidDirectoryRequest):
        normalize_handle("spaces are not handles")
    with pytest.raises(InvalidDirectoryRequest):
        normalize_handle("a" * 33)


def test_duplicate_canonical_handles_are_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        ExactHandleDirectory(
            [
                DirectoryEntry(subject="subject-1", handle="Alice", discoverable=True),
                DirectoryEntry(subject="subject-2", handle="@alice", discoverable=True),
            ]
        )
