from __future__ import annotations

import json
from pathlib import Path

import pytest

from authentik.goreecloud.consumer_directory import (
    DirectoryEntry,
    ExactHandleDirectory,
    InvalidDirectoryRequest,
    normalize_handle,
)


CONTRACT_PATH = Path(__file__).parents[2] / "contracts" / "consumer-directory.v1.json"


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


def test_network_contract_cannot_client_assert_requester_or_enumerate_directory() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    assert contract["contract_id"] == "goreecloud-identity.consumer-directory.v1"
    assert contract["request"]["method"] == "POST"
    assert contract["request"]["path"] == "/v1/consumer-directory/resolve"
    assert contract["request"]["body"]["required_fields"] == ["handle"]
    assert contract["request"]["body"]["allowed_fields"] == ["handle"]
    assert contract["request"]["authentication"]["requester_service_source"] == "verified_service_principal"
    assert contract["request"]["authentication"]["requester_service_must_not_be_client_supplied"] is True

    unresolved = contract["responses"]["not_resolved"]
    assert unresolved["status"] == 404
    assert unresolved["body"]["error"]["code"] == "not_resolved"
    assert set(unresolved["indistinguishable_conditions"]) == {
        "handle does not exist",
        "account is not discoverable",
        "verified requesting service is not authorized for disclosure",
    }

    privacy = contract["privacy_requirements"]
    assert privacy["exact_match_only"] is True
    assert privacy["prefix_search_prohibited"] is True
    assert privacy["fuzzy_search_prohibited"] is True
    assert privacy["directory_browse_prohibited"] is True
    assert privacy["administrative_listing_prohibited"] is True
    assert privacy["email_or_phone_disclosure_prohibited"] is True
    assert privacy["uniform_negative_response_required"] is True

    assert contract["responses"]["resolved"]["body_fields"] == ["subject", "handle", "display_name"]
