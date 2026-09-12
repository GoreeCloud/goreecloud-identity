#!/usr/bin/env python3
"""Validate the native GoreeCloud Identity account-model source contract."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTRACT = Path("contracts/native-account-model.v1.json")
EXPECTED_SCHEMA = "goreecloud.identity.native-account-model/v1"
EXPECTED_LIFECYCLE = ["invited", "active", "disabled", "archived"]


class ContractError(ValueError):
    pass


def load_contract(path: Path = CONTRACT) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError("native account model must be a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_identity_kinds(contract: dict[str, Any]) -> None:
    kinds = contract.get("identityKinds")
    require(isinstance(kinds, dict), "identityKinds object is required")
    require(set(kinds) == {"human", "administrator", "service"}, "identity kinds must be closed")

    human = kinds["human"]
    administrator = kinds["administrator"]
    service = kinds["service"]
    require(isinstance(human, dict), "human identity contract is required")
    require(isinstance(administrator, dict), "administrator identity contract is required")
    require(isinstance(service, dict), "service identity contract is required")
    require(human.get("canonical") is True, "human identity must be canonical")
    require(
        human.get("administratorIdentityDistinct") is True,
        "administrator identity must remain distinct from ordinary human identity",
    )
    require(human.get("supportsMultipleUsers") is True, "multi-user human identity is required")
    require(administrator.get("canonical") is True, "administrator identity must be canonical")
    require(
        administrator.get("humanIdentityRequired") is True,
        "administrator identity must bind to a human identity",
    )
    require(
        administrator.get("separatePrivileges") is True,
        "administrator privileges must remain explicit and separate",
    )
    require(service.get("canonical") is True, "service identity must be canonical")
    require(
        service.get("humanIdentityRequired") is False,
        "service identities must not masquerade as human identities",
    )
    require(
        service.get("separateCredentialLifecycle") is True,
        "service identities require a separate credential lifecycle",
    )


def validate_registration(contract: dict[str, Any]) -> None:
    policy = contract.get("registrationPolicy")
    require(isinstance(policy, dict), "registrationPolicy object is required")
    require(policy.get("defaultMode") == "invite_only", "registration must default to invite-only")
    require(
        policy.get("administratorCreatedAccounts") is True,
        "administrator-created accounts must remain supported",
    )
    self_registration = policy.get("selfRegistration")
    require(isinstance(self_registration, dict), "selfRegistration policy is required")
    require(
        self_registration.get("defaultEnabled") is False,
        "self-registration must remain disabled by default",
    )
    require(
        self_registration.get("operatorMayEnable") is True,
        "operators must be able to explicitly enable self-registration",
    )
    require(
        self_registration.get("explicitConfigurationRequired") is True,
        "self-registration enablement must require explicit configuration",
    )


def validate_lifecycle_and_data_boundary(contract: dict[str, Any]) -> None:
    lifecycle = contract.get("humanAccountLifecycle")
    require(lifecycle == EXPECTED_LIFECYCLE, "human account lifecycle states drifted")

    disablement = contract.get("disablement")
    require(isinstance(disablement, dict), "disablement policy is required")
    require(
        disablement.get("newAuthenticationDenied") is True,
        "disabled accounts must deny new authentication",
    )
    require(
        disablement.get("activeSessionsRequireRevocationEvaluation") is True,
        "disablement must trigger session revocation evaluation",
    )
    require(
        disablement.get("applicationOwnedDataDeletionAuthorized") is False,
        "Identity disablement must not authorize application-data deletion",
    )
    require(
        disablement.get("applicationOwnedDataOwnershipTransferred") is False,
        "Identity disablement must not transfer application-data ownership",
    )


def validate_migration_boundary(contract: dict[str, Any]) -> None:
    migration = contract.get("migrationBoundary")
    require(isinstance(migration, dict), "migrationBoundary object is required")
    require(
        migration.get("inheritedRuntime") == "transitional_reference_only",
        "inherited runtime must remain transitional reference infrastructure",
    )
    require(
        migration.get("inheritedObjectNamesCanonical") is False,
        "inherited object names must not become canonical GoreeCloud Identity names",
    )
    require(migration.get("nativeMigrationRequired") is True, "native migration must remain required")
    require(
        migration.get("silentIdentityRebindingAllowed") is False,
        "migration must not silently rebind identity",
    )
    require(
        migration.get("applicationOwnedDataPreserved") is True,
        "application-owned data must be preserved across identity migration",
    )


def validate_contract(contract: dict[str, Any]) -> None:
    require(contract.get("schemaVersion") == EXPECTED_SCHEMA, "unexpected account-model schema")
    require(contract.get("lifecycle") == "development", "account-model lifecycle must be development")
    require(
        contract.get("canonicalAuthority") == "GoreeCloud Identity",
        "canonical identity authority must be GoreeCloud Identity",
    )
    require(
        contract.get("architecture") == "goreecloud-owned-native",
        "canonical architecture must be GoreeCloud-owned native",
    )
    require(
        contract.get("runtimeImplementationState") == "contract_only",
        "source contract must not claim a completed native runtime",
    )
    require(
        contract.get("productionAccepted") is False,
        "source contract must not claim production acceptance",
    )
    require(contract.get("authorityTransfer") is False, "Identity authority must not transfer")
    validate_identity_kinds(contract)
    validate_registration(contract)
    validate_lifecycle_and_data_boundary(contract)
    validate_migration_boundary(contract)


def main() -> int:
    try:
        validate_contract(load_contract())
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"native Identity account-model validation failed: {exc}")
        return 1
    print("native GoreeCloud Identity account-model source contract validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
