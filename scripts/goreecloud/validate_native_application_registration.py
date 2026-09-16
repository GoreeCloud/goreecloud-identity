#!/usr/bin/env python3
"""Validate the GoreeCloud Identity native application-registration source contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

CONTRACT = Path("contracts/native-application-registration.v1.json")
EXPECTED_SCHEMA = "goreecloud.identity.native-application-registration/v1"
TOP_LEVEL_KEYS = {
    "schemaVersion",
    "lifecycle",
    "canonicalAuthority",
    "runtimeImplementationState",
    "productionAccepted",
    "registrationRecord",
    "redirectPolicy",
    "audienceAndScopePolicy",
    "lifecyclePolicy",
    "consumerBoundary",
    "registrations",
    "emptyRegistryMeansNoRuntimeRegistrations",
    "authorityTransfer",
}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def closed_object(value: object, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} object is required")
    section = cast(dict[str, Any], value)
    require(set(section) == keys, f"{name} fields must be closed and exact")
    return section


def require_flags(
    section: dict[str, Any],
    *,
    required_true: tuple[str, ...] = (),
    required_false: tuple[str, ...] = (),
    name: str,
) -> None:
    for key in required_true:
        require(section.get(key) is True, f"{name}.{key} must remain required")
    for key in required_false:
        require(section.get(key) is False, f"{name}.{key} must remain prohibited")


def require_contract_only(section: dict[str, Any], name: str) -> None:
    require(
        section.get("runtimeAccepted") is False,
        f"{name} must not claim runtime acceptance",
    )


def load_contract() -> dict[str, Any]:
    value: object = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError("native registration contract must be a JSON object")
    return cast(dict[str, Any], value)


def validate_contract(contract: dict[str, Any]) -> None:
    require(
        set(contract) == TOP_LEVEL_KEYS,
        "native registration top-level fields must be closed and exact",
    )
    require(
        contract.get("schemaVersion") == EXPECTED_SCHEMA,
        "unexpected native registration schema",
    )
    require(
        contract.get("lifecycle") == "development",
        "native registration lifecycle must remain development",
    )
    require(
        contract.get("canonicalAuthority") == "GoreeCloud Identity",
        "canonical authority must remain GoreeCloud Identity",
    )
    require(
        contract.get("runtimeImplementationState") == "contract_only",
        "registration runtime must remain contract-only",
    )
    require(
        contract.get("productionAccepted") is False,
        "registration contract must not claim production acceptance",
    )
    require(
        contract.get("authorityTransfer") is False,
        "Identity registration authority must not transfer",
    )

    record = closed_object(
        contract.get("registrationRecord"),
        {
            "requiredFields",
            "exactStringFields",
            "stringNormalizationAllowed",
            "blankOrControlBearingIdentifiersAllowed",
            "publicNativeClientRequired",
            "embeddedClientSecretAllowed",
            "oneRegistrationPerApplicationAudienceRequired",
            "runtimeAccepted",
        },
        "registrationRecord",
    )
    require(
        record.get("requiredFields")
        == [
            "applicationId",
            "clientId",
            "audience",
            "redirectUris",
            "allowedScopes",
            "enabled",
        ],
        "registration required fields drifted",
    )
    require(
        record.get("exactStringFields")
        == ["applicationId", "clientId", "audience"],
        "registration exact string fields drifted",
    )
    require_flags(
        record,
        required_true=(
            "publicNativeClientRequired",
            "oneRegistrationPerApplicationAudienceRequired",
        ),
        required_false=(
            "stringNormalizationAllowed",
            "blankOrControlBearingIdentifiersAllowed",
            "embeddedClientSecretAllowed",
        ),
        name="registrationRecord",
    )
    require_contract_only(record, "registrationRecord")

    redirects = closed_object(
        contract.get("redirectPolicy"),
        {
            "exactRegistrationRequired",
            "wildcardRedirectAllowed",
            "userinfoAllowed",
            "fragmentAllowed",
            "httpsRequiredOutsideExplicitLoopbackDevelopment",
            "loopbackDevelopmentMustBeExplicit",
            "runtimeAccepted",
        },
        "redirectPolicy",
    )
    require_flags(
        redirects,
        required_true=(
            "exactRegistrationRequired",
            "httpsRequiredOutsideExplicitLoopbackDevelopment",
            "loopbackDevelopmentMustBeExplicit",
        ),
        required_false=(
            "wildcardRedirectAllowed",
            "userinfoAllowed",
            "fragmentAllowed",
        ),
        name="redirectPolicy",
    )
    require_contract_only(redirects, "redirectPolicy")

    authority = closed_object(
        contract.get("audienceAndScopePolicy"),
        {
            "exactAudienceRequired",
            "audienceReuseAcrossUnrelatedApplicationsAllowed",
            "explicitAllowedScopesRequired",
            "wildcardScopeAllowed",
            "clientMayExpandBeyondRegisteredScopes",
            "runtimeAccepted",
        },
        "audienceAndScopePolicy",
    )
    require_flags(
        authority,
        required_true=(
            "exactAudienceRequired",
            "explicitAllowedScopesRequired",
        ),
        required_false=(
            "audienceReuseAcrossUnrelatedApplicationsAllowed",
            "wildcardScopeAllowed",
            "clientMayExpandBeyondRegisteredScopes",
        ),
        name="audienceAndScopePolicy",
    )
    require_contract_only(authority, "audienceAndScopePolicy")

    lifecycle = closed_object(
        contract.get("lifecyclePolicy"),
        {
            "disabledRegistrationMayAuthorize",
            "applicationDisablementRequiresSessionRevocationEvaluation",
            "registrationChangeRequiresSessionReevaluation",
            "silentAudienceReassignmentAllowed",
            "silentClientIdReassignmentAllowed",
            "runtimeAccepted",
        },
        "lifecyclePolicy",
    )
    require_flags(
        lifecycle,
        required_true=(
            "applicationDisablementRequiresSessionRevocationEvaluation",
            "registrationChangeRequiresSessionReevaluation",
        ),
        required_false=(
            "disabledRegistrationMayAuthorize",
            "silentAudienceReassignmentAllowed",
            "silentClientIdReassignmentAllowed",
        ),
        name="lifecyclePolicy",
    )
    require_contract_only(lifecycle, "lifecyclePolicy")

    consumer = closed_object(
        contract.get("consumerBoundary"),
        {
            "consumerMaySelfRegisterAtRuntime",
            "consumerMayChooseAnotherApplicationsAudience",
            "consumerMayChooseAnotherApplicationsClientId",
            "consumerMayOverrideRegisteredRedirect",
            "registrationImpliesApplicationDataAuthorization",
            "registrationImpliesPrivacyShieldAuthorization",
            "registrationImpliesWardveilAcceptance",
        },
        "consumerBoundary",
    )
    require_flags(
        consumer,
        required_false=tuple(consumer.keys()),
        name="consumerBoundary",
    )

    registrations = contract.get("registrations")
    require(isinstance(registrations, list), "registrations must be an array")
    require(
        registrations == [],
        "source contract must not silently register concrete native applications",
    )
    require(
        contract.get("emptyRegistryMeansNoRuntimeRegistrations") is True,
        "empty registry must mean no runtime registrations",
    )


def main() -> int:
    try:
        validate_contract(load_contract())
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"native Identity application-registration validation failed: {exc}")
        return 1
    print("native GoreeCloud Identity application-registration source contract validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
