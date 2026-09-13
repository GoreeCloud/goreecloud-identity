#!/usr/bin/env python3
"""Validate the native GoreeCloud Identity application-session source contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTRACT = Path("contracts/native-application-session.v1.json")
EXPECTED_SCHEMA = "goreecloud.identity.native-application-session/v1"
EXPECTED_AUDIT_EVENTS = [
    "native_application_authorization_started",
    "native_application_authorization_succeeded",
    "native_application_authorization_failed",
    "native_application_session_created",
    "native_application_refresh_rotated",
    "native_application_session_revoked",
]
TOP_LEVEL_KEYS = {
    "schemaVersion",
    "lifecycle",
    "canonicalAuthority",
    "architecture",
    "runtimeImplementationState",
    "productionAccepted",
    "protocolProfile",
    "applicationRegistration",
    "tokens",
    "sessionBinding",
    "authorizationBoundary",
    "storageAndTransport",
    "revocationAndOffline",
    "audit",
    "consumerRequirements",
    "migrationBoundary",
    "authorityTransfer",
}


class ContractError(ValueError):
    pass


def load_contract(path: Path = CONTRACT) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError("native application-session contract must be a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def closed_object(value: object, expected_keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} object is required")
    require(set(value) == expected_keys, f"{name} fields must be closed and exact")
    return value


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


def validate_protocol_profile(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("protocolProfile"),
        {
            "preferredFlow",
            "authorizationCodeRequired",
            "pkceS256Required",
            "externalUserAgentRequired",
            "stateRequired",
            "nonceRequiredForOidc",
            "implicitGrantAllowed",
            "resourceOwnerPasswordGrantAllowed",
            "nativeClientSecretRequired",
            "runtimeAccepted",
        },
        "protocolProfile",
    )
    require(
        section.get("preferredFlow") == "oidc_oauth_authorization_code_pkce",
        "native applications must use the bounded OIDC/OAuth authorization-code PKCE profile",
    )
    require_flags(
        section,
        required_true=(
            "authorizationCodeRequired",
            "pkceS256Required",
            "externalUserAgentRequired",
            "stateRequired",
            "nonceRequiredForOidc",
        ),
        required_false=(
            "implicitGrantAllowed",
            "resourceOwnerPasswordGrantAllowed",
            "nativeClientSecretRequired",
        ),
        name="protocolProfile",
    )
    require_contract_only(section, "protocolProfile")


def validate_application_registration(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("applicationRegistration"),
        {
            "publicNativeClientClassRequired",
            "exactClientIdRequired",
            "exactRegisteredRedirectRequired",
            "wildcardRedirectAllowed",
            "httpsRequiredOutsideExplicitLoopbackDevelopment",
            "redirectUserinfoAllowed",
            "redirectFragmentAllowed",
            "applicationWideReusableCredentialAllowed",
            "runtimeAccepted",
        },
        "applicationRegistration",
    )
    require_flags(
        section,
        required_true=(
            "publicNativeClientClassRequired",
            "exactClientIdRequired",
            "exactRegisteredRedirectRequired",
            "httpsRequiredOutsideExplicitLoopbackDevelopment",
        ),
        required_false=(
            "wildcardRedirectAllowed",
            "redirectUserinfoAllowed",
            "redirectFragmentAllowed",
            "applicationWideReusableCredentialAllowed",
        ),
        name="applicationRegistration",
    )
    require_contract_only(section, "applicationRegistration")


def validate_tokens(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("tokens"),
        {
            "shortLivedAccessTokenRequired",
            "audienceBindingRequired",
            "scopeBindingRequired",
            "idTokenAsApiBearerAllowed",
            "refreshTokenRotationRequired",
            "refreshTokenReuseDetectionRequired",
            "refreshTokenFamilyRevocationRequired",
            "refreshTokenDisclosureInLogsAllowed",
            "refreshTokenDisclosureInOrdinaryDocsAllowed",
            "runtimeAccepted",
        },
        "tokens",
    )
    require_flags(
        section,
        required_true=(
            "shortLivedAccessTokenRequired",
            "audienceBindingRequired",
            "scopeBindingRequired",
            "refreshTokenRotationRequired",
            "refreshTokenReuseDetectionRequired",
            "refreshTokenFamilyRevocationRequired",
        ),
        required_false=(
            "idTokenAsApiBearerAllowed",
            "refreshTokenDisclosureInLogsAllowed",
            "refreshTokenDisclosureInOrdinaryDocsAllowed",
        ),
        name="tokens",
    )
    require_contract_only(section, "tokens")


def validate_session_binding(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("sessionBinding"),
        {
            "userBindingRequired",
            "applicationBindingRequired",
            "clientInstanceBindingRequired",
            "clientInstanceIdentifierLocalRandomRequired",
            "hardwareFingerprintingAllowed",
            "deviceSessionVisibilityRequired",
            "perSessionRevocationRequired",
            "accountDisablementRequiresRevocationEvaluation",
            "applicationDisablementRequiresRevocationEvaluation",
            "runtimeAccepted",
        },
        "sessionBinding",
    )
    require_flags(
        section,
        required_true=(
            "userBindingRequired",
            "applicationBindingRequired",
            "clientInstanceBindingRequired",
            "clientInstanceIdentifierLocalRandomRequired",
            "deviceSessionVisibilityRequired",
            "perSessionRevocationRequired",
            "accountDisablementRequiresRevocationEvaluation",
            "applicationDisablementRequiresRevocationEvaluation",
        ),
        required_false=("hardwareFingerprintingAllowed",),
        name="sessionBinding",
    )
    require_contract_only(section, "sessionBinding")


def validate_authorization_boundary(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("authorizationBoundary"),
        {
            "identityAuthenticatesPrincipal",
            "identityIssuesDelegatedPlatformClaims",
            "applicationAuthorizationPreserved",
            "applicationDataOwnershipPreserved",
            "applicationMayExpandBeyondIssuedScope",
            "identitySessionImpliesApplicationMutationPermission",
            "runtimeAccepted",
        },
        "authorizationBoundary",
    )
    require_flags(
        section,
        required_true=(
            "identityAuthenticatesPrincipal",
            "identityIssuesDelegatedPlatformClaims",
            "applicationAuthorizationPreserved",
            "applicationDataOwnershipPreserved",
        ),
        required_false=(
            "applicationMayExpandBeyondIssuedScope",
            "identitySessionImpliesApplicationMutationPermission",
        ),
        name="authorizationBoundary",
    )
    require_contract_only(section, "authorizationBoundary")


def validate_storage_and_transport(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("storageAndTransport"),
        {
            "tlsRequiredOutsideExplicitLoopbackDevelopment",
            "userPasswordStorageInNativeClientAllowed",
            "browserSessionCookieReuseAsNativeCredentialAllowed",
            "sourceControlledReusableCredentialsAllowed",
            "ordinaryDocumentationReusableCredentialsAllowed",
            "authenticationLogReusableCredentialsAllowed",
            "protectedPlatformCredentialStorageRequired",
            "runtimeAccepted",
        },
        "storageAndTransport",
    )
    require_flags(
        section,
        required_true=(
            "tlsRequiredOutsideExplicitLoopbackDevelopment",
            "protectedPlatformCredentialStorageRequired",
        ),
        required_false=(
            "userPasswordStorageInNativeClientAllowed",
            "browserSessionCookieReuseAsNativeCredentialAllowed",
            "sourceControlledReusableCredentialsAllowed",
            "ordinaryDocumentationReusableCredentialsAllowed",
            "authenticationLogReusableCredentialsAllowed",
        ),
        name="storageAndTransport",
    )
    require_contract_only(section, "storageAndTransport")


def validate_revocation_and_offline(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("revocationAndOffline"),
        {
            "expiredCredentialFallbackAllowed",
            "offlineMutationAuthorizationImpliedByCachedIdentityState",
            "serverMutationRequiresCurrentCredentialValidation",
            "revokedSessionMayRefresh",
            "revocationPropagationRequired",
            "runtimeAccepted",
        },
        "revocationAndOffline",
    )
    require_flags(
        section,
        required_true=(
            "serverMutationRequiresCurrentCredentialValidation",
            "revocationPropagationRequired",
        ),
        required_false=(
            "expiredCredentialFallbackAllowed",
            "offlineMutationAuthorizationImpliedByCachedIdentityState",
            "revokedSessionMayRefresh",
        ),
        name="revocationAndOffline",
    )
    require_contract_only(section, "revocationAndOffline")


def validate_audit(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("audit"),
        {
            "requiredEvents",
            "passwordsAllowed",
            "authorizationCodesAllowed",
            "accessTokensAllowed",
            "refreshTokensAllowed",
            "runtimeAccepted",
        },
        "audit",
    )
    require(
        section.get("requiredEvents") == EXPECTED_AUDIT_EVENTS,
        "native application-session audit event set drifted",
    )
    require_flags(
        section,
        required_false=(
            "passwordsAllowed",
            "authorizationCodesAllowed",
            "accessTokensAllowed",
            "refreshTokensAllowed",
        ),
        name="audit",
    )
    require_contract_only(section, "audit")


def validate_consumer_requirements(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("consumerRequirements"),
        {
            "identityIssuedCredentialRequired",
            "serviceTokenSubstitutionAllowed",
            "sharedApplicationPasswordAllowed",
            "directIdentityDatabaseAccessAllowed",
            "directApplicationDatabaseAuthorizationBypassAllowed",
            "clientMaySelectAnotherUserAsPrincipal",
        },
        "consumerRequirements",
    )
    require_flags(
        section,
        required_true=("identityIssuedCredentialRequired",),
        required_false=(
            "serviceTokenSubstitutionAllowed",
            "sharedApplicationPasswordAllowed",
            "directIdentityDatabaseAccessAllowed",
            "directApplicationDatabaseAuthorizationBypassAllowed",
            "clientMaySelectAnotherUserAsPrincipal",
        ),
        name="consumerRequirements",
    )


def validate_migration_boundary(contract: dict[str, Any]) -> None:
    section = closed_object(
        contract.get("migrationBoundary"),
        {
            "inheritedAuthentikProtocolSupportIsNativeAcceptance",
            "inheritedRuntime",
            "nativeRuntimeImplementationRequired",
            "existingApplicationSessionMigrationMustBeExplicit",
            "applicationOwnedAuthorizationPreserved",
            "applicationOwnedDataPreserved",
        },
        "migrationBoundary",
    )
    require(
        section.get("inheritedRuntime") == "transitional_reference_only",
        "inherited runtime must remain transitional reference infrastructure",
    )
    require_flags(
        section,
        required_true=(
            "nativeRuntimeImplementationRequired",
            "existingApplicationSessionMigrationMustBeExplicit",
            "applicationOwnedAuthorizationPreserved",
            "applicationOwnedDataPreserved",
        ),
        required_false=("inheritedAuthentikProtocolSupportIsNativeAcceptance",),
        name="migrationBoundary",
    )


def validate_contract(contract: dict[str, Any]) -> None:
    require(
        set(contract) == TOP_LEVEL_KEYS,
        "native application-session top-level fields must be closed and exact",
    )
    require(
        contract.get("schemaVersion") == EXPECTED_SCHEMA,
        "unexpected native application-session schema",
    )
    require(
        contract.get("lifecycle") == "development",
        "native application-session lifecycle must remain development",
    )
    require(
        contract.get("canonicalAuthority") == "GoreeCloud Identity",
        "canonical authority must remain GoreeCloud Identity",
    )
    require(
        contract.get("architecture") == "goreecloud-owned-native",
        "architecture must remain GoreeCloud-owned native",
    )
    require(
        contract.get("runtimeImplementationState") == "contract_only",
        "contract must not claim native runtime implementation",
    )
    require(
        contract.get("productionAccepted") is False,
        "contract must not claim production acceptance",
    )
    require(
        contract.get("authorityTransfer") is False,
        "Identity authority must not transfer",
    )

    validate_protocol_profile(contract)
    validate_application_registration(contract)
    validate_tokens(contract)
    validate_session_binding(contract)
    validate_authorization_boundary(contract)
    validate_storage_and_transport(contract)
    validate_revocation_and_offline(contract)
    validate_audit(contract)
    validate_consumer_requirements(contract)
    validate_migration_boundary(contract)


def main() -> int:
    try:
        validate_contract(load_contract())
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"native Identity application-session validation failed: {exc}")
        return 1
    print("native GoreeCloud Identity application-session source contract validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
