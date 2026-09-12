#!/usr/bin/env python3
"""Validate the native GoreeCloud Identity account-security source contract."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTRACT = Path("contracts/native-account-security.v1.json")
EXPECTED_SCHEMA = "goreecloud.identity.native-account-security/v1"
EXPECTED_AUDIT_EVENTS = [
    "authentication_succeeded",
    "authentication_failed",
    "mfa_enrolled",
    "mfa_removed",
    "credential_added",
    "credential_revoked",
    "session_created",
    "session_revoked",
    "recovery_started",
    "recovery_completed",
    "account_disabled",
]


class ContractError(ValueError):
    pass


def load_contract(path: Path = CONTRACT) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError("native account security contract must be a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_contract_only(section: dict[str, Any], name: str) -> None:
    require(section.get("runtimeAccepted") is False, f"{name} must not claim runtime acceptance")


def validate_authentication_methods(contract: dict[str, Any]) -> None:
    methods = contract.get("authenticationMethods")
    require(isinstance(methods, dict), "authenticationMethods object is required")
    require(set(methods) == {"password", "passkeyWebAuthn", "totp"}, "authentication methods must be closed")

    password = methods["password"]
    require(password.get("supportedWhereRequired") is True, "password support must remain bounded to where required")
    require(password.get("plaintextStorageAllowed") is False, "plaintext password storage must be prohibited")
    require(password.get("protectedVerifierRequired") is True, "password verifier protection is required")
    require_contract_only(password, "password")

    passkey = methods["passkeyWebAuthn"]
    require(passkey.get("standardsBased") is True, "passkey/WebAuthn must remain standards based")
    require(passkey.get("privateKeyExportAllowed") is False, "passkey private-key export must be prohibited")
    require(passkey.get("userVerificationPolicyRequired") is True, "WebAuthn user-verification policy is required")
    require_contract_only(passkey, "passkeyWebAuthn")

    totp = methods["totp"]
    require(totp.get("multiFactorPurpose") is True, "TOTP must remain an MFA mechanism")
    require(totp.get("secretProtectionRequired") is True, "TOTP secret protection is required")
    require(totp.get("replayProtectionRequired") is True, "TOTP replay protection is required")
    require_contract_only(totp, "totp")


def validate_recovery_and_sessions(contract: dict[str, Any]) -> None:
    recovery = contract.get("recovery")
    require(isinstance(recovery, dict), "recovery contract is required")
    require(recovery.get("securityDowngradeAllowed") is False, "recovery must not silently weaken security")
    require(recovery.get("reusableRecoveryMaterialInLogsAllowed") is False, "recovery material must not enter logs")
    require(
        recovery.get("reusableRecoveryMaterialInOrdinaryDocsAllowed") is False,
        "recovery material must not enter ordinary documentation",
    )
    require(
        recovery.get("normalServiceExclusiveDependencyAllowed") is False,
        "recovery must not depend exclusively on the normal Identity service",
    )
    require(recovery.get("breakGlassAdministrationSeparate") is True, "break-glass administration must remain distinct")
    require_contract_only(recovery, "recovery")

    sessions = contract.get("sessions")
    require(isinstance(sessions, dict), "sessions contract is required")
    for key in ["visibilityRequired", "expirationRequired", "revocationRequired", "accountDisablementRequiresRevocationEvaluation"]:
        require(sessions.get(key) is True, f"sessions.{key} must remain required")
    require(sessions.get("sessionSecretDisclosureAllowed") is False, "session secrets must not be disclosed")
    require_contract_only(sessions, "sessions")


def validate_visibility_audit_redirects(contract: dict[str, Any]) -> None:
    visibility = contract.get("deviceAndCredentialVisibility")
    require(isinstance(visibility, dict), "deviceAndCredentialVisibility contract is required")
    require(visibility.get("visibilityRequired") is True, "device/credential visibility is required")
    require(visibility.get("revocationCapabilityRequired") is True, "credential revocation capability is required")
    require(visibility.get("reusableSecretDisclosureAllowed") is False, "visibility must not disclose reusable secrets")
    require_contract_only(visibility, "deviceAndCredentialVisibility")

    audit = contract.get("authenticationAudit")
    require(isinstance(audit, dict), "authenticationAudit contract is required")
    require(audit.get("requiredEvents") == EXPECTED_AUDIT_EVENTS, "authentication audit event set drifted")
    for key in ["passwordsAllowed", "tokensAllowed", "mfaSecretsAllowed", "recoverySecretsAllowed"]:
        require(audit.get(key) is False, f"authenticationAudit.{key} must remain false")
    require_contract_only(audit, "authenticationAudit")

    redirects = contract.get("redirectValidation")
    require(isinstance(redirects, dict), "redirectValidation contract is required")
    require(redirects.get("exactRegisteredRedirectRequired") is True, "registered redirect matching must be exact")
    require(redirects.get("wildcardRedirectDefaultAllowed") is False, "wildcard redirects must be disabled by default")
    require(
        redirects.get("httpsRequiredOutsideExplicitLoopbackDevelopment") is True,
        "HTTPS must be required outside explicit loopback development",
    )
    require(redirects.get("userinfoInRedirectAllowed") is False, "redirect userinfo must be prohibited")
    require(redirects.get("fragmentInRedirectAllowed") is False, "redirect fragments must be prohibited")
    require_contract_only(redirects, "redirectValidation")


def validate_secret_and_abuse_boundaries(contract: dict[str, Any]) -> None:
    secret = contract.get("secretProtection")
    require(isinstance(secret, dict), "secretProtection contract is required")
    for key in [
        "sourceControlledReusableSecretsAllowed",
        "ordinaryDocumentationReusableSecretsAllowed",
        "authenticationLogReusableSecretsAllowed",
    ]:
        require(secret.get(key) is False, f"secretProtection.{key} must remain false")
    require(secret.get("protectedRuntimeConfigurationRequired") is True, "protected runtime configuration is required")
    require(secret.get("restrictiveRuntimePermissionsRequired") is True, "restrictive runtime permissions are required")
    require_contract_only(secret, "secretProtection")

    abuse = contract.get("abuseProtection")
    require(isinstance(abuse, dict), "abuseProtection contract is required")
    for key in [
        "boundedAuthenticationAttemptsRequired",
        "rateLimitingOrEquivalentRequired",
        "failClosedOnProtectionFailure",
        "securitySensitiveDefaultsFailClosed",
    ]:
        require(abuse.get(key) is True, f"abuseProtection.{key} must remain required")
    require_contract_only(abuse, "abuseProtection")


def validate_migration_boundary(contract: dict[str, Any]) -> None:
    migration = contract.get("migrationBoundary")
    require(isinstance(migration, dict), "migrationBoundary contract is required")
    require(
        migration.get("inheritedAuthentikFeatureParityIsNativeAcceptance") is False,
        "inherited authentik feature parity must not become native acceptance",
    )
    require(migration.get("inheritedRuntime") == "transitional_reference_only", "inherited runtime must remain transitional")
    require(migration.get("nativeRuntimeImplementationRequired") is True, "native runtime implementation must remain required")
    require(migration.get("applicationOwnedAuthorizationPreserved") is True, "application authorization must remain preserved")
    require(migration.get("applicationOwnedDataPreserved") is True, "application-owned data must remain preserved")


def validate_contract(contract: dict[str, Any]) -> None:
    require(contract.get("schemaVersion") == EXPECTED_SCHEMA, "unexpected native account-security schema")
    require(contract.get("lifecycle") == "development", "account-security lifecycle must remain development")
    require(contract.get("canonicalAuthority") == "GoreeCloud Identity", "canonical authority must be GoreeCloud Identity")
    require(contract.get("architecture") == "goreecloud-owned-native", "architecture must remain GoreeCloud-owned native")
    require(contract.get("runtimeImplementationState") == "contract_only", "contract must not claim native runtime implementation")
    require(contract.get("productionAccepted") is False, "contract must not claim production acceptance")
    require(contract.get("authorityTransfer") is False, "Identity authority must not transfer")
    validate_authentication_methods(contract)
    validate_recovery_and_sessions(contract)
    validate_visibility_audit_redirects(contract)
    validate_secret_and_abuse_boundaries(contract)
    validate_migration_boundary(contract)


def main() -> int:
    try:
        validate_contract(load_contract())
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        print(f"native Identity account-security validation failed: {exc}")
        return 1
    print("native GoreeCloud Identity account-security source contract validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
