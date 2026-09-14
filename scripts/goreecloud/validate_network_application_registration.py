#!/usr/bin/env python3
"""Validate the GoreeCloud Network registration contract and runtime evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "goreecloud.identity.application-registration/v1"
CONTRACT_PATH = Path("docs/goreecloud/integrations/network-application-registration.v1.json")


class ContractError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a JSON object")
    return value


def canonical_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.extend(_walk_keys(child))
    return keys


def _validate_application(contract: dict[str, Any]) -> None:
    application = contract.get("application")
    if not isinstance(application, dict):
        raise ContractError("application object is required")
    expected_application = {
        "id": "goreecloud-network",
        "displayName": "GoreeCloud Network",
        "lifecycle": "Development",
        "productionAccepted": False,
        "identityAuthority": "GoreeCloud Identity",
        "resourceAudience": "goreecloud-network",
        "administratorScope": "goreecloud.network.admin",
    }
    for key, expected in expected_application.items():
        if application.get(key) != expected:
            raise ContractError(f"application.{key} must be {expected!r}")


def _validate_issuer(contract: dict[str, Any]) -> None:
    issuer = contract.get("issuer")
    expected_issuer = "https://identity.goreecloud.com/application/o/network/"
    if not isinstance(issuer, dict) or issuer.get("expected") != expected_issuer:
        raise ContractError("canonical Network issuer is required")
    if issuer.get("discoveryRequired") is not True:
        raise ContractError("issuer discovery must remain required")


def _validate_server_client(contract: dict[str, Any]) -> None:
    server_client = contract.get("serverIntrospectionClient")
    if not isinstance(server_client, dict):
        raise ContractError("serverIntrospectionClient is required")
    if server_client.get("id") != "goreecloud-network-server":
        raise ContractError("unexpected Network server introspection client id")
    if server_client.get("clientType") != "confidential":
        raise ContractError("Network server introspection client must be confidential")
    if server_client.get("credentialHandling") != "runtime_secret_only":
        raise ContractError("Network server credential must remain runtime-secret-only")
    if server_client.get("redirectUris") != []:
        raise ContractError("server introspection client must not declare redirect URIs")


def _validate_interactive_administration(contract: dict[str, Any]) -> None:
    interactive = contract.get("interactiveAdministration")
    if not isinstance(interactive, dict):
        raise ContractError("interactiveAdministration object is required")
    if interactive.get("state") != "not_implemented":
        raise ContractError(
            "interactive Network Identity administration must remain "
            "not_implemented until separately validated"
        )


def _validate_runtime_acceptance(contract: dict[str, Any]) -> None:
    acceptance = contract.get("runtimeAcceptance")
    if not isinstance(acceptance, dict):
        raise ContractError("runtimeAcceptance object is required")
    if acceptance.get("registrationState") != "contract_defined_runtime_registration_pending":
        raise ContractError("runtime registration must remain pending in the source contract")
    if acceptance.get("networkVerifierEvidenceVersion") != (
        "goreecloud.network.identity.acceptance/v1"
    ):
        raise ContractError("Network verifier evidence version is inconsistent")
    if acceptance.get("successfulProbeState") != (
        "runtime_probe_passed_production_acceptance_pending"
    ):
        raise ContractError("successful runtime probe state is inconsistent")
    if acceptance.get("productionAccepted") is not False:
        raise ContractError("source contract must never claim production acceptance")

    required_checks = acceptance.get("requiredChecks")
    if not isinstance(required_checks, list):
        raise ContractError("runtimeAcceptance.requiredChecks must be a list")
    required = {
        "client_registration",
        "issuer_and_discovery",
        "audience",
        "administrator_scope",
        "token_introspection",
        "session_expiration",
        "disabled_account_behavior",
        "identity_provider_outage",
        "recovery",
        "rollback",
    }
    if not required.issubset(set(required_checks)):
        raise ContractError("required runtime acceptance checks are incomplete")


def _validate_secret_policy(contract: dict[str, Any]) -> None:
    secret_policy = contract.get("secretPolicy")
    if not isinstance(secret_policy, dict):
        raise ContractError("secretPolicy object is required")
    if secret_policy.get("repositoryMayContainReusableSecrets") is not False:
        raise ContractError("repository reusable-secret policy must remain false")
    if secret_policy.get("observedEvidenceMayContainReusableSecrets") is not False:
        raise ContractError("observed evidence reusable-secret policy must remain false")


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("schemaVersion") != SCHEMA_VERSION:
        raise ContractError("unexpected contract schemaVersion")
    _validate_application(contract)
    _validate_issuer(contract)
    _validate_server_client(contract)
    _validate_interactive_administration(contract)
    _validate_runtime_acceptance(contract)
    _validate_secret_policy(contract)


def validate_observed(contract: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    validate_contract(contract)

    secret_policy = contract["secretPolicy"]
    prohibited = {str(key).lower() for key in secret_policy["prohibitedEvidenceFields"]}
    present = {key.lower() for key in _walk_keys(observed)}
    leaking = sorted(prohibited.intersection(present))
    if leaking:
        names = ", ".join(leaking)
        raise ContractError(
            f"observed evidence contains prohibited reusable-secret fields: {names}"
        )

    application = contract["application"]
    issuer = contract["issuer"]
    expected = {
        "applicationId": application["id"],
        "issuer": issuer["expected"],
        "audience": application["resourceAudience"],
        "administratorScope": application["administratorScope"],
        "serverIntrospectionClientId": contract["serverIntrospectionClient"]["id"],
    }
    for key, expected_value in expected.items():
        if observed.get(key) != expected_value:
            raise ContractError(
                f"observed {key} does not match the approved Network registration contract"
            )

    if observed.get("runtimeConfigured") is not True:
        raise ContractError("observed runtime must explicitly report runtimeConfigured=true")
    if observed.get("registrationPresent") is not True:
        raise ContractError("observed runtime must explicitly report registrationPresent=true")
    if observed.get("productionAccepted") is not False:
        raise ContractError("observed registration evidence must not claim production acceptance")

    return {
        "evidenceVersion": "goreecloud.identity.network-registration-observation/v1",
        "applicationId": application["id"],
        "contractSha256": canonical_sha256(contract),
        "state": "observed_registration_matches_contract_runtime_acceptance_pending",
        "runtimeConfigured": True,
        "registrationPresent": True,
        "productionAccepted": False,
    }


def contract_evidence(contract: dict[str, Any]) -> dict[str, Any]:
    validate_contract(contract)
    return {
        "evidenceVersion": "goreecloud.identity.network-registration-contract/v1",
        "applicationId": contract["application"]["id"],
        "contractSha256": canonical_sha256(contract),
        "state": "contract_valid_runtime_observation_pending",
        "productionAccepted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--observed", type=Path)
    args = parser.parse_args()

    try:
        contract = load_json(args.contract)
        evidence = contract_evidence(contract)
        if args.observed is not None:
            observed = load_json(args.observed)
            evidence = validate_observed(contract, observed)
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        failure = {
            "state": "validation_failed",
            "productionAccepted": False,
            "detail": str(exc),
        }
        print(json.dumps(failure, indent=2))
        return 1

    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
