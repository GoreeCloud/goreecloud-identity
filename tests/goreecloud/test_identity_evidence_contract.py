import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "contracts" / "identity.mesh-evidence-profile.json"
EVIDENCE_SCHEMA_PATH = ROOT / "contracts" / "identity.evidence.schema.json"
SERVICE_TOKEN_PATH = ROOT / "contracts" / "mesh-service-token.v1.json"
DELIVERY_CLIENT_PATH = ROOT / "goreecloud_identity" / "mesh_delivery.py"

EXPECTED_DOMAINS = {
    "identity",
    "authentication",
    "authorization",
    "accounts",
    "devices",
    "credentials",
    "sessions",
    "delegated-authority",
}

EXPECTED_ASSERTIONS = {
    "service-identity-verification": "identity",
    "authentication-result": "authentication",
    "authorization-decision": "authorization",
    "account-state": "accounts",
    "device-identity-state": "devices",
    "credential-state": "credentials",
    "session-state": "sessions",
    "delegated-authority-state": "delegated-authority",
}


def load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_profile_separates_evidence_from_authentication_credentials() -> None:
    profile = load(PROFILE_PATH)

    assert profile["system"] == "goreecloud-identity"
    assert profile["producer_repository"] == "GoreeCloud/goreecloud-identity"
    assert set(profile["authority_domains"]) == EXPECTED_DOMAINS
    assert profile["producer_contracts"] == ["contracts/identity.evidence.schema.json"]
    assert profile["authentication_contracts"] == ["contracts/mesh-service-token.v1.json"]
    assert "contracts/mesh-service-token.v1.json" not in profile["producer_contracts"]
    assert set(profile["permitted_assertion_families"]) == set(EXPECTED_ASSERTIONS)

    delivery = profile["runtime_delivery"]
    assert delivery["producer_service_id"] == "goreecloud-identity"
    assert delivery["producer_identity_must_match_envelope"] is True
    assert delivery["delivery_client"] == "goreecloud_identity.mesh_delivery.MeshDeliveryClient"
    assert delivery["https_required_except_loopback"] is True
    assert delivery["redirects_followed"] is False
    assert delivery["credential_persisted"] is False
    assert delivery["receipt_requires_evidence_id_binding"] is True
    assert delivery["receipt_requires_producer_service_binding"] is True
    assert delivery["implemented"] is True
    assert DELIVERY_CLIENT_PATH.is_file()

    assert delivery["production_acceptance"] is False
    assert profile["status"] == "source-implemented"
    assert profile["production_acceptance"] is False


def test_evidence_schema_enforces_identity_minimization_and_authority_mapping() -> None:
    schema = load(EVIDENCE_SCHEMA_PATH)
    properties = schema["properties"]

    assert properties["contract"]["const"] == "goreecloud.identity-evidence.v1"
    assert set(properties["authority_domain"]["enum"]) == EXPECTED_DOMAINS
    assert set(properties["assertion"]["enum"]) == set(EXPECTED_ASSERTIONS)
    assert properties["contains_user_content"]["const"] is False
    assert properties["contains_secret_material"]["const"] is False
    assert properties["contains_reusable_credentials"]["const"] is False
    assert properties["contains_raw_profile_attributes"]["const"] is False

    observed_mapping = {}
    for rule in schema["allOf"]:
        assertion = rule["if"]["properties"]["assertion"]["const"]
        domain = rule["then"]["properties"]["authority_domain"]["const"]
        observed_mapping[assertion] = domain
    assert observed_mapping == EXPECTED_ASSERTIONS


def test_service_token_contract_remains_distinct_authentication_contract() -> None:
    token = load(SERVICE_TOKEN_PATH)
    evidence = load(EVIDENCE_SCHEMA_PATH)

    assert token != evidence
    assert EVIDENCE_SCHEMA_PATH.name == "identity.evidence.schema.json"
    assert SERVICE_TOKEN_PATH.name == "mesh-service-token.v1.json"
