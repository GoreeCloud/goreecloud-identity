from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "goreecloud"
    / "validate_network_application_registration.py"
)
SPEC = importlib.util.spec_from_file_location("network_registration_validator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class NetworkApplicationRegistrationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = validator.load_json(validator.CONTRACT_PATH)

    def test_contract_is_valid_and_pending_runtime_acceptance(self) -> None:
        evidence = validator.contract_evidence(self.contract)
        self.assertEqual(evidence["state"], "contract_valid_runtime_observation_pending")
        self.assertFalse(evidence["productionAccepted"])
        self.assertEqual(evidence["applicationId"], "goreecloud-network")

    def test_matching_minimized_runtime_observation_is_not_production_acceptance(
        self,
    ) -> None:
        observed = {
            "applicationId": "goreecloud-network",
            "issuer": "https://identity.goreecloud.com/application/o/network/",
            "audience": "goreecloud-network",
            "administratorScope": "goreecloud.network.admin",
            "serverIntrospectionClientId": "goreecloud-network-server",
            "runtimeConfigured": True,
            "registrationPresent": True,
            "productionAccepted": False,
        }
        evidence = validator.validate_observed(self.contract, observed)
        self.assertEqual(
            evidence["state"],
            "observed_registration_matches_contract_runtime_acceptance_pending",
        )
        self.assertTrue(evidence["runtimeConfigured"])
        self.assertFalse(evidence["productionAccepted"])

    def test_observed_evidence_rejects_reusable_secret_fields(self) -> None:
        observed = {
            "applicationId": "goreecloud-network",
            "issuer": "https://identity.goreecloud.com/application/o/network/",
            "audience": "goreecloud-network",
            "administratorScope": "goreecloud.network.admin",
            "serverIntrospectionClientId": "goreecloud-network-server",
            "runtimeConfigured": True,
            "registrationPresent": True,
            "productionAccepted": False,
            "nested": {"clientSecret": "must-not-be-recorded"},
        }
        with self.assertRaises(validator.ContractError):
            validator.validate_observed(self.contract, observed)

    def test_observed_evidence_rejects_identity_contract_mismatch(self) -> None:
        observed = {
            "applicationId": "goreecloud-network",
            "issuer": "https://identity.invalid.example/application/o/network/",
            "audience": "goreecloud-network",
            "administratorScope": "goreecloud.network.admin",
            "serverIntrospectionClientId": "goreecloud-network-server",
            "runtimeConfigured": True,
            "registrationPresent": True,
            "productionAccepted": False,
        }
        with self.assertRaises(validator.ContractError):
            validator.validate_observed(self.contract, observed)

    def test_validator_cli_emits_non_secret_contract_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(self.contract), encoding="utf-8")
            loaded = validator.load_json(path)
            evidence = validator.contract_evidence(loaded)
        encoded = json.dumps(evidence)
        self.assertNotIn("clientSecret", encoded)
        self.assertNotIn("accessToken", encoded)
        self.assertNotIn("privateKey", encoded)


if __name__ == "__main__":
    unittest.main()
