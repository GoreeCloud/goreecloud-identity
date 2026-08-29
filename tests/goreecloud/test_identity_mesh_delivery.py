import io
import json
from urllib import error, request

import pytest

from goreecloud_identity.mesh_delivery import MeshDeliveryClient, MeshDeliveryError


def envelope() -> dict[str, object]:
    return {
        "version": "goreecloud.evidence-envelope.v1",
        "id": "identity-authentication-001",
        "producer": {
            "system": "goreecloud-identity",
            "repository": "GoreeCloud/goreecloud-identity",
            "revision": "a" * 40,
            "contract": "contracts/identity.evidence.schema.json",
        },
        "authority_domain": "authentication",
        "subject": {"kind": "service", "id": "goreecloud-drive"},
        "assertion": "authentication-result",
        "outcome": "verified",
        "source": "identity://evidence/authentication-001",
        "observed_at": "2026-08-29T12:00:00Z",
        "valid_until": "2026-08-29T13:00:00Z",
        "data_class": "derived",
        "contains_user_content": False,
        "contains_secret_material": False,
    }


class FakeResponse:
    def __init__(self, payload: dict[str, object], status: int = 201) -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._body


class FakeOpener:
    def __init__(self, response=None, exception: Exception | None = None) -> None:
        self.response = response
        self.exception = exception
        self.last_request = None
        self.last_timeout = None

    def open(self, req, timeout):
        self.last_request = req
        self.last_timeout = timeout
        if self.exception is not None:
            raise self.exception
        return self.response


def accepted_payload(evidence_id: str = "identity-authentication-001") -> dict[str, object]:
    return {
        "envelope": {"id": evidence_id},
        "replayed": False,
        "accepted_at": "2026-08-29T12:01:00Z",
        "producer_service_id": "goreecloud-identity",
    }


def test_delivery_requires_https_except_loopback() -> None:
    MeshDeliveryClient("https://mesh.goreecloud.com")
    MeshDeliveryClient("http://127.0.0.1:8787")
    MeshDeliveryClient("http://localhost:8787")

    with pytest.raises(ValueError):
        MeshDeliveryClient("http://mesh.goreecloud.com")
    with pytest.raises(ValueError):
        MeshDeliveryClient("https://user:secret@mesh.goreecloud.com")
    with pytest.raises(ValueError):
        MeshDeliveryClient("https://mesh.goreecloud.com?token=secret")


def test_delivery_binds_identity_producer_and_receipt_without_returning_credential(
    monkeypatch,
) -> None:
    fake = FakeOpener(FakeResponse(accepted_payload()))
    monkeypatch.setattr(request, "build_opener", lambda *handlers: fake)

    submitted = envelope()
    token = "short-lived-identity-token"
    client = MeshDeliveryClient("https://mesh.goreecloud.com", timeout_seconds=3)
    receipt = client.deliver(submitted, bearer_token=token)

    assert receipt.evidence_id == submitted["id"]
    assert receipt.producer_service_id == "goreecloud-identity"
    assert receipt.replayed is False
    assert token not in repr(receipt)
    assert token not in json.dumps(submitted)
    assert fake.last_timeout == 3.0
    assert fake.last_request.full_url == "https://mesh.goreecloud.com/v1/evidence/envelopes"
    assert fake.last_request.get_header("Authorization") == f"Bearer {token}"


def test_delivery_rejects_cross_producer_submission_and_header_injection() -> None:
    client = MeshDeliveryClient("https://mesh.goreecloud.com")
    wrong = envelope()
    wrong["producer"] = {"system": "wardveil-security"}

    with pytest.raises(ValueError):
        client.deliver(wrong, bearer_token="token")
    with pytest.raises(ValueError):
        client.deliver(envelope(), bearer_token="token\r\nInjected: true")


def test_delivery_refuses_redirect(monkeypatch) -> None:
    redirect = error.HTTPError(
        "https://mesh.goreecloud.com/v1/evidence/envelopes",
        302,
        "Found",
        {"Location": "https://other.example/evidence"},
        io.BytesIO(b""),
    )
    fake = FakeOpener(exception=redirect)
    monkeypatch.setattr(request, "build_opener", lambda *handlers: fake)

    with pytest.raises(MeshDeliveryError, match="refused an HTTP redirect"):
        MeshDeliveryClient("https://mesh.goreecloud.com").deliver(envelope(), bearer_token="token")


def test_delivery_fails_closed_on_receipt_binding_mismatch(monkeypatch) -> None:
    wrong_id = FakeOpener(FakeResponse(accepted_payload("different-evidence-id")))
    monkeypatch.setattr(request, "build_opener", lambda *handlers: wrong_id)
    with pytest.raises(MeshDeliveryError, match="submitted evidence id"):
        MeshDeliveryClient("https://mesh.goreecloud.com").deliver(envelope(), bearer_token="token")

    wrong_service_payload = accepted_payload()
    wrong_service_payload["producer_service_id"] = "privacy-shield"
    wrong_service = FakeOpener(FakeResponse(wrong_service_payload))
    monkeypatch.setattr(request, "build_opener", lambda *handlers: wrong_service)
    with pytest.raises(MeshDeliveryError, match="GoreeCloud Identity service identity"):
        MeshDeliveryClient("https://mesh.goreecloud.com").deliver(envelope(), bearer_token="token")
