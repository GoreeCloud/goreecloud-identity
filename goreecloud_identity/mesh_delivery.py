"""Fail-closed GoreeCloud Identity evidence delivery to GoreeCloud Mesh.

Credential issuance remains a GoreeCloud Identity responsibility. The client
uses a supplied short-lived bearer credential only for the outbound request;
it is never persisted, placed in the envelope, or returned in a receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib import error, parse, request


class MeshDeliveryError(RuntimeError):
    """Evidence was not accepted with a trustworthy producer-bound receipt."""


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True, slots=True)
class MeshDeliveryReceipt:
    evidence_id: str
    replayed: bool
    accepted_at: str | None
    producer_service_id: str


class MeshDeliveryClient:
    """Deliver only GoreeCloud Identity evidence envelopes to Mesh."""

    producer_service_id = "goreecloud-identity"

    def __init__(self, mesh_base_url: str, *, timeout_seconds: float = 5.0) -> None:
        self._endpoint = self._build_endpoint(mesh_base_url)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._timeout_seconds = float(timeout_seconds)

    @staticmethod
    def _build_endpoint(mesh_base_url: str) -> str:
        raw = str(mesh_base_url or "").strip().rstrip("/")
        parsed = parse.urlparse(raw)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Mesh base URL must not contain user information")
        if parsed.query or parsed.fragment or parsed.params:
            raise ValueError("Mesh base URL must not contain query, fragment, or path parameters")
        if parsed.scheme == "https" and parsed.hostname:
            return raw + "/v1/evidence/envelopes"
        if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
            return raw + "/v1/evidence/envelopes"
        raise ValueError("Mesh evidence delivery requires HTTPS except for loopback development")

    def deliver(self, envelope: dict[str, object], *, bearer_token: str) -> MeshDeliveryReceipt:
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be an object")
        producer = envelope.get("producer")
        if not isinstance(producer, dict) or producer.get("system") != self.producer_service_id:
            raise ValueError("Identity delivery accepts only goreecloud-identity envelopes")

        token = str(bearer_token or "").strip()
        if not token or "\r" in token or "\n" in token:
            raise ValueError("a valid GoreeCloud Identity bearer credential is required")

        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        req = request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "goreecloud-identity/mesh-evidence",
            },
        )

        opener = request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(req, timeout=self._timeout_seconds) as response:
                status = response.status
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise MeshDeliveryError("Mesh evidence delivery refused an HTTP redirect") from exc
            try:
                rejected = json.loads(exc.read().decode("utf-8"))
                detail = rejected.get("error", "Mesh rejected Identity evidence delivery")
            except Exception:
                detail = "Mesh rejected Identity evidence delivery"
            raise MeshDeliveryError(f"Mesh evidence delivery failed with HTTP {exc.code}: {detail}") from exc
        except (error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise MeshDeliveryError("Mesh evidence delivery failed before a valid receipt was accepted") from exc

        if status not in {200, 201} or not isinstance(payload, dict):
            raise MeshDeliveryError("Mesh evidence delivery returned an invalid acceptance response")

        delivered = payload.get("envelope")
        if not isinstance(delivered, dict) or delivered.get("id") != envelope.get("id"):
            raise MeshDeliveryError("Mesh delivery receipt did not bind to the submitted evidence id")
        if payload.get("producer_service_id") != self.producer_service_id:
            raise MeshDeliveryError("Mesh delivery receipt did not bind to GoreeCloud Identity service identity")

        return MeshDeliveryReceipt(
            evidence_id=str(delivered["id"]),
            replayed=payload.get("replayed") is True,
            accepted_at=payload.get("accepted_at") if isinstance(payload.get("accepted_at"), str) else None,
            producer_service_id=self.producer_service_id,
        )
