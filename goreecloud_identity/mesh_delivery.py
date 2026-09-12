"""Fail-closed GoreeCloud Identity evidence delivery to GoreeCloud Mesh.

Credential issuance remains a GoreeCloud Identity responsibility. The client
uses a supplied short-lived bearer credential only for the outbound request;
it is never persisted, placed in the envelope, or returned in a receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from urllib import error, parse, request

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_BEARER_TOKEN_LENGTH = 8192
MAX_EVIDENCE_ID_LENGTH = 240


class MeshDeliveryError(RuntimeError):
    """Evidence was not accepted with a trustworthy producer-bound receipt."""


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _canonical_text(value: object, *, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name} must be a bounded canonical string")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _read_json_object(response, *, maximum: int) -> dict[str, object]:  # noqa: ANN001
    body = response.read(maximum + 1)
    if not body or len(body) > maximum:
        raise MeshDeliveryError("Mesh evidence delivery returned an oversized or empty response")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MeshDeliveryError("Mesh evidence delivery returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise MeshDeliveryError("Mesh evidence delivery returned an invalid acceptance response")
    return payload


def _receipt_time(value: object) -> str:
    text = _canonical_text(value, name="accepted_at", maximum=80)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise MeshDeliveryError("Mesh delivery receipt accepted_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MeshDeliveryError("Mesh delivery receipt accepted_at must include timezone information")
    return text


@dataclass(frozen=True, slots=True)
class MeshDeliveryReceipt:
    evidence_id: str
    replayed: bool
    accepted_at: str
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
        raw = str(mesh_base_url or "")
        if not raw or raw != raw.strip():
            raise ValueError("Mesh base URL must be canonical")
        parsed = parse.urlparse(raw)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Mesh base URL must not contain user information")
        if parsed.query or parsed.fragment or parsed.params:
            raise ValueError("Mesh base URL must not contain query, fragment, or path parameters")
        if parsed.path not in {"", "/"}:
            raise ValueError("Mesh base URL must be an origin without an application path")
        if not parsed.hostname:
            raise ValueError("Mesh base URL must contain a hostname")
        if parsed.scheme == "https":
            pass
        elif parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
            pass
        else:
            raise ValueError("Mesh evidence delivery requires HTTPS except for loopback development")
        origin = parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        return origin + "/v1/evidence/envelopes"

    def deliver(self, envelope: dict[str, object], *, bearer_token: str) -> MeshDeliveryReceipt:
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be an object")
        evidence_id = _canonical_text(
            envelope.get("id"),
            name="evidence id",
            maximum=MAX_EVIDENCE_ID_LENGTH,
        )
        producer = envelope.get("producer")
        if not isinstance(producer, dict) or producer.get("system") != self.producer_service_id:
            raise ValueError("Identity delivery accepts only goreecloud-identity envelopes")

        token = str(bearer_token or "")
        if (
            not token
            or token != token.strip()
            or len(token) > MAX_BEARER_TOKEN_LENGTH
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in token)
        ):
            raise ValueError("a valid canonical GoreeCloud Identity bearer credential is required")

        body = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_ENVELOPE_BYTES:
            raise ValueError("Identity evidence envelope exceeds the delivery size bound")
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
                payload = _read_json_object(response, maximum=MAX_RESPONSE_BYTES)
        except error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise MeshDeliveryError("Mesh evidence delivery refused an HTTP redirect") from exc
            try:
                rejected = _read_json_object(exc, maximum=MAX_RESPONSE_BYTES)
                raw_detail = rejected.get("error")
                detail = (
                    _canonical_text(raw_detail, name="Mesh rejection detail", maximum=256)
                    if isinstance(raw_detail, str)
                    else "Mesh rejected Identity evidence delivery"
                )
            except Exception:
                detail = "Mesh rejected Identity evidence delivery"
            raise MeshDeliveryError(f"Mesh evidence delivery failed with HTTP {exc.code}: {detail}") from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise MeshDeliveryError("Mesh evidence delivery failed before a valid receipt was accepted") from exc

        if status not in {200, 201}:
            raise MeshDeliveryError("Mesh evidence delivery returned an invalid acceptance response")

        delivered = payload.get("envelope")
        if not isinstance(delivered, dict) or delivered.get("id") != evidence_id:
            raise MeshDeliveryError("Mesh delivery receipt did not bind to the submitted evidence id")
        if payload.get("producer_service_id") != self.producer_service_id:
            raise MeshDeliveryError("Mesh delivery receipt did not bind to GoreeCloud Identity service identity")
        if not isinstance(payload.get("replayed"), bool):
            raise MeshDeliveryError("Mesh delivery receipt replay state is invalid")
        accepted_at = _receipt_time(payload.get("accepted_at"))

        return MeshDeliveryReceipt(
            evidence_id=evidence_id,
            replayed=payload["replayed"],
            accepted_at=accepted_at,
            producer_service_id=self.producer_service_id,
        )
