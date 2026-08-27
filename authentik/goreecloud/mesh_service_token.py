"""GoreeCloud Identity service credentials for GoreeCloud Mesh.

This module implements the ``goreecloud-identity.mesh-service-token.v1``
contract. Private signing keys remain in Identity; consumers receive only
short-lived RS256 JWTs and public JWKS material.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import re
from typing import Iterable
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "goreecloud-identity"
AUDIENCE = "goreecloud-mesh"
MAX_LIFETIME_SECONDS = 900
_ALLOWED_SCOPES = frozenset(
    {
        "mesh.services.write",
        "mesh.relationships.write",
        "mesh.policy.evaluate",
        "mesh.attestations.write",
        "mesh.contracts.write",
        "mesh.evidence.read",
        "mesh.evidence.write",
        "mesh.everkeep.recovery.write",
    }
)
_SERVICE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


@dataclass(frozen=True, slots=True)
class MeshSigningKey:
    """One active or retained RSA signing key owned by GoreeCloud Identity."""

    kid: str
    private_key: rsa.RSAPrivateKey

    def __post_init__(self) -> None:
        if not _KID_RE.fullmatch(self.kid):
            raise ValueError("kid must be an opaque 8-128 character identifier")
        if self.private_key.key_size < 2048:
            raise ValueError("Mesh service-token RSA keys must be at least 2048 bits")

    def public_jwk(self) -> dict[str, object]:
        jwk = RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        return {
            **jwk,
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
        }


class MeshServiceTokenIssuer:
    """Issue narrowly scoped, short-lived service JWTs and publish JWKS."""

    def __init__(self, active_key: MeshSigningKey, retained_keys: Iterable[MeshSigningKey] = ()):
        keys = [active_key, *retained_keys]
        kids = [key.kid for key in keys]
        if len(kids) != len(set(kids)):
            raise ValueError("Mesh signing key ids must be unique")
        self._active_key = active_key
        self._keys = tuple(keys)

    @property
    def active_kid(self) -> str:
        return self._active_key.kid

    def jwks(self) -> dict[str, object]:
        """Return only public verification material, active key first."""
        return {"keys": [key.public_jwk() for key in self._keys]}

    def issue(
        self,
        *,
        service_id: str,
        scopes: Iterable[str],
        lifetime_seconds: int = 300,
        now: datetime | None = None,
        not_before: datetime | None = None,
        jti: str | None = None,
    ) -> str:
        service_id = str(service_id or "").strip()
        if not _SERVICE_ID_RE.fullmatch(service_id):
            raise ValueError("service_id must be a canonical lowercase GoreeCloud service identifier")

        normalized_scopes = tuple(dict.fromkeys(str(scope).strip() for scope in scopes if str(scope).strip()))
        if not normalized_scopes:
            raise ValueError("at least one Mesh scope is required")
        unknown = sorted(set(normalized_scopes) - _ALLOWED_SCOPES)
        if unknown:
            raise ValueError(f"unsupported Mesh scope(s): {', '.join(unknown)}")

        if not isinstance(lifetime_seconds, int) or isinstance(lifetime_seconds, bool):
            raise ValueError("lifetime_seconds must be an integer")
        if lifetime_seconds <= 0 or lifetime_seconds > MAX_LIFETIME_SECONDS:
            raise ValueError("Mesh service token lifetime must be between 1 and 900 seconds")

        issued_at = _utc(now or datetime.now(UTC))
        nbf = _utc(not_before) if not_before is not None else issued_at
        if nbf > issued_at + timedelta(seconds=60):
            raise ValueError("not_before cannot exceed the allowed 60-second clock skew")
        expires_at = issued_at + timedelta(seconds=lifetime_seconds)
        token_id = str(jti or uuid4()).strip()
        if not token_id or len(token_id) > 200:
            raise ValueError("jti must be a non-empty opaque identifier")

        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": f"service:{service_id}",
            "service_id": service_id,
            "scope": " ".join(normalized_scopes),
            "iat": int(issued_at.timestamp()),
            "nbf": int(nbf.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": token_id,
        }
        return jwt.encode(
            claims,
            self._active_key.private_key,
            algorithm="RS256",
            headers={"kid": self._active_key.kid, "typ": "JWT"},
        )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime values must be timezone-aware")
    return value.astimezone(UTC)
