"""GoreeCloud Identity service credentials for GoreeCloud Mesh.

This module implements the ``goreecloud-identity.mesh-service-token.v1``
contract. Private signing keys remain in Identity; consumers receive only
short-lived RS256 JWTs and public JWKS material.

Runtime signing keys are loaded from Identity-owned secret files. Token
issuance is bound to a pre-verified workload principal so callers cannot
select an arbitrary GoreeCloud service identity or escalate Mesh scopes.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "goreecloud-identity"
AUDIENCE = "goreecloud-mesh"
MAX_LIFETIME_SECONDS = 900
MIN_RSA_KEY_SIZE_BITS = 2048
MAX_TOKEN_ID_LENGTH = 200
ACTIVE_KID_ENV = "GOREECLOUD_MESH_ACTIVE_KID"
ACTIVE_PRIVATE_KEY_FILE_ENV = "GOREECLOUD_MESH_ACTIVE_PRIVATE_KEY_FILE"
RETAINED_PUBLIC_KEY_FILES_ENV = "GOREECLOUD_MESH_RETAINED_PUBLIC_KEY_FILES_JSON"
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
_AUTH_CONTEXT_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,200}$")


def _validate_kid(kid: str) -> str:
    normalized = str(kid or "").strip()
    if not _KID_RE.fullmatch(normalized):
        raise ValueError("kid must be an opaque 8-128 character identifier")
    return normalized


def _public_jwk(kid: str, public_key: rsa.RSAPublicKey) -> dict[str, object]:
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    return {**jwk, "kid": kid, "use": "sig", "alg": "RS256"}


@dataclass(frozen=True, slots=True)
class VerifiedWorkloadPrincipal:
    """Identity-authenticated workload allowed to receive Mesh credentials."""

    service_id: str
    allowed_scopes: frozenset[str]
    authentication_context: str

    def __post_init__(self) -> None:
        service_id = str(self.service_id or "").strip()
        if not _SERVICE_ID_RE.fullmatch(service_id):
            raise ValueError(
                "service_id must be a canonical lowercase GoreeCloud service identifier"
            )

        scopes = _normalize_scopes(self.allowed_scopes)
        unknown = sorted(set(scopes) - _ALLOWED_SCOPES)
        if unknown:
            raise ValueError(f"unsupported Mesh scope(s): {', '.join(unknown)}")

        authentication_context = str(self.authentication_context or "").strip()
        if not _AUTH_CONTEXT_RE.fullmatch(authentication_context):
            raise ValueError(
                "authentication_context must identify the verified workload authentication"
            )

        object.__setattr__(self, "service_id", service_id)
        object.__setattr__(self, "allowed_scopes", frozenset(scopes))
        object.__setattr__(self, "authentication_context", authentication_context)


@dataclass(frozen=True, slots=True)
class MeshVerificationKey:
    """A public-only retained RSA key used during signing-key rotation."""

    kid: str
    public_key: rsa.RSAPublicKey

    def __post_init__(self) -> None:
        _validate_kid(self.kid)
        if not isinstance(self.public_key, rsa.RSAPublicKey):
            raise ValueError("Mesh verification key must be an RSA public key")
        if self.public_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise ValueError("Mesh service-token RSA keys must be at least 2048 bits")

    @classmethod
    def from_public_key_file(
        cls,
        *,
        kid: str,
        path: str | os.PathLike[str],
    ) -> MeshVerificationKey:
        key_path = Path(path)
        if not key_path.is_file():
            raise ValueError(
                f"Mesh verification key file does not exist or is not a file: {key_path}"
            )
        try:
            loaded = serialization.load_pem_public_key(key_path.read_bytes())
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                f"Mesh verification key file is not a valid PEM public key: {key_path}"
            ) from exc
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise ValueError("Mesh service-token verification keys must be RSA public keys")
        return cls(kid=_validate_kid(kid), public_key=loaded)

    def public_jwk(self) -> dict[str, object]:
        return _public_jwk(self.kid, self.public_key)


@dataclass(frozen=True, slots=True)
class MeshSigningKey:
    """The active RSA signing key owned exclusively by GoreeCloud Identity."""

    kid: str
    private_key: rsa.RSAPrivateKey

    def __post_init__(self) -> None:
        _validate_kid(self.kid)
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Mesh signing key must be an RSA private key")
        if self.private_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise ValueError("Mesh service-token RSA keys must be at least 2048 bits")

    @classmethod
    def from_private_key_file(
        cls,
        *,
        kid: str,
        path: str | os.PathLike[str],
    ) -> MeshSigningKey:
        """Load an Identity-owned PEM key from a runtime secret file."""

        key_path = Path(path)
        if not key_path.is_file():
            raise ValueError(f"Mesh signing key file does not exist or is not a file: {key_path}")
        try:
            loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                f"Mesh signing key file is not a valid unencrypted PEM private key: {key_path}"
            ) from exc
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise ValueError("Mesh service-token signing keys must be RSA private keys")
        return cls(kid=_validate_kid(kid), private_key=loaded)

    def verification_key(self) -> MeshVerificationKey:
        return MeshVerificationKey(kid=self.kid, public_key=self.private_key.public_key())

    def public_jwk(self) -> dict[str, object]:
        return self.verification_key().public_jwk()


class MeshServiceTokenIssuer:
    """Issue narrowly scoped, short-lived service JWTs and publish JWKS."""

    def __init__(
        self,
        active_key: MeshSigningKey,
        retained_keys: Iterable[MeshVerificationKey | MeshSigningKey] = (),
    ):
        retained_public = tuple(
            key.verification_key() if isinstance(key, MeshSigningKey) else key
            for key in retained_keys
        )
        if not all(isinstance(key, MeshVerificationKey) for key in retained_public):
            raise ValueError("retained Mesh keys must be public verification keys")
        keys: tuple[MeshSigningKey | MeshVerificationKey, ...] = (active_key, *retained_public)
        kids = [key.kid for key in keys]
        if len(kids) != len(set(kids)):
            raise ValueError("Mesh signing key ids must be unique")
        self._active_key = active_key
        self._keys = keys

    @classmethod
    def from_key_files(
        cls,
        *,
        active_kid: str,
        active_private_key_file: str | os.PathLike[str],
        retained_public_key_files: Mapping[str, str | os.PathLike[str]] | None = None,
    ) -> MeshServiceTokenIssuer:
        active = MeshSigningKey.from_private_key_file(
            kid=active_kid,
            path=active_private_key_file,
        )
        retained = [
            MeshVerificationKey.from_public_key_file(kid=kid, path=path)
            for kid, path in (retained_public_key_files or {}).items()
        ]
        return cls(active, retained)

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> MeshServiceTokenIssuer:
        """Build the issuer from secret/public-key file references.

        The active private key is read only from an Identity-owned secret file.
        Retained rotation keys are public-only PEM files so expired signing
        authority is not retained merely to validate still-live credentials.
        """

        env = os.environ if environ is None else environ
        active_kid = str(env.get(ACTIVE_KID_ENV, "")).strip()
        active_file = str(env.get(ACTIVE_PRIVATE_KEY_FILE_ENV, "")).strip()
        if not active_kid or not active_file:
            raise ValueError(
                f"{ACTIVE_KID_ENV} and {ACTIVE_PRIVATE_KEY_FILE_ENV} are required "
                "for Mesh token issuance"
            )

        retained_raw = str(env.get(RETAINED_PUBLIC_KEY_FILES_ENV, "{}")).strip() or "{}"
        try:
            retained = json.loads(retained_raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{RETAINED_PUBLIC_KEY_FILES_ENV} must be a JSON object of kid-to-file mappings"
            ) from exc
        if not isinstance(retained, dict) or not all(
            isinstance(kid, str) and isinstance(path, str) and path.strip()
            for kid, path in retained.items()
        ):
            raise ValueError(
                f"{RETAINED_PUBLIC_KEY_FILES_ENV} must be a JSON object of kid-to-file mappings"
            )

        return cls.from_key_files(
            active_kid=active_kid,
            active_private_key_file=active_file,
            retained_public_key_files=retained,
        )

    @property
    def active_kid(self) -> str:
        return self._active_key.kid

    def jwks(self) -> dict[str, object]:
        """Return only public verification material, active key first."""
        return {"keys": [key.public_jwk() for key in self._keys]}

    def issue_for_principal(
        self,
        *,
        principal: VerifiedWorkloadPrincipal,
        requested_scopes: Iterable[str],
        lifetime_seconds: int = 300,
        now: datetime | None = None,
        not_before: datetime | None = None,
        jti: str | None = None,
    ) -> str:
        """Issue a Mesh token without allowing caller-selected identity."""

        if not isinstance(principal, VerifiedWorkloadPrincipal):
            raise TypeError("principal must be a VerifiedWorkloadPrincipal")
        normalized_scopes = _normalize_scopes(requested_scopes)
        if not normalized_scopes:
            raise ValueError("at least one Mesh scope is required")
        unauthorized = sorted(set(normalized_scopes) - principal.allowed_scopes)
        if unauthorized:
            raise PermissionError(
                f"workload principal is not authorized for Mesh scope(s): {', '.join(unauthorized)}"
            )

        return self._issue_bound_token(
            service_id=principal.service_id,
            scopes=normalized_scopes,
            lifetime_seconds=lifetime_seconds,
            now=now,
            not_before=not_before,
            jti=jti,
        )

    def _issue_bound_token(
        self,
        *,
        service_id: str,
        scopes: Iterable[str],
        lifetime_seconds: int,
        now: datetime | None,
        not_before: datetime | None,
        jti: str | None,
    ) -> str:
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
        if not token_id or len(token_id) > MAX_TOKEN_ID_LENGTH:
            raise ValueError("jti must be a non-empty opaque identifier")

        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": f"service:{service_id}",
            "service_id": service_id,
            "scope": " ".join(scopes),
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


def _normalize_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(scope).strip() for scope in scopes if str(scope).strip()))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime values must be timezone-aware")
    return value.astimezone(UTC)
