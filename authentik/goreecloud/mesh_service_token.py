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
import stat
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
MAX_PRIVATE_KEY_FILE_BYTES = 64 * 1024
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
        "mesh.events.read",
        "mesh.evidence.read",
        "mesh.evidence.write",
        "mesh.everkeep.recovery.write",
        "mesh.platform-registry.read",
        "mesh.platform-registry.write",
    }
)
_SERVICE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_AUTH_CONTEXT_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,200}$")


def _canonical_string(value: object, *, name: str) -> str:
    raw = str(value or "")
    if not raw or raw != raw.strip():
        raise ValueError(f"{name} must be a non-empty canonical string")
    return raw


def _validate_kid(kid: str) -> str:
    canonical = _canonical_string(kid, name="kid")
    if not _KID_RE.fullmatch(canonical):
        raise ValueError("kid must be an opaque 8-128 character identifier")
    return canonical


def _public_jwk(kid: str, public_key: rsa.RSAPublicKey) -> dict[str, object]:
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    return {**jwk, "kid": kid, "use": "sig", "alg": "RS256"}


def _read_private_key_file(path: str | os.PathLike[str]) -> bytes:
    """Read one bounded, non-symlink, non-group/other-writable private key file."""

    key_path = Path(path)
    try:
        path_info = key_path.lstat()
    except OSError as exc:
        raise ValueError(
            "Mesh signing key file does not exist or is not accessible: " f"{key_path}"
        ) from exc
    if stat.S_ISLNK(path_info.st_mode):
        raise ValueError("Mesh signing key file must not be a symbolic link")
    if not stat.S_ISREG(path_info.st_mode):
        raise ValueError("Mesh signing key file must be a regular file")
    if stat.S_IMODE(path_info.st_mode) & 0o022:
        raise ValueError("Mesh signing key file must not be writable by group or other users")
    if path_info.st_size <= 0 or path_info.st_size > MAX_PRIVATE_KEY_FILE_BYTES:
        raise ValueError(
            f"Mesh signing key file must be between 1 and {MAX_PRIVATE_KEY_FILE_BYTES} bytes"
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(key_path, flags)
    except OSError as exc:
        raise ValueError("Mesh signing key file could not be opened safely") from exc
    try:
        opened_info = os.fstat(fd)
        if not stat.S_ISREG(opened_info.st_mode):
            raise ValueError("Mesh signing key file must remain a regular file when opened")
        if (opened_info.st_dev, opened_info.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise ValueError("Mesh signing key file changed while being opened")
        if stat.S_IMODE(opened_info.st_mode) & 0o022:
            raise ValueError("Mesh signing key file permissions changed to an unsafe mode")
        if opened_info.st_size <= 0 or opened_info.st_size > MAX_PRIVATE_KEY_FILE_BYTES:
            raise ValueError("Mesh signing key file size changed outside the accepted bound")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            body = handle.read(MAX_PRIVATE_KEY_FILE_BYTES + 1)
        if not body or len(body) > MAX_PRIVATE_KEY_FILE_BYTES:
            raise ValueError("Mesh signing key file contents exceed the accepted bound")
        return body
    finally:
        os.close(fd)


@dataclass(frozen=True, slots=True)
class VerifiedWorkloadPrincipal:
    """Identity-authenticated workload allowed to receive Mesh credentials."""

    service_id: str
    allowed_scopes: frozenset[str]
    authentication_context: str

    def __post_init__(self) -> None:
        service_id = _canonical_string(self.service_id, name="service_id")
        if not _SERVICE_ID_RE.fullmatch(service_id):
            raise ValueError(
                "service_id must be a canonical lowercase GoreeCloud service identifier"
            )

        scopes = _normalize_scopes(self.allowed_scopes)

        authentication_context = _canonical_string(
            self.authentication_context, name="authentication_context"
        )
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
                "Mesh verification key file does not exist or is not a file: " f"{key_path}"
            )
        try:
            loaded = serialization.load_pem_public_key(key_path.read_bytes())
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                "Mesh verification key file is not a valid PEM public key: " f"{key_path}"
            ) from exc
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise ValueError("Mesh service-token verification keys must be RSA public keys")
        return cls(kid=_validate_kid(kid), public_key=loaded)


@dataclass(frozen=True, slots=True)
class MeshSigningKey:
    """Identity-owned active signing key; private material is never exported."""

    kid: str
    private_key: rsa.RSAPrivateKey

    def __post_init__(self) -> None:
        _validate_kid(self.kid)
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Mesh service-token signing key must be an RSA private key")
        if self.private_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise ValueError("Mesh service-token RSA keys must be at least 2048 bits")

    @classmethod
    def from_private_key_file(
        cls,
        *,
        kid: str,
        path: str | os.PathLike[str],
    ) -> MeshSigningKey:
        """Load an Identity-owned PEM key from a bounded runtime secret file."""

        key_path = Path(path)
        try:
            loaded = serialization.load_pem_private_key(
                _read_private_key_file(key_path), password=None
            )
        except (OSError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError) and str(exc).startswith("Mesh signing key file"):
                raise
            raise ValueError(
                "Mesh signing key file is not a valid unencrypted PEM private key: " f"{key_path}"
            ) from exc
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise ValueError("Mesh service-token signing keys must be RSA private keys")
        return cls(kid=_validate_kid(kid), private_key=loaded)

    def verification_key(self) -> MeshVerificationKey:
        return MeshVerificationKey(kid=self.kid, public_key=self.private_key.public_key())


class MeshServiceTokenIssuer:
    """Issue short-lived Mesh credentials from Identity-owned key material."""

    def __init__(
        self,
        active_key: MeshSigningKey,
        retained_keys: Iterable[MeshVerificationKey] = (),
    ) -> None:
        if not isinstance(active_key, MeshSigningKey):
            raise TypeError("active_key must be a MeshSigningKey")
        retained_public = tuple(retained_keys)
        if not all(isinstance(key, MeshVerificationKey) for key in retained_public):
            raise ValueError("retained Mesh keys must be public verification keys")
        keys: tuple[MeshSigningKey | MeshVerificationKey, ...] = (
            active_key,
            *retained_public,
        )
        kids = [key.kid for key in keys]
        if len(kids) != len(set(kids)):
            raise ValueError("Mesh signing key ids must be unique")
        self._active_key = active_key
        self._retained_keys = retained_public

    @property
    def active_kid(self) -> str:
        return self._active_key.kid

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
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> MeshServiceTokenIssuer:
        """Build the issuer from secret/public-key file references.

        The active private key is read only from an Identity-owned secret file.
        Retained rotation keys are intentionally public-only files so old private
        signing material cannot be reintroduced through the runtime config.
        """

        env = os.environ if environ is None else environ
        active_kid = _canonical_string(env.get(ACTIVE_KID_ENV, ""), name=ACTIVE_KID_ENV)
        active_file = _canonical_string(
            env.get(ACTIVE_PRIVATE_KEY_FILE_ENV, ""), name=ACTIVE_PRIVATE_KEY_FILE_ENV
        )

        retained_raw = str(env.get(RETAINED_PUBLIC_KEY_FILES_ENV, "{}")).strip() or "{}"
        try:
            retained = json.loads(retained_raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{RETAINED_PUBLIC_KEY_FILES_ENV} must be a JSON object of " "kid-to-file mappings"
            ) from exc
        if not isinstance(retained, dict) or not all(
            isinstance(kid, str)
            and kid == kid.strip()
            and kid
            and isinstance(path, str)
            and path == path.strip()
            and path
            for kid, path in retained.items()
        ):
            raise ValueError(
                f"{RETAINED_PUBLIC_KEY_FILES_ENV} must be a JSON object of canonical "
                "kid-to-file mappings"
            )

        return cls.from_key_files(
            active_kid=active_kid,
            active_private_key_file=active_file,
            retained_public_key_files=retained,
        )

    def jwks(self) -> dict[str, list[dict[str, object]]]:
        """Return public verification material for active and retained keys."""

        keys = [self._active_key.verification_key(), *self._retained_keys]
        return {"keys": [_public_jwk(key.kid, key.public_key) for key in keys]}

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
        """Issue a Mesh token limited by the pre-verified workload's scope ceiling."""

        if not isinstance(principal, VerifiedWorkloadPrincipal):
            raise TypeError("principal must be a VerifiedWorkloadPrincipal")
        normalized_scopes = _normalize_scopes(requested_scopes)
        unauthorized = sorted(set(normalized_scopes) - principal.allowed_scopes)
        if unauthorized:
            raise PermissionError(
                "workload principal is not authorized for Mesh scope(s): "
                f"{', '.join(unauthorized)}"
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
        scopes: tuple[str, ...],
        lifetime_seconds: int,
        now: datetime | None,
        not_before: datetime | None,
        jti: str | None,
    ) -> str:
        if not scopes:
            raise ValueError("at least one Mesh scope is required")
        if lifetime_seconds < 1 or lifetime_seconds > MAX_LIFETIME_SECONDS:
            raise ValueError(
                f"Mesh service-token lifetime must be between 1 and "
                f"{MAX_LIFETIME_SECONDS} seconds"
            )
        issued_at = now or datetime.now(UTC)
        if issued_at.tzinfo is None:
            raise ValueError("Mesh service-token time must be timezone-aware")
        not_before_at = not_before or issued_at
        if not_before_at.tzinfo is None:
            raise ValueError("Mesh service-token not-before time must be timezone-aware")
        if not_before_at > issued_at + timedelta(seconds=60):
            raise ValueError("not_before cannot exceed the allowed 60-second clock skew")
        expires_at = issued_at + timedelta(seconds=lifetime_seconds)
        if not_before_at >= expires_at:
            raise ValueError("Mesh service-token not_before must be before expiry")
        token_id = str(jti or uuid4())
        if not token_id or token_id != token_id.strip() or len(token_id) > MAX_TOKEN_ID_LENGTH:
            raise ValueError("jti must be a non-empty canonical opaque identifier")

        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": f"service:{service_id}",
            "service_id": service_id,
            "scope": " ".join(scopes),
            "iat": int(issued_at.timestamp()),
            "nbf": int(not_before_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": token_id,
        }
        headers = {"kid": self._active_key.kid, "typ": "JWT"}
        return jwt.encode(
            claims,
            self._active_key.private_key,
            algorithm="RS256",
            headers=headers,
        )


def _normalize_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for scope in scopes:
        canonical = _canonical_string(scope, name="Mesh scope")
        if canonical not in _ALLOWED_SCOPES:
            raise ValueError(f"unsupported Mesh scope(s): {canonical}")
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)
