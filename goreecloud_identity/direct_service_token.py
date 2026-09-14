"""Native GoreeCloud Identity credentials for direct first-party service calls.

This module is deliberately separate from the Mesh service-token profile. Direct
service credentials are audience-bound to the service being called and cannot be
reused as GoreeCloud Mesh credentials. The first approved profile authenticates
GoreeCloud Search to GoreeCloud Privacy Shield's capability-reference verifier.

Source implementation does not establish a deployed issuer, JWKS endpoint,
network transport, production signing-key custody, or production acceptance.
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
from types import MappingProxyType
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "goreecloud-identity"
TOKEN_PROFILE = "goreecloud-identity.direct-service-token.v1"
PRIVACY_SHIELD_AUDIENCE = "goreecloud-privacy-shield"
PRIVACY_SHIELD_VERIFY_SCOPE = "privacy.capability-reference.verify"
PRIVACY_SHIELD_CONSUME_SCOPE = "privacy.capability-reference.consume"
DEFAULT_LIFETIME_SECONDS = 300
MAX_LIFETIME_SECONDS = 900
CLOCK_SKEW_SECONDS = 60
MAX_JTI_LENGTH = 200
MAX_PRIVATE_KEY_FILE_BYTES = 64 * 1024
MIN_RSA_KEY_SIZE_BITS = 2048
ACTIVE_KID_ENV = "GOREECLOUD_DIRECT_SERVICE_ACTIVE_KID"
ACTIVE_PRIVATE_KEY_FILE_ENV = "GOREECLOUD_DIRECT_SERVICE_ACTIVE_PRIVATE_KEY_FILE"
RETAINED_PUBLIC_KEY_FILES_ENV = "GOREECLOUD_DIRECT_SERVICE_RETAINED_PUBLIC_KEY_FILES_JSON"

_SERVICE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_AUTH_CONTEXT_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,200}$")

_AUDIENCE_POLICIES = {
    PRIVACY_SHIELD_AUDIENCE: {
        "service_ids": frozenset({"goreecloud-search"}),
        "scopes": frozenset(
            {
                PRIVACY_SHIELD_VERIFY_SCOPE,
                PRIVACY_SHIELD_CONSUME_SCOPE,
            }
        ),
    }
}


def _validate_service_id(service_id: str) -> str:
    normalized = str(service_id or "").strip()
    if not _SERVICE_ID_RE.fullmatch(normalized):
        raise ValueError("service_id must be a canonical lowercase GoreeCloud service identifier")
    return normalized


def _validate_kid(kid: str) -> str:
    normalized = str(kid or "").strip()
    if not _KID_RE.fullmatch(normalized):
        raise ValueError("kid must be an opaque 8-128 character identifier")
    return normalized


def _validate_audience(audience: str) -> str:
    normalized = str(audience or "").strip()
    if normalized not in _AUDIENCE_POLICIES:
        raise ValueError("unsupported direct-service audience")
    return normalized


def _normalize_scopes(scopes: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(scope).strip() for scope in scopes if str(scope).strip()))


def _public_jwk(kid: str, public_key: rsa.RSAPublicKey) -> dict[str, object]:
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    return {**jwk, "kid": kid, "use": "sig", "alg": "RS256"}


def _read_private_key_file(path: str | os.PathLike[str]) -> tuple[Path, bytes]:
    key_path = Path(path)
    if key_path.is_symlink():
        raise ValueError(f"Direct-service signing key file must not be a symbolic link: {key_path}")

    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    try:
        descriptor = os.open(key_path, flags)
    except OSError as exc:
        raise ValueError(
            f"Direct-service signing key file does not exist or cannot be opened safely: {key_path}"
        ) from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Direct-service signing key file must be a regular file: {key_path}")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(
                f"Direct-service signing key file must use owner-only permissions: {key_path}"
            )
        if metadata.st_size <= 0 or metadata.st_size > MAX_PRIVATE_KEY_FILE_BYTES:
            raise ValueError(
                "Direct-service signing key file must be non-empty and no larger than "
                f"{MAX_PRIVATE_KEY_FILE_BYTES} bytes: {key_path}"
            )

        chunks: list[bytes] = []
        remaining = MAX_PRIVATE_KEY_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        material = b"".join(chunks)
        if not material or len(material) > MAX_PRIVATE_KEY_FILE_BYTES:
            raise ValueError(
                "Direct-service signing key file must be non-empty and no larger than "
                f"{MAX_PRIVATE_KEY_FILE_BYTES} bytes: {key_path}"
            )
        return key_path, material
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class VerifiedDirectServicePrincipal:
    """Identity-authenticated workload allowed to receive direct-service credentials."""

    service_id: str
    audience_scopes: Mapping[str, Iterable[str]]
    authentication_context: str

    def __post_init__(self) -> None:
        service_id = _validate_service_id(self.service_id)
        if not isinstance(self.audience_scopes, Mapping) or not self.audience_scopes:
            raise ValueError("audience_scopes must define at least one approved direct-service audience")

        normalized: dict[str, frozenset[str]] = {}
        for raw_audience, raw_scopes in self.audience_scopes.items():
            audience = _validate_audience(raw_audience)
            policy = _AUDIENCE_POLICIES[audience]
            if service_id not in policy["service_ids"]:
                raise PermissionError(
                    f"service_id is not approved for direct-service audience {audience}"
                )
            scopes = frozenset(_normalize_scopes(raw_scopes))
            if not scopes:
                raise ValueError("each direct-service audience must grant at least one scope")
            unknown = sorted(scopes - policy["scopes"])
            if unknown:
                raise ValueError(f"unsupported direct-service scope(s): {', '.join(unknown)}")
            normalized[audience] = scopes

        authentication_context = str(self.authentication_context or "").strip()
        if not _AUTH_CONTEXT_RE.fullmatch(authentication_context):
            raise ValueError(
                "authentication_context must identify the verified workload authentication"
            )

        object.__setattr__(self, "service_id", service_id)
        object.__setattr__(self, "audience_scopes", MappingProxyType(normalized))
        object.__setattr__(self, "authentication_context", authentication_context)


@dataclass(frozen=True, slots=True)
class DirectServiceVerificationKey:
    kid: str
    public_key: rsa.RSAPublicKey

    def __post_init__(self) -> None:
        _validate_kid(self.kid)
        if not isinstance(self.public_key, rsa.RSAPublicKey):
            raise ValueError("Direct-service verification key must be an RSA public key")
        numbers = self.public_key.public_numbers()
        if self.public_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise ValueError("Direct-service RSA keys must be at least 2048 bits")
        if numbers.e < 3 or numbers.e % 2 == 0:
            raise ValueError("Direct-service RSA public exponent must be an odd integer >= 3")

    @classmethod
    def from_public_key_file(
        cls,
        *,
        kid: str,
        path: str | os.PathLike[str],
    ) -> DirectServiceVerificationKey:
        key_path = Path(path)
        if not key_path.is_file():
            raise ValueError(
                f"Direct-service verification key file does not exist or is not a file: {key_path}"
            )
        try:
            loaded = serialization.load_pem_public_key(key_path.read_bytes())
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                f"Direct-service verification key file is not a valid PEM public key: {key_path}"
            ) from exc
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise ValueError("Direct-service verification keys must be RSA public keys")
        return cls(kid=_validate_kid(kid), public_key=loaded)

    def public_jwk(self) -> dict[str, object]:
        return _public_jwk(self.kid, self.public_key)


@dataclass(frozen=True, slots=True)
class DirectServiceSigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey

    def __post_init__(self) -> None:
        _validate_kid(self.kid)
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Direct-service signing key must be an RSA private key")
        numbers = self.private_key.public_key().public_numbers()
        if self.private_key.key_size < MIN_RSA_KEY_SIZE_BITS:
            raise ValueError("Direct-service RSA keys must be at least 2048 bits")
        if numbers.e < 3 or numbers.e % 2 == 0:
            raise ValueError("Direct-service RSA public exponent must be an odd integer >= 3")

    @classmethod
    def from_private_key_file(
        cls,
        *,
        kid: str,
        path: str | os.PathLike[str],
    ) -> DirectServiceSigningKey:
        key_path, material = _read_private_key_file(path)
        try:
            loaded = serialization.load_pem_private_key(material, password=None)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Direct-service signing key file is not a valid unencrypted PEM private key: {key_path}"
            ) from exc
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise ValueError("Direct-service signing keys must be RSA private keys")
        return cls(kid=_validate_kid(kid), private_key=loaded)

    def verification_key(self) -> DirectServiceVerificationKey:
        return DirectServiceVerificationKey(
            kid=self.kid,
            public_key=self.private_key.public_key(),
        )

    def public_jwk(self) -> dict[str, object]:
        return self.verification_key().public_jwk()


class DirectServiceTokenIssuer:
    """Issue audience-bound first-party service JWTs and public JWKS material."""

    def __init__(
        self,
        active_key: DirectServiceSigningKey,
        retained_keys: Iterable[DirectServiceVerificationKey | DirectServiceSigningKey] = (),
    ):
        retained_public = tuple(
            key.verification_key() if isinstance(key, DirectServiceSigningKey) else key
            for key in retained_keys
        )
        if not all(isinstance(key, DirectServiceVerificationKey) for key in retained_public):
            raise ValueError("retained direct-service keys must be public verification keys")
        keys: tuple[DirectServiceSigningKey | DirectServiceVerificationKey, ...] = (
            active_key,
            *retained_public,
        )
        kids = [key.kid for key in keys]
        if len(kids) != len(set(kids)):
            raise ValueError("Direct-service signing key ids must be unique")
        self._active_key = active_key
        self._keys = keys

    @classmethod
    def from_key_files(
        cls,
        *,
        active_kid: str,
        active_private_key_file: str | os.PathLike[str],
        retained_public_key_files: Mapping[str, str | os.PathLike[str]] | None = None,
    ) -> DirectServiceTokenIssuer:
        active = DirectServiceSigningKey.from_private_key_file(
            kid=active_kid,
            path=active_private_key_file,
        )
        retained = [
            DirectServiceVerificationKey.from_public_key_file(kid=kid, path=path)
            for kid, path in (retained_public_key_files or {}).items()
        ]
        return cls(active, retained)

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> DirectServiceTokenIssuer:
        env = os.environ if environ is None else environ
        active_kid = str(env.get(ACTIVE_KID_ENV, "")).strip()
        active_file = str(env.get(ACTIVE_PRIVATE_KEY_FILE_ENV, "")).strip()
        if not active_kid or not active_file:
            raise ValueError(
                f"{ACTIVE_KID_ENV} and {ACTIVE_PRIVATE_KEY_FILE_ENV} are required "
                "for direct-service token issuance"
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
        return {"keys": [key.public_jwk() for key in self._keys]}

    def issue_for_principal(
        self,
        *,
        principal: VerifiedDirectServicePrincipal,
        audience: str,
        requested_scopes: Iterable[str],
        lifetime_seconds: int = DEFAULT_LIFETIME_SECONDS,
        now: datetime | None = None,
        not_before: datetime | None = None,
        jti: str | None = None,
    ) -> str:
        if not isinstance(principal, VerifiedDirectServicePrincipal):
            raise TypeError("principal must be a VerifiedDirectServicePrincipal")
        normalized_audience = _validate_audience(audience)
        allowed_scopes = principal.audience_scopes.get(normalized_audience)
        if allowed_scopes is None:
            raise PermissionError("workload principal is not authorized for the requested audience")

        normalized_scopes = _normalize_scopes(requested_scopes)
        if not normalized_scopes:
            raise ValueError("at least one direct-service scope is required")
        unauthorized = sorted(set(normalized_scopes) - set(allowed_scopes))
        if unauthorized:
            raise PermissionError(
                "workload principal is not authorized for direct-service scope(s): "
                + ", ".join(unauthorized)
            )

        if not isinstance(lifetime_seconds, int) or isinstance(lifetime_seconds, bool):
            raise ValueError("lifetime_seconds must be an integer")
        if lifetime_seconds <= 0 or lifetime_seconds > MAX_LIFETIME_SECONDS:
            raise ValueError("Direct-service token lifetime must be between 1 and 900 seconds")

        issued_at = _utc(now or datetime.now(UTC))
        nbf = _utc(not_before) if not_before is not None else issued_at
        if nbf < issued_at - timedelta(seconds=CLOCK_SKEW_SECONDS) or nbf > issued_at + timedelta(
            seconds=CLOCK_SKEW_SECONDS
        ):
            raise ValueError("not_before must remain within the allowed 60-second clock skew")
        expires_at = issued_at + timedelta(seconds=lifetime_seconds)
        token_id = str(jti or uuid4()).strip()
        if not token_id or len(token_id) > MAX_JTI_LENGTH:
            raise ValueError("jti must be a non-empty opaque identifier")

        claims = {
            "iss": ISSUER,
            "aud": normalized_audience,
            "sub": f"service:{principal.service_id}",
            "service_id": principal.service_id,
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


@dataclass(frozen=True, slots=True)
class AuthenticatedDirectService:
    service_id: str
    audience: str
    scopes: frozenset[str]
    token_id: str
    expires_at: datetime


class DirectServiceTokenVerifier:
    """Verify Identity direct-service tokens and derive the authenticated service id."""

    def __init__(self, jwks: Mapping[str, object]):
        raw_keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
        if not isinstance(raw_keys, list) or not raw_keys:
            raise ValueError("JWKS must contain at least one direct-service verification key")

        keys: dict[str, rsa.RSAPublicKey] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, Mapping):
                raise ValueError("JWKS keys must be objects")
            kid = _validate_kid(str(raw_key.get("kid", "")))
            if kid in keys:
                raise ValueError("JWKS kid values must be unique")
            if raw_key.get("kty") != "RSA" or raw_key.get("alg") != "RS256":
                raise ValueError("Direct-service JWKS keys must be RSA/RS256")
            if raw_key.get("use") != "sig":
                raise ValueError("Direct-service JWKS keys must be signing verification keys")
            if any(name in raw_key for name in ("d", "p", "q", "dp", "dq", "qi", "oth")):
                raise ValueError("Direct-service JWKS must not contain private RSA parameters")
            try:
                public_key = RSAAlgorithm.from_jwk(dict(raw_key))
            except (TypeError, ValueError) as exc:
                raise ValueError("Direct-service JWKS contains invalid RSA key material") from exc
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Direct-service JWKS keys must decode to RSA public keys")
            DirectServiceVerificationKey(kid=kid, public_key=public_key)
            keys[kid] = public_key
        self._keys = MappingProxyType(keys)

    def verify(
        self,
        token: str,
        *,
        audience: str,
        required_scopes: Iterable[str] = (),
        now: datetime | None = None,
    ) -> AuthenticatedDirectService:
        normalized_audience = _validate_audience(audience)
        policy = _AUDIENCE_POLICIES[normalized_audience]
        required = frozenset(_normalize_scopes(required_scopes))
        unsupported_required = sorted(required - policy["scopes"])
        if unsupported_required:
            raise ValueError(
                "unsupported required direct-service scope(s): " + ", ".join(unsupported_required)
            )

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ValueError("invalid direct-service token header") from exc
        if header.get("alg") != "RS256" or header.get("typ") != "JWT":
            raise ValueError("direct-service token must use the RS256/JWT protected-header profile")
        if "crit" in header or any(name in header for name in ("jku", "jwk", "x5u", "x5c")):
            raise ValueError("direct-service token must not select or embed verification keys")
        kid = _validate_kid(str(header.get("kid", "")))
        public_key = self._keys.get(kid)
        if public_key is None:
            raise ValueError("unknown direct-service signing key id")

        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=normalized_audience,
                issuer=ISSUER,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "service_id",
                        "scope",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                    ],
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise ValueError("direct-service token signature or registered claims are invalid") from exc

        if claims.get("aud") != normalized_audience:
            raise ValueError("direct-service token must carry exactly one approved audience")
        service_id = _validate_service_id(str(claims.get("service_id", "")))
        if claims.get("sub") != f"service:{service_id}":
            raise ValueError("direct-service token subject must match service_id")
        if service_id not in policy["service_ids"]:
            raise PermissionError("service identity is not approved for the requested audience")

        scope_claim = claims.get("scope")
        if not isinstance(scope_claim, str) or not scope_claim:
            raise ValueError("direct-service token scope must be a non-empty string")
        canonical_scope = " ".join(scope_claim.split())
        if canonical_scope != scope_claim:
            raise ValueError("direct-service token scope must use canonical single-space separation")
        token_scopes = frozenset(scope_claim.split(" "))
        unsupported = sorted(token_scopes - policy["scopes"])
        if unsupported:
            raise PermissionError(
                "direct-service token contains unsupported scope(s): " + ", ".join(unsupported)
            )
        if not required.issubset(token_scopes):
            raise PermissionError("direct-service token is missing a required scope")

        issued_at = _numeric_date(claims.get("iat"), "iat")
        not_before = _numeric_date(claims.get("nbf"), "nbf")
        expires_at = _numeric_date(claims.get("exp"), "exp")
        if expires_at <= issued_at or expires_at - issued_at > MAX_LIFETIME_SECONDS:
            raise ValueError("direct-service token lifetime is invalid")
        if (
            not_before < issued_at - CLOCK_SKEW_SECONDS
            or not_before > issued_at + CLOCK_SKEW_SECONDS
        ):
            raise ValueError("direct-service token not-before claim exceeds allowed skew")

        current = int(_utc(now or datetime.now(UTC)).timestamp())
        if issued_at > current + CLOCK_SKEW_SECONDS:
            raise ValueError("direct-service token issued-at claim is in the future")
        if not_before > current + CLOCK_SKEW_SECONDS:
            raise ValueError("direct-service token is not yet valid")
        if current >= expires_at + CLOCK_SKEW_SECONDS:
            raise ValueError("direct-service token is expired")

        token_id = str(claims.get("jti", "")).strip()
        if not token_id or len(token_id) > MAX_JTI_LENGTH:
            raise ValueError("direct-service token jti is invalid")

        return AuthenticatedDirectService(
            service_id=service_id,
            audience=normalized_audience,
            scopes=token_scopes,
            token_id=token_id,
            expires_at=datetime.fromtimestamp(expires_at, tz=UTC),
        )


def _numeric_date(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"direct-service token {name} must be an integer NumericDate")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime values must be timezone-aware")
    return value.astimezone(UTC)
