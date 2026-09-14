import os
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from goreecloud_identity.direct_service_token import (
    ACTIVE_KID_ENV,
    ACTIVE_PRIVATE_KEY_FILE_ENV,
    DEFAULT_LIFETIME_SECONDS,
    PRIVACY_SHIELD_AUDIENCE,
    PRIVACY_SHIELD_CONSUME_SCOPE,
    PRIVACY_SHIELD_VERIFY_SCOPE,
    RETAINED_PUBLIC_KEY_FILES_ENV,
    DirectServiceSigningKey,
    DirectServiceTokenIssuer,
    DirectServiceTokenVerifier,
    VerifiedDirectServicePrincipal,
)


def signing_key(kid: str = "direct-key-2026") -> DirectServiceSigningKey:
    return DirectServiceSigningKey(
        kid=kid,
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def search_principal(*scopes: str) -> VerifiedDirectServicePrincipal:
    return VerifiedDirectServicePrincipal(
        service_id="goreecloud-search",
        audience_scopes={PRIVACY_SHIELD_AUDIENCE: frozenset(scopes)},
        authentication_context="workload:goreecloud-search",
    )


def write_private_key(path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        path.chmod(0o600)


def test_issues_and_verifies_privacy_shield_bound_search_identity() -> None:
    key = signing_key()
    issuer = DirectServiceTokenIssuer(key)
    now = datetime(2026, 9, 14, 20, 0, tzinfo=UTC)
    token = issuer.issue_for_principal(
        principal=search_principal(PRIVACY_SHIELD_CONSUME_SCOPE),
        audience=PRIVACY_SHIELD_AUDIENCE,
        requested_scopes=[PRIVACY_SHIELD_CONSUME_SCOPE],
        lifetime_seconds=DEFAULT_LIFETIME_SECONDS,
        now=now,
        jti="search-privacy-test-001",
    )

    authenticated = DirectServiceTokenVerifier(issuer.jwks()).verify(
        token,
        audience=PRIVACY_SHIELD_AUDIENCE,
        required_scopes=[PRIVACY_SHIELD_CONSUME_SCOPE],
        now=now + timedelta(seconds=1),
    )

    assert authenticated.service_id == "goreecloud-search"
    assert authenticated.audience == PRIVACY_SHIELD_AUDIENCE
    assert authenticated.scopes == frozenset({PRIVACY_SHIELD_CONSUME_SCOPE})
    assert authenticated.token_id == "search-privacy-test-001"
    assert authenticated.expires_at == now + timedelta(seconds=DEFAULT_LIFETIME_SECONDS)


def test_direct_service_profile_cannot_be_reused_as_mesh_audience() -> None:
    issuer = DirectServiceTokenIssuer(signing_key())
    with pytest.raises(ValueError, match="unsupported direct-service audience"):
        issuer.issue_for_principal(
            principal=search_principal(PRIVACY_SHIELD_VERIFY_SCOPE),
            audience="goreecloud-mesh",
            requested_scopes=[PRIVACY_SHIELD_VERIFY_SCOPE],
        )


def test_only_explicitly_approved_service_identity_can_receive_privacy_shield_token() -> None:
    with pytest.raises(PermissionError, match="not approved"):
        VerifiedDirectServicePrincipal(
            service_id="goreecloud-browser",
            audience_scopes={
                PRIVACY_SHIELD_AUDIENCE: frozenset({PRIVACY_SHIELD_VERIFY_SCOPE})
            },
            authentication_context="workload:goreecloud-browser",
        )


def test_principal_scope_ceiling_prevents_direct_service_escalation() -> None:
    issuer = DirectServiceTokenIssuer(signing_key())
    with pytest.raises(PermissionError, match="not authorized"):
        issuer.issue_for_principal(
            principal=search_principal(PRIVACY_SHIELD_VERIFY_SCOPE),
            audience=PRIVACY_SHIELD_AUDIENCE,
            requested_scopes=[PRIVACY_SHIELD_CONSUME_SCOPE],
        )


def test_verifier_requires_operation_scope_independently_from_identity() -> None:
    key = signing_key()
    issuer = DirectServiceTokenIssuer(key)
    now = datetime(2026, 9, 14, 20, 0, tzinfo=UTC)
    token = issuer.issue_for_principal(
        principal=search_principal(PRIVACY_SHIELD_VERIFY_SCOPE),
        audience=PRIVACY_SHIELD_AUDIENCE,
        requested_scopes=[PRIVACY_SHIELD_VERIFY_SCOPE],
        now=now,
    )

    with pytest.raises(PermissionError, match="missing a required scope"):
        DirectServiceTokenVerifier(issuer.jwks()).verify(
            token,
            audience=PRIVACY_SHIELD_AUDIENCE,
            required_scopes=[PRIVACY_SHIELD_CONSUME_SCOPE],
            now=now,
        )


def test_verifier_rejects_subject_service_id_mismatch() -> None:
    key = signing_key()
    issuer = DirectServiceTokenIssuer(key)
    now = datetime(2026, 9, 14, 20, 0, tzinfo=UTC)
    token = jwt.encode(
        {
            "iss": "goreecloud-identity",
            "aud": PRIVACY_SHIELD_AUDIENCE,
            "sub": "service:goreecloud-browser",
            "service_id": "goreecloud-search",
            "scope": PRIVACY_SHIELD_VERIFY_SCOPE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "subject-mismatch",
        },
        key.private_key,
        algorithm="RS256",
        headers={"kid": key.kid, "typ": "JWT"},
    )

    with pytest.raises(ValueError, match="subject must match service_id"):
        DirectServiceTokenVerifier(issuer.jwks()).verify(
            token,
            audience=PRIVACY_SHIELD_AUDIENCE,
            now=now,
        )


def test_verifier_rejects_token_selected_verification_key_source() -> None:
    key = signing_key()
    issuer = DirectServiceTokenIssuer(key)
    now = datetime(2026, 9, 14, 20, 0, tzinfo=UTC)
    token = jwt.encode(
        {
            "iss": "goreecloud-identity",
            "aud": PRIVACY_SHIELD_AUDIENCE,
            "sub": "service:goreecloud-search",
            "service_id": "goreecloud-search",
            "scope": PRIVACY_SHIELD_VERIFY_SCOPE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "bad-key-source",
        },
        key.private_key,
        algorithm="RS256",
        headers={
            "kid": key.kid,
            "typ": "JWT",
            "jku": "https://attacker.invalid/jwks.json",
        },
    )

    with pytest.raises(ValueError, match="must not select or embed verification keys"):
        DirectServiceTokenVerifier(issuer.jwks()).verify(
            token,
            audience=PRIVACY_SHIELD_AUDIENCE,
            now=now,
        )


def test_verifier_rejects_expired_token_with_bounded_clock_skew() -> None:
    issuer = DirectServiceTokenIssuer(signing_key())
    now = datetime(2026, 9, 14, 20, 0, tzinfo=UTC)
    token = issuer.issue_for_principal(
        principal=search_principal(PRIVACY_SHIELD_VERIFY_SCOPE),
        audience=PRIVACY_SHIELD_AUDIENCE,
        requested_scopes=[PRIVACY_SHIELD_VERIFY_SCOPE],
        lifetime_seconds=60,
        now=now,
    )

    with pytest.raises(ValueError, match="expired"):
        DirectServiceTokenVerifier(issuer.jwks()).verify(
            token,
            audience=PRIVACY_SHIELD_AUDIENCE,
            now=now + timedelta(seconds=121),
        )


def test_jwks_contains_only_public_key_material() -> None:
    issuer = DirectServiceTokenIssuer(signing_key())
    jwks = issuer.jwks()
    assert len(jwks["keys"]) == 1
    public = jwks["keys"][0]
    assert public["kty"] == "RSA"
    assert public["alg"] == "RS256"
    assert public["use"] == "sig"
    for private_parameter in ("d", "p", "q", "dp", "dq", "qi", "oth"):
        assert private_parameter not in public


def test_environment_key_source_is_separate_from_mesh_configuration(tmp_path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "direct-service.pem"
    write_private_key(private_path, private_key)

    issuer = DirectServiceTokenIssuer.from_environment(
        {
            ACTIVE_KID_ENV: "direct-key-file-2026",
            ACTIVE_PRIVATE_KEY_FILE_ENV: str(private_path),
            RETAINED_PUBLIC_KEY_FILES_ENV: "{}",
            "GOREECLOUD_MESH_ACTIVE_KID": "mesh-key-must-not-be-used",
        }
    )

    assert issuer.active_kid == "direct-key-file-2026"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
def test_private_key_file_requires_owner_only_permissions(tmp_path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "direct-service.pem"
    write_private_key(private_path, private_key)
    private_path.chmod(0o640)

    with pytest.raises(ValueError, match="owner-only permissions"):
        DirectServiceTokenIssuer.from_key_files(
            active_kid="direct-key-permissions",
            active_private_key_file=private_path,
        )
