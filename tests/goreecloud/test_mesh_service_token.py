import json
from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    ACTIVE_KID_ENV,
    ACTIVE_PRIVATE_KEY_FILE_ENV,
    AUDIENCE,
    DEFAULT_LIFETIME_SECONDS,
    ISSUER,
    RETAINED_PUBLIC_KEY_FILES_ENV,
    MeshServiceTokenIssuer,
    MeshSigningKey,
    MeshVerificationKey,
    VerifiedWorkloadPrincipal,
)


def signing_key(kid: str) -> MeshSigningKey:
    return MeshSigningKey(
        kid=kid,
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def principal(service_id: str, *scopes: str) -> VerifiedWorkloadPrincipal:
    return VerifiedWorkloadPrincipal(
        service_id=service_id,
        allowed_scopes=frozenset(scopes),
        authentication_context=f"workload:{service_id}",
    )


def write_private_key(path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def write_public_key(path, key: rsa.RSAPublicKey) -> None:
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_issues_rs256_mesh_service_token_bound_to_verified_principal_and_scope() -> None:
    key = signing_key("mesh-key-2026-08")
    issuer = MeshServiceTokenIssuer(key)
    now = datetime(2026, 8, 27, 2, 45, tzinfo=UTC)

    token = issuer.issue_for_principal(
        principal=principal("wardveil-security", "mesh.evidence.write"),
        requested_scopes=["mesh.evidence.write"],
        lifetime_seconds=DEFAULT_LIFETIME_SECONDS,
        now=now,
        jti="wardveil-test-001",
    )

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"] == key.kid

    claims = jwt.decode(
        token,
        key.private_key.public_key(),
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_nbf": False},
    )
    assert claims["sub"] == "service:wardveil-security"
    assert claims["service_id"] == "wardveil-security"
    assert claims["scope"] == "mesh.evidence.write"
    assert claims["exp"] - claims["iat"] == DEFAULT_LIFETIME_SECONDS
    assert claims["jti"] == "wardveil-test-001"


def test_public_arbitrary_service_id_issuance_api_is_not_exposed() -> None:
    issuer = MeshServiceTokenIssuer(signing_key("mesh-key-no-arbitrary-id"))
    assert not hasattr(issuer, "issue")
    with pytest.raises(TypeError, match="VerifiedWorkloadPrincipal"):
        issuer.issue_for_principal(  # type: ignore[arg-type]
            principal="wardveil-security",
            requested_scopes=["mesh.evidence.write"],
        )


def test_principal_scope_ceiling_prevents_escalation() -> None:
    issuer = MeshServiceTokenIssuer(signing_key("mesh-key-scope-ceiling"))
    verified = principal("privacy-shield", "mesh.evidence.write")

    with pytest.raises(PermissionError, match="not authorized"):
        issuer.issue_for_principal(
            principal=verified,
            requested_scopes=["mesh.evidence.write", "mesh.evidence.read"],
        )


def test_jwks_contains_public_active_and_retained_keys_without_private_material() -> None:
    active = signing_key("mesh-key-active")
    retained_private = signing_key("mesh-key-retained")
    retained = retained_private.verification_key()
    issuer = MeshServiceTokenIssuer(active, [retained])

    assert isinstance(retained, MeshVerificationKey)
    assert not hasattr(retained, "private_key")
    jwks = issuer.jwks()
    assert [item["kid"] for item in jwks["keys"]] == [active.kid, retained.kid]
    for item in jwks["keys"]:
        assert item["kty"] == "RSA"
        assert item["alg"] == "RS256"
        assert item["use"] == "sig"
        assert "n" in item and "e" in item
        for private_parameter in ("d", "p", "q", "dp", "dq", "qi", "oth"):
            assert private_parameter not in item


def test_loads_active_private_and_retained_public_keys_from_files(tmp_path) -> None:
    active_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    retained_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    active_path = tmp_path / "active-private.pem"
    retained_path = tmp_path / "retained-public.pem"
    write_private_key(active_path, active_private)
    write_public_key(retained_path, retained_private.public_key())

    issuer = MeshServiceTokenIssuer.from_environment(
        {
            ACTIVE_KID_ENV: "mesh-key-active-file",
            ACTIVE_PRIVATE_KEY_FILE_ENV: str(active_path),
            RETAINED_PUBLIC_KEY_FILES_ENV: json.dumps(
                {"mesh-key-retained-file": str(retained_path)}
            ),
        }
    )

    assert issuer.active_kid == "mesh-key-active-file"
    assert [item["kid"] for item in issuer.jwks()["keys"]] == [
        "mesh-key-active-file",
        "mesh-key-retained-file",
    ]

    token = issuer.issue_for_principal(
        principal=principal("everkeep", "mesh.evidence.write"),
        requested_scopes=["mesh.evidence.write"],
        lifetime_seconds=60,
    )
    assert jwt.get_unverified_header(token)["kid"] == "mesh-key-active-file"


def test_retained_rotation_configuration_rejects_private_key_files(tmp_path) -> None:
    active_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    retained_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    active_path = tmp_path / "active-private.pem"
    retained_private_path = tmp_path / "retained-private.pem"
    write_private_key(active_path, active_private)
    write_private_key(retained_private_path, retained_private)

    with pytest.raises(ValueError, match="valid PEM public key"):
        MeshServiceTokenIssuer.from_key_files(
            active_kid="mesh-key-active-private",
            active_private_key_file=active_path,
            retained_public_key_files={
                "mesh-key-retained-private": retained_private_path,
            },
        )


def test_key_source_configuration_fails_closed(tmp_path) -> None:
    with pytest.raises(ValueError, match="are required"):
        MeshServiceTokenIssuer.from_environment({})

    with pytest.raises(ValueError, match="JSON object"):
        MeshServiceTokenIssuer.from_environment(
            {
                ACTIVE_KID_ENV: "mesh-key-config",
                ACTIVE_PRIVATE_KEY_FILE_ENV: str(tmp_path / "missing.pem"),
                RETAINED_PUBLIC_KEY_FILES_ENV: "[]",
            }
        )

    invalid_path = tmp_path / "invalid.pem"
    invalid_path.write_text("not a private key")
    with pytest.raises(ValueError, match="valid unencrypted PEM"):
        MeshServiceTokenIssuer.from_key_files(
            active_kid="mesh-key-invalid",
            active_private_key_file=invalid_path,
        )

    with pytest.raises(ValueError, match="does not exist"):
        MeshServiceTokenIssuer.from_key_files(
            active_kid="mesh-key-missing",
            active_private_key_file=tmp_path / "missing.pem",
        )


def test_rejects_unknown_principal_scope_excessive_lifetime_and_invalid_service_id() -> None:
    with pytest.raises(ValueError, match="unsupported Mesh scope"):
        principal("everkeep", "mesh.root")
    with pytest.raises(ValueError, match="canonical lowercase"):
        principal("Everkeep", "mesh.evidence.write")

    issuer = MeshServiceTokenIssuer(signing_key("mesh-key-validation"))
    with pytest.raises(ValueError, match="between 1 and 900"):
        issuer.issue_for_principal(
            principal=principal("everkeep", "mesh.evidence.write"),
            requested_scopes=["mesh.evidence.write"],
            lifetime_seconds=901,
        )


def test_rejects_weak_keys_duplicate_kids_and_naive_time() -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ValueError, match="at least 2048 bits"):
        MeshSigningKey(kid="mesh-key-weak", private_key=weak)

    first = signing_key("mesh-key-duplicate")
    second = signing_key("mesh-key-duplicate")
    with pytest.raises(ValueError, match="must be unique"):
        MeshServiceTokenIssuer(first, [second])

    issuer = MeshServiceTokenIssuer(signing_key("mesh-key-naive-time"))
    with pytest.raises(ValueError, match="timezone-aware"):
        issuer.issue_for_principal(
            principal=principal("privacy-shield", "mesh.evidence.write"),
            requested_scopes=["mesh.evidence.write"],
            lifetime_seconds=60,
            now=datetime(2026, 8, 27, 2, 45),
        )
