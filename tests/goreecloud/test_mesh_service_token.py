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
    ISSUER,
    RETAINED_PUBLIC_KEY_FILES_ENV,
    MeshServiceTokenIssuer,
    MeshSigningKey,
    MeshVerificationKey,
    VerifiedWorkloadPrincipal,
)

EXPECTED_TOKEN_LIFETIME_SECONDS = 300


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
        lifetime_seconds=EXPECTED_TOKEN_LIFETIME_SECONDS,
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
    assert claims["exp"] - claims["iat"] == EXPECTED_TOKEN_LIFETIME_SECONDS
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


def test_event_read_scope_is_workload_bound_and_non_escalating() -> None:
    key = signing_key("mesh-key-event-read")
    issuer = MeshServiceTokenIssuer(key)
    now = datetime(2026, 9, 5, 10, 15, tzinfo=UTC)

    consumer = principal("mesh-event-consumer", "mesh.events.read")
    token = issuer.issue_for_principal(
        principal=consumer,
        requested_scopes=["mesh.events.read"],
        lifetime_seconds=60,
        now=now,
        jti="mesh-event-read-001",
    )
    claims = jwt.decode(
        token,
        key.private_key.public_key(),
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_nbf": False},
    )
    assert claims["service_id"] == "mesh-event-consumer"
    assert claims["scope"] == "mesh.events.read"

    with pytest.raises(PermissionError, match="not authorized"):
        issuer.issue_for_principal(
            principal=consumer,
            requested_scopes=["mesh.events.read", "mesh.evidence.read"],
            lifetime_seconds=60,
            now=now,
        )


def test_platform_registry_scopes_are_workload_bound_and_non_escalating() -> None:
    key = signing_key("mesh-key-platform-registry")
    issuer = MeshServiceTokenIssuer(key)
    now = datetime(2026, 9, 3, 21, 5, tzinfo=UTC)

    manager = principal("goreecloud-manager", "mesh.platform-registry.read")
    read_token = issuer.issue_for_principal(
        principal=manager,
        requested_scopes=["mesh.platform-registry.read"],
        lifetime_seconds=60,
        now=now,
        jti="manager-platform-read-001",
    )
    read_claims = jwt.decode(
        read_token,
        key.private_key.public_key(),
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_nbf": False},
    )
    assert read_claims["service_id"] == "goreecloud-manager"
    assert read_claims["scope"] == "mesh.platform-registry.read"

    with pytest.raises(PermissionError, match="not authorized"):
        issuer.issue_for_principal(
            principal=manager,
            requested_scopes=["mesh.platform-registry.write"],
            lifetime_seconds=60,
            now=now,
        )

    producer = principal(
        "goreecloud-privacy-shield",
        "mesh.platform-registry.write",
    )
    write_token = issuer.issue_for_principal(
        principal=producer,
        requested_scopes=["mesh.platform-registry.write"],
        lifetime_seconds=60,
        now=now,
        jti="privacy-platform-write-001",
    )
    write_claims = jwt.decode(
        write_token,
        key.private_key.public_key(),
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_nbf": False},
    )
    assert write_claims["service_id"] == "goreecloud-privacy-shield"
    assert write_claims["scope"] == "mesh.platform-registry.write"


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
    # Intentional weak-key rejection test; verifies the enforced 2048-bit minimum.
    weak = rsa.generate_private_key(  # nosec B505
        public_exponent=65537,
        key_size=1024,
    )
    with pytest.raises(ValueError, match="at least 2048 bits"):
        MeshSigningKey(kid="mesh-key-weak", private_key=weak)

    first = signing_key("mesh-key-duplicate")
    second = signing_key("mesh-key-duplicate").verification_key()
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
