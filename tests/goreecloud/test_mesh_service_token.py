from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    AUDIENCE,
    ISSUER,
    MeshServiceTokenIssuer,
    MeshSigningKey,
)


def signing_key(kid: str) -> MeshSigningKey:
    return MeshSigningKey(kid=kid, private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))


def test_issues_rs256_mesh_service_token_bound_to_service_and_scope() -> None:
    key = signing_key("mesh-key-2026-08")
    issuer = MeshServiceTokenIssuer(key)
    now = datetime(2026, 8, 27, 2, 45, tzinfo=UTC)

    token = issuer.issue(
        service_id="wardveil-security",
        scopes=["mesh.evidence.write"],
        lifetime_seconds=300,
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
    assert claims["exp"] - claims["iat"] == 300
    assert claims["jti"] == "wardveil-test-001"


def test_jwks_contains_public_active_and_retained_keys_without_private_material() -> None:
    active = signing_key("mesh-key-active")
    retained = signing_key("mesh-key-retained")
    issuer = MeshServiceTokenIssuer(active, [retained])

    jwks = issuer.jwks()
    assert [item["kid"] for item in jwks["keys"]] == [active.kid, retained.kid]
    for item in jwks["keys"]:
        assert item["kty"] == "RSA"
        assert item["alg"] == "RS256"
        assert item["use"] == "sig"
        assert "n" in item and "e" in item
        assert "d" not in item


def test_rejects_unknown_scope_excessive_lifetime_and_invalid_service_id() -> None:
    issuer = MeshServiceTokenIssuer(signing_key("mesh-key-validation"))
    with pytest.raises(ValueError, match="unsupported Mesh scope"):
        issuer.issue(service_id="everkeep", scopes=["mesh.root"], lifetime_seconds=60)
    with pytest.raises(ValueError, match="between 1 and 900"):
        issuer.issue(service_id="everkeep", scopes=["mesh.evidence.write"], lifetime_seconds=901)
    with pytest.raises(ValueError, match="canonical lowercase"):
        issuer.issue(service_id="Everkeep", scopes=["mesh.evidence.write"], lifetime_seconds=60)


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
        issuer.issue(
            service_id="privacy-shield",
            scopes=["mesh.evidence.write"],
            lifetime_seconds=60,
            now=datetime(2026, 8, 27, 2, 45),
        )
