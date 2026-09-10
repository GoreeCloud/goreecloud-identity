from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    MeshServiceTokenIssuer,
    MeshSigningKey,
    VerifiedWorkloadPrincipal,
)


def signing_key() -> MeshSigningKey:
    return MeshSigningKey(
        kid="mesh-key-temporal-bounds",
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def principal() -> VerifiedWorkloadPrincipal:
    return VerifiedWorkloadPrincipal(
        service_id="goreecloud-manager",
        allowed_scopes=frozenset({"mesh.events.read"}),
        authentication_context="workload:goreecloud-manager",
    )


def test_rejects_not_before_at_or_after_expiry() -> None:
    token_issuer = MeshServiceTokenIssuer(signing_key())
    now = datetime(2026, 9, 10, 5, 30, tzinfo=UTC)

    for offset in (1, 2, 60):
        with pytest.raises(ValueError, match="not_before must be before expiry"):
            token_issuer.issue_for_principal(
                principal=principal(),
                requested_scopes=["mesh.events.read"],
                lifetime_seconds=1,
                now=now,
                not_before=now + timedelta(seconds=offset),
            )


def test_allows_delayed_validity_window_when_nbf_precedes_expiry() -> None:
    key = signing_key()
    token_issuer = MeshServiceTokenIssuer(key)
    now = datetime(2026, 9, 10, 5, 30, tzinfo=UTC)
    token = token_issuer.issue_for_principal(
        principal=principal(),
        requested_scopes=["mesh.events.read"],
        lifetime_seconds=60,
        now=now,
        not_before=now + timedelta(seconds=30),
        jti="temporal-window-accepted",
    )

    claims = jwt.decode(
        token,
        key.private_key.public_key(),
        algorithms=["RS256"],
        options={
            "verify_signature": True,
            "verify_aud": False,
            "verify_iss": False,
            "verify_exp": False,
            "verify_nbf": False,
        },
    )
    assert claims["iat"] < claims["nbf"] < claims["exp"]
