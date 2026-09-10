from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    AUDIENCE,
    ISSUER,
    MeshServiceTokenIssuer,
    MeshSigningKey,
    VerifiedWorkloadPrincipal,
)


def issuer() -> MeshServiceTokenIssuer:
    return MeshServiceTokenIssuer(
        MeshSigningKey(
            kid="mesh-key-temporal-bounds",
            private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        )
    )


def principal() -> VerifiedWorkloadPrincipal:
    return VerifiedWorkloadPrincipal(
        service_id="goreecloud-manager",
        allowed_scopes=frozenset({"mesh.events.read"}),
        authentication_context="workload:goreecloud-manager",
    )


def test_rejects_not_before_at_or_after_expiry() -> None:
    token_issuer = issuer()
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
    token_issuer = issuer()
    now = datetime(2026, 9, 10, 5, 30, tzinfo=UTC)
    token = token_issuer.issue_for_principal(
        principal=principal(),
        requested_scopes=["mesh.events.read"],
        lifetime_seconds=60,
        now=now,
        not_before=now + timedelta(seconds=30),
        jti="temporal-window-accepted",
    )

    key = token_issuer._active_key.private_key.public_key()  # test-only inspection
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": False, "verify_nbf": False},
    )
    assert claims["iat"] < claims["nbf"] < claims["exp"]
