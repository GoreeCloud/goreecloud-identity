from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    MeshServiceTokenIssuer,
    MeshSigningKey,
    VerifiedWorkloadPrincipal,
)


def signing_key(kid: str = "mesh-key-canonical") -> MeshSigningKey:
    return MeshSigningKey(
        kid=kid,
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


def test_verified_principal_rejects_whitespace_normalized_identity() -> None:
    with pytest.raises(ValueError, match="canonical"):
        VerifiedWorkloadPrincipal(
            service_id=" everkeep",
            allowed_scopes=frozenset({"mesh.evidence.write"}),
            authentication_context="workload:everkeep",
        )

    with pytest.raises(ValueError, match="canonical"):
        VerifiedWorkloadPrincipal(
            service_id="everkeep",
            allowed_scopes=frozenset({"mesh.evidence.write"}),
            authentication_context="workload:everkeep ",
        )


def test_scope_and_key_id_must_be_canonical_before_issuance() -> None:
    with pytest.raises(ValueError, match="canonical"):
        VerifiedWorkloadPrincipal(
            service_id="everkeep",
            allowed_scopes=frozenset({" mesh.evidence.write"}),
            authentication_context="workload:everkeep",
        )

    with pytest.raises(ValueError, match="canonical"):
        signing_key(" mesh-key-canonical")


def test_requested_scope_and_jti_are_not_silently_trimmed() -> None:
    issuer = MeshServiceTokenIssuer(signing_key())
    principal = VerifiedWorkloadPrincipal(
        service_id="everkeep",
        allowed_scopes=frozenset({"mesh.evidence.write"}),
        authentication_context="workload:everkeep",
    )

    with pytest.raises(ValueError, match="canonical"):
        issuer.issue_for_principal(
            principal=principal,
            requested_scopes=["mesh.evidence.write "],
            now=datetime(2026, 9, 12, 8, 15, tzinfo=UTC),
        )

    with pytest.raises(ValueError, match="canonical"):
        issuer.issue_for_principal(
            principal=principal,
            requested_scopes=["mesh.evidence.write"],
            now=datetime(2026, 9, 12, 8, 15, tzinfo=UTC),
            jti=" replay-id ",
        )
