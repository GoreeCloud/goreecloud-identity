"""Compatibility shim for the native GoreeCloud Identity Mesh token authority.

The substantive implementation now lives in ``goreecloud_identity.mesh_service_token``.
This module remains temporarily so inherited Authentik integration and older imports
continue to resolve while the native GoreeCloud Identity runtime is built out.
"""

from goreecloud_identity.mesh_service_token import (
    ACTIVE_KID_ENV,
    ACTIVE_PRIVATE_KEY_FILE_ENV,
    AUDIENCE,
    DEFAULT_LIFETIME_SECONDS,
    ISSUER,
    MAX_JTI_LENGTH,
    MAX_LIFETIME_SECONDS,
    MIN_RSA_KEY_SIZE_BITS,
    RETAINED_PUBLIC_KEY_FILES_ENV,
    MeshServiceTokenIssuer,
    MeshSigningKey,
    MeshVerificationKey,
    VerifiedWorkloadPrincipal,
)

__all__ = [
    "ACTIVE_KID_ENV",
    "ACTIVE_PRIVATE_KEY_FILE_ENV",
    "AUDIENCE",
    "DEFAULT_LIFETIME_SECONDS",
    "ISSUER",
    "MAX_JTI_LENGTH",
    "MAX_LIFETIME_SECONDS",
    "MIN_RSA_KEY_SIZE_BITS",
    "RETAINED_PUBLIC_KEY_FILES_ENV",
    "MeshServiceTokenIssuer",
    "MeshSigningKey",
    "MeshVerificationKey",
    "VerifiedWorkloadPrincipal",
]
