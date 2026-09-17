import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    MAX_PUBLIC_KEY_FILE_BYTES,
    MeshVerificationKey,
)


def write_public_key(path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_retained_public_key_rejects_symbolic_link(tmp_path) -> None:
    target = tmp_path / "retained-public.pem"
    link = tmp_path / "retained-public-link.pem"
    write_public_key(target)
    os.symlink(target, link)

    with pytest.raises(ValueError, match="must not be a symbolic link"):
        MeshVerificationKey.from_public_key_file(
            kid="mesh-key-retained-link",
            path=link,
        )


def test_retained_public_key_rejects_group_or_other_writable_file(tmp_path) -> None:
    path = tmp_path / "retained-public.pem"
    write_public_key(path)
    path.chmod(0o666)

    with pytest.raises(ValueError, match="must not be writable by group or other users"):
        MeshVerificationKey.from_public_key_file(
            kid="mesh-key-retained-mode",
            path=path,
        )


def test_retained_public_key_rejects_oversized_file_before_pem_parse(tmp_path) -> None:
    path = tmp_path / "retained-public.pem"
    path.write_bytes(b"A" * (MAX_PUBLIC_KEY_FILE_BYTES + 1))

    with pytest.raises(ValueError, match="must be between 1 and"):
        MeshVerificationKey.from_public_key_file(
            kid="mesh-key-retained-size",
            path=path,
        )
