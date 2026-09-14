import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from authentik.goreecloud.mesh_service_token import (
    MAX_PRIVATE_KEY_FILE_BYTES,
    MeshSigningKey,
)


def private_key_bytes() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def test_private_signing_key_file_rejects_symlink(tmp_path) -> None:
    real_path = tmp_path / "real-private.pem"
    real_path.write_bytes(private_key_bytes())
    link_path = tmp_path / "linked-private.pem"
    link_path.symlink_to(real_path)

    with pytest.raises(ValueError, match="symbolic link"):
        MeshSigningKey.from_private_key_file(kid="mesh-key-symlink", path=link_path)


def test_private_signing_key_file_rejects_group_or_other_writable_mode(tmp_path) -> None:
    key_path = tmp_path / "unsafe-private.pem"
    key_path.write_bytes(private_key_bytes())
    os.chmod(key_path, 0o666)

    with pytest.raises(ValueError, match="writable by group or other"):
        MeshSigningKey.from_private_key_file(kid="mesh-key-mode", path=key_path)


def test_private_signing_key_file_rejects_oversized_input(tmp_path) -> None:
    key_path = tmp_path / "oversized-private.pem"
    key_path.write_bytes(b"x" * (MAX_PRIVATE_KEY_FILE_BYTES + 1))
    os.chmod(key_path, 0o600)

    with pytest.raises(ValueError, match="between 1 and"):
        MeshSigningKey.from_private_key_file(kid="mesh-key-oversized", path=key_path)
