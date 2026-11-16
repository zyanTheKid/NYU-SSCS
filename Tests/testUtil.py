"""Tests for certificate and signature helpers in util.py."""

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from util import extract_public_key, verify_artifact_signature


def makeSelfSignedCert(privateKey: ec.EllipticCurvePrivateKey) -> bytes:
    """Create a throwaway self-signed certificate for privateKey (PEM bytes)."""
    subjectName = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subjectName)
        .issuer_name(subjectName)
        .public_key(privateKey.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(privateKey, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def testExtractPublicKeyReturnsPem() -> None:
    privateKey = ec.generate_private_key(ec.SECP256R1())
    publicPem = extract_public_key(makeSelfSignedCert(privateKey))
    assert publicPem.startswith(b"-----BEGIN PUBLIC KEY-----")


def testValidSignatureReturnsTrue(tmp_path: Path) -> None:
    privateKey = ec.generate_private_key(ec.SECP256R1())
    artifactFile = tmp_path / "artifact.md"
    artifactFile.write_bytes(b"hello\n")
    signature = privateKey.sign(b"hello\n", ec.ECDSA(hashes.SHA256()))
    publicPem = extract_public_key(makeSelfSignedCert(privateKey))
    assert verify_artifact_signature(signature, publicPem, str(artifactFile)) is True


def testTamperedArtifactReturnsFalse(tmp_path: Path) -> None:
    privateKey = ec.generate_private_key(ec.SECP256R1())
    artifactFile = tmp_path / "artifact.md"
    artifactFile.write_bytes(b"tampered\n")
    signature = privateKey.sign(b"hello\n", ec.ECDSA(hashes.SHA256()))
    publicPem = extract_public_key(makeSelfSignedCert(privateKey))
    assert verify_artifact_signature(signature, publicPem, str(artifactFile)) is False


def testNonEcKeyRaisesTypeError(tmp_path: Path) -> None:
    rsaKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsaPem = rsaKey.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    artifactFile = tmp_path / "artifact.md"
    artifactFile.write_bytes(b"hello\n")
    with pytest.raises(TypeError):
        verify_artifact_signature(b"sig", rsaPem, str(artifactFile))
