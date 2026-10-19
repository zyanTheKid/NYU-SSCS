"""Helpers for extracting public keys and verifying artifact signatures."""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def extract_public_key(cert: bytes) -> bytes:
    """Return the PEM-encoded public key from a PEM-encoded certificate."""
    certificate = x509.load_pem_x509_certificate(cert)
    public_key = certificate.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_public_key


def verify_artifact_signature(
    signature: bytes, public_key: bytes, artifact_filename: str
) -> bool:
    """Verify an ECDSA-SHA256 signature over the artifact file.

    Returns True if the signature is valid, False otherwise.
    """
    loadedKey = load_pem_public_key(public_key)
    if not isinstance(loadedKey, ec.EllipticCurvePublicKey):
        raise TypeError("The provided public key is not an ECDSA public key.")

    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    try:
        loadedKey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Signature is invalid")
        return False
    return True
