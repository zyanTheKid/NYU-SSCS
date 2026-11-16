"""Tests for the RFC 6962 Merkle proof helpers in merkle_proof.py."""

import base64

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
)

hasher = DefaultHasher
leaves = [hasher.hash_leaf(x) for x in (b"a", b"b", b"c", b"d")]
leftNode = hasher.hash_children(leaves[0], leaves[1])
rightNode = hasher.hash_children(leaves[2], leaves[3])
rootFour = hasher.hash_children(leftNode, rightNode)
rootThree = hasher.hash_children(leftNode, leaves[2])
badRoot = "00" * 32


def testHashLeafUsesDomainSeparation() -> None:
    assert hasher.hash_leaf(b"a") != hasher.new().digest()
    assert hasher.size() == 32
    assert len(hasher.empty_root()) == 32


def testInclusionProofValid() -> None:
    proof = [leaves[3].hex(), leftNode.hex()]
    verify_inclusion(hasher, 2, 4, leaves[2].hex(), proof, rootFour.hex(), debug=True)


def testInclusionProofTamperedRootRaises() -> None:
    proof = [leaves[3].hex(), leftNode.hex()]
    with pytest.raises(RootMismatchError) as errorInfo:
        verify_inclusion(hasher, 2, 4, leaves[2].hex(), proof, badRoot)
    assert "does not match" in str(errorInfo.value)


def testInclusionIndexBeyondSizeRaises() -> None:
    with pytest.raises(ValueError, match="index is beyond size"):
        root_from_inclusion_proof(hasher, 4, 4, leaves[0], [])


def testInclusionWrongProofLengthRaises() -> None:
    with pytest.raises(ValueError, match="wrong proof size"):
        root_from_inclusion_proof(hasher, 2, 4, leaves[2], [leaves[3]])


def testInclusionWrongLeafSizeRaises() -> None:
    with pytest.raises(ValueError, match="leaf_hash has unexpected size"):
        root_from_inclusion_proof(hasher, 2, 4, b"short", [])


def testConsistencyProofValid() -> None:
    verify_consistency(hasher, 2, 4, [rightNode.hex()], leftNode.hex(), rootFour.hex())
    proofThree = [leaves[2].hex(), leaves[3].hex(), leftNode.hex()]
    verify_consistency(hasher, 3, 4, proofThree, rootThree.hex(), rootFour.hex())


def testConsistencySameSizeAndEmptyCases() -> None:
    verify_consistency(hasher, 4, 4, [], rootFour.hex(), rootFour.hex())
    verify_consistency(hasher, 0, 4, [], rootFour.hex(), rootFour.hex())


@pytest.mark.parametrize(
    ("oldSize", "newSize", "proof", "errorMessage"),
    [
        (4, 2, [], "size2"),
        (4, 4, [badRoot], "not empty"),
        (0, 4, [badRoot], "expected empty"),
        (2, 4, [], "empty bytearray_proof"),
        (3, 4, [badRoot], "wrong bytearray_proof size"),
    ],
)
def testConsistencyInvalidInputsRaise(
    oldSize: int, newSize: int, proof: list[str], errorMessage: str
) -> None:
    with pytest.raises(ValueError, match=errorMessage):
        verify_consistency(
            hasher, oldSize, newSize, proof, rootThree.hex(), rootFour.hex()
        )


def testConsistencyTamperedRootRaises() -> None:
    with pytest.raises(RootMismatchError):
        verify_consistency(hasher, 2, 4, [rightNode.hex()], leftNode.hex(), badRoot)


def testComputeLeafHashMatchesHasher() -> None:
    entryBody = base64.b64encode(b"entry").decode()
    assert compute_leaf_hash(entryBody) == hasher.hash_leaf(b"entry").hex()
