"""Command-line verifier for the Sigstore Rekor transparency log."""

import argparse
import base64
import json
import sys
from typing import Any

import requests

from merkle_proof import (
    DefaultHasher,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from util import extract_public_key, verify_artifact_signature

reckor = "https://rekor.sigstore.dev/api/v1"

REQUEST_TIMEOUT = 10  # seconds


def get_log_entry(log_index: int, debug: bool = False) -> dict[str, Any]:
    """Fetch a single entry from the Rekor log by its log index."""
    url = requests.get(
        f"{reckor}/log/entries",
        params={"logIndex": log_index},
        timeout=REQUEST_TIMEOUT,
    )
    url.raise_for_status()
    data: dict[str, Any] = url.json()
    uuid = list(data.keys())[0]
    entry: dict[str, Any] = data[uuid]
    return entry


def get_verification_proof(log_index: int, debug: bool = False) -> dict[str, Any]:
    """Return the inclusion proof stored with a Rekor log entry."""
    entry = get_log_entry(log_index)
    proof: dict[str, Any] = entry["verification"]["inclusionProof"]
    return proof


def inclusion(log_index: int, artifact_filepath: str, debug: bool = False) -> None:
    """Verify the artifact's signature and its inclusion in the Rekor log."""
    entry = get_log_entry(log_index)

    body = json.loads(base64.b64decode(entry["body"]))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    certificate = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])

    publicKey = extract_public_key(certificate)

    if not verify_artifact_signature(signature, publicKey, artifact_filepath):
        print("Artifact signature verification failed")
        sys.exit(1)

    proof = entry["verification"]["inclusionProof"]
    leafHash = compute_leaf_hash(entry["body"])

    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        leafHash,
        proof["hashes"],
        proof["rootHash"],
    )

    print("Offline Verification Successful")


def get_latest_checkpoint(debug: bool = False) -> dict[str, Any]:
    """Fetch the latest signed checkpoint from Rekor."""
    url = requests.get(f"{reckor}/log", timeout=REQUEST_TIMEOUT)
    url.raise_for_status()
    checkpoint: dict[str, Any] = url.json()
    return checkpoint


def consistency(prev_checkpoint: dict[str, Any], debug: bool = False) -> None:
    """Verify that an older checkpoint is consistent with the latest one."""
    latestCheckpoint = get_latest_checkpoint()

    url = requests.get(
        f"{reckor}/log/proof",
        params={
            "firstSize": prev_checkpoint["treeSize"],
            "lastSize": latestCheckpoint["treeSize"],
            "treeId": prev_checkpoint["treeID"],
        },
        timeout=REQUEST_TIMEOUT,
    )
    url.raise_for_status()
    proof = url.json()["hashes"]

    verify_consistency(
        DefaultHasher,
        prev_checkpoint["treeSize"],
        latestCheckpoint["treeSize"],
        proof,
        prev_checkpoint["rootHash"],
        latestCheckpoint["rootHash"],
    )

    print("Consistency Verification Successful")


def main() -> None:
    """Parse command-line arguments and run the requested verification."""
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help=(
            "Verify inclusion of an entry in the Rekor Transparency Log using "
            "log index and artifact filename. Usage: --inclusion 126574567"
        ),
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()

    # Validate argument combinations before doing any work
    if args.inclusion is not None and not args.artifact:
        parser.error("--inclusion requires --artifact")

    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            parser.error("--consistency requires --tree-id")
        if not args.tree_size:
            parser.error("--consistency requires --tree-size")
        if not args.root_hash:
            parser.error("--consistency requires --root-hash")

        prev_checkpoint: dict[str, Any] = {
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash,
        }

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
