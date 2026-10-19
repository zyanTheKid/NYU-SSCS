"""Shared fixtures: a Rekor log entry rebuilt offline from artifact.bundle."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest

repoRoot = Path(__file__).resolve().parent.parent


def b64ToHex(value: str) -> str:
    """Convert a base64 string (as stored in the bundle) to hex."""
    return base64.b64decode(value).hex()


@pytest.fixture
def artifactPath() -> Path:
    """Path to the artifact that was signed in Assignment 1."""
    return repoRoot / "artifact.md"


@pytest.fixture
def logEntry() -> dict[str, Any]:
    """Build the same dict Rekor's /log/entries API returns, from the bundle.

    The bundle stores hashes in base64 and numbers as strings; the API uses
    hex strings and integers, so convert them here.
    """
    bundle = json.loads((repoRoot / "artifact.bundle").read_text())
    tlogEntry = bundle["verificationMaterial"]["tlogEntries"][0]
    inclusionProof = tlogEntry["inclusionProof"]
    return {
        "body": tlogEntry["canonicalizedBody"],
        "logIndex": int(tlogEntry["logIndex"]),
        "verification": {
            "inclusionProof": {
                "logIndex": int(inclusionProof["logIndex"]),
                "treeSize": int(inclusionProof["treeSize"]),
                "rootHash": b64ToHex(inclusionProof["rootHash"]),
                "hashes": [b64ToHex(h) for h in inclusionProof["hashes"]],
            }
        },
    }
