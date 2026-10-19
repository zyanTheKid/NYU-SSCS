"""Tests for main.py. Network calls to Rekor are mocked, so tests run offline."""

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import main
from merkle_proof import DefaultHasher

LOG_INDEX = 3064522293
CHECKPOINT = {"treeID": "1193050959916656506", "treeSize": 4, "rootHash": "ab"}


def fakeResponse(payload: Any) -> MagicMock:
    """Fake requests.Response whose .json() returns payload."""
    response = MagicMock()
    response.json.return_value = payload
    return response


def runCli(monkeypatch: pytest.MonkeyPatch, *cliArgs: str) -> None:
    """Run main.main() as if called from the command line."""
    monkeypatch.setattr(sys, "argv", ["main.py", *cliArgs])
    main.main()


def buildSmallTree() -> tuple[str, str, str]:
    """Return (root of first 2 leaves, right subtree, root of all 4 leaves)."""
    leaves = [DefaultHasher.hash_leaf(x) for x in (b"a", b"b", b"c", b"d")]
    leftNode = DefaultHasher.hash_children(leaves[0], leaves[1])
    rightNode = DefaultHasher.hash_children(leaves[2], leaves[3])
    rootHash = DefaultHasher.hash_children(leftNode, rightNode)
    return leftNode.hex(), rightNode.hex(), rootHash.hex()


def testGetLogEntryReturnsEntry(logEntry: dict[str, Any]) -> None:
    payload = {"some-uuid": logEntry}
    with patch("main.requests.get", return_value=fakeResponse(payload)) as mockGet:
        assert main.get_log_entry(LOG_INDEX) == logEntry
    assert mockGet.call_args.kwargs["timeout"] == main.REQUEST_TIMEOUT


def testGetVerificationProof(logEntry: dict[str, Any]) -> None:
    with patch("main.get_log_entry", return_value=logEntry):
        proof = main.get_verification_proof(LOG_INDEX)
    expectedSize = logEntry["verification"]["inclusionProof"]["treeSize"]
    assert proof["treeSize"] == expectedSize


def testGetLatestCheckpoint() -> None:
    with patch("main.requests.get", return_value=fakeResponse(CHECKPOINT)):
        assert main.get_latest_checkpoint()["treeSize"] == 4


def testInclusionValidArtifact(
    logEntry: dict[str, Any], artifactPath: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Real signature + real inclusion proof from the A1 bundle, no network."""
    with patch("main.get_log_entry", return_value=logEntry):
        main.inclusion(LOG_INDEX, str(artifactPath))
    assert "Offline Verification Successful" in capsys.readouterr().out


def testInclusionTamperedArtifactExits(
    logEntry: dict[str, Any], tmp_path: Path
) -> None:
    tamperedFile = tmp_path / "tampered.md"
    tamperedFile.write_text("not the signed content\n")
    with patch("main.get_log_entry", return_value=logEntry):
        with pytest.raises(SystemExit) as exitInfo:
            main.inclusion(LOG_INDEX, str(tamperedFile))
    assert exitInfo.value.code == 1


def testConsistencyValid(capsys: pytest.CaptureFixture[str]) -> None:
    oldRoot, rightNode, newRoot = buildSmallTree()
    latestCheckpoint = {"treeID": "1", "treeSize": 4, "rootHash": newRoot}
    responses = [fakeResponse(latestCheckpoint), fakeResponse({"hashes": [rightNode]})]
    with patch("main.requests.get", side_effect=responses):
        main.consistency({"treeID": "1", "treeSize": 2, "rootHash": oldRoot})
    assert "Consistency Verification Successful" in capsys.readouterr().out


def testCliCheckpointPrintsJson(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("main.requests.get", return_value=fakeResponse(CHECKPOINT)):
        runCli(monkeypatch, "-c", "-d")
    output = capsys.readouterr().out
    assert "enabled debug mode" in output
    printedJson = json.loads(output.split("\n", 1)[1])
    assert printedJson["treeID"] == CHECKPOINT["treeID"]


def testCliInclusion(
    monkeypatch: pytest.MonkeyPatch,
    logEntry: dict[str, Any],
    artifactPath: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch("main.get_log_entry", return_value=logEntry):
        runCli(
            monkeypatch, "--inclusion", str(LOG_INDEX), "--artifact", str(artifactPath)
        )
    assert "Offline Verification Successful" in capsys.readouterr().out


def testCliConsistency(monkeypatch: pytest.MonkeyPatch) -> None:
    with patch("main.consistency") as mockConsistency:
        runCli(
            monkeypatch,
            "--consistency",
            "--tree-id",
            "1",
            "--tree-size",
            "2",
            "--root-hash",
            "ab",
        )
    mockConsistency.assert_called_once_with(
        {"treeID": "1", "treeSize": 2, "rootHash": "ab"}, False
    )


@pytest.mark.parametrize(
    "cliArgs",
    [
        ["--inclusion", "5"],
        ["--consistency"],
        ["--consistency", "--tree-id", "1"],
        ["--consistency", "--tree-id", "1", "--tree-size", "2"],
    ],
)
def testCliMissingArgumentsExitWithCode2(
    monkeypatch: pytest.MonkeyPatch, cliArgs: list[str]
) -> None:
    with pytest.raises(SystemExit) as exitInfo:
        runCli(monkeypatch, *cliArgs)
    assert exitInfo.value.code == 2
