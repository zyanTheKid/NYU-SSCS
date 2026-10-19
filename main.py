import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

# Imports
import json, requests, base64, sys

reckor = "https://rekor.sigstore.dev/api/v1"

REQUEST_TIMEOUT = 10  # seconds

def get_log_entry(log_index, debug=False):
    # TODO: verify that log index value is sane
    url = requests.get(f"{reckor}/log/entries", params={"logIndex": log_index}, timeout=REQUEST_TIMEOUT)
    url.raise_for_status()
    data = url.json()
    uuid = list(data.keys())[0]
    return data[uuid]
    # pass

def get_verification_proof(log_index, debug=False):
    # TODO: verify that log index value is sane
    entry = get_log_entry(log_index)
    return entry["verification"]["inclusionProof"]
    # pass

def inclusion(log_index, artifact_filepath, debug=False):
    # TODO::
    # verify that log index and artifact filepath values are sane
    entry = get_log_entry(log_index)
    
    body = json.loads(base64.b64decode(entry["body"]))
    signature = base64.b64decode(body["spec"]["signature"]["content"])
    certificate = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])

    # extract_public_key(certificate)
    publicKey = extract_public_key(certificate)

    # verify_artifact_signature(signature, public_key, artifact_filepath)
    if not verify_artifact_signature(signature, publicKey, artifact_filepath):
        print("Artifact signature verification failed")
        sys.exit(1)

    # get_verification_proof(log_index)
    proof = entry["verification"]["inclusionProof"]
    leafHash = compute_leaf_hash(entry["body"])

    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    verify_inclusion(DefaultHasher, proof["logIndex"], proof["treeSize"], leafHash, proof["hashes"], proof["rootHash"])
    
    print("Offline Verification Successful")
    # pass
    
def get_latest_checkpoint(debug=False):
    # TODO: Fetch the latest checkpoint from rekor
    url = requests.get(f"{reckor}/log", timeout=REQUEST_TIMEOUT)
    url.raise_for_status()
    return url.json()
    # pass

def consistency(prev_checkpoint, debug=False):
    # TODO: 
    # verify that prev checkpoint is not empty
    latestCheckpoint = get_latest_checkpoint()

    # get_latest_checkpoint()
    url = requests.get(f"{reckor}/log/proof", params={"firstSize": prev_checkpoint["treeSize"], "lastSize": latestCheckpoint["treeSize"], "treeId": prev_checkpoint["treeID"]}, timeout=REQUEST_TIMEOUT)
    url.raise_for_status()
    proof = url.json()["hashes"]

    verify_consistency(DefaultHasher, prev_checkpoint["treeSize"], latestCheckpoint["treeSize"], proof, prev_checkpoint["rootHash"], latestCheckpoint["rootHash"])

    print("Consistency Verification Successful")
    # pass

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()

    # Validate argument combinations before doing any work
    if args.inclusion is not None and not args.artifact:
        parser.error("--inclusion requires --artifact")

    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
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

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
