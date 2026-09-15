#!/usr/bin/env python3
"""Verify both published discovery surfaces with only the pinned public key.

Every reference is checked before pruning. Downloads are bounded, and successful
HTTP responses are validated once; invalid signatures/schema never trigger retry.
The CLI cold-cache smoke follows this independent publication consistency check.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

PRIMARY = "https://raw.githubusercontent.com/sheeki03/tirith/main/"
FALLBACK = "https://github.com/sheeki03/tirith/releases/download/threatdb-current/"
MAX_DB = 256 * 1024 * 1024


class PublicationLag(ValueError):
    """A verified discovery pointer has not propagated the expected generation."""


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify_signature(payload, signature, key):
    if len(key) != 32 or len(signature) != 64:
        raise ValueError("invalid Ed25519 key/signature length")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        (root / "payload").write_bytes(payload)
        (root / "signature").write_bytes(signature)
        result = subprocess.run([
            "openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
            "-inkey", str(root / "key.der"), "-rawin", "-in", str(root / "payload"),
            "-sigfile", str(root / "signature"),
        ], capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError("Ed25519 signature verification failed")


def signed_document(data, key):
    document = json.loads(data)
    signature = base64.b64decode(document.pop("signature"), validate=True)
    verify_signature(canonical(document), signature, key)
    return document


def fetch(url, limit):
    # URLs are fixed discovery locations or validated same-release filenames.
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "response"
        subprocess.run([
            "curl", "-sSfL", "--proto", "=https", "--proto-redir", "=https",
            "--connect-timeout", "15", "--max-time", "120", "--max-filesize", str(limit),
            "--retry", "2", "--retry-connrefused", "--retry-max-time", "240",
            url, "-o", str(output),
        ], check=True, timeout=260)
        data = output.read_bytes()
        if len(data) > limit:
            raise ValueError("published response exceeds byte cap")
        return data


def validate_asset(asset, sequence, key, download):
    url, size, digest = asset["url"], asset["size"], asset["sha256"]
    if not isinstance(size, int) or isinstance(size, bool) or not 172 <= size <= MAX_DB:
        raise ValueError("invalid published asset size")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid published asset digest")
    if not url.startswith(FALLBACK) or not re.fullmatch(r"tirith-threatdb-(?:v2-)?[0-9]+-[0-9]+\.dat", url[len(FALLBACK):]):
        raise ValueError("asset is outside the expected immutable publication namespace")
    if "filename" in asset and asset["filename"] != url[len(FALLBACK):]:
        raise ValueError("signed filename and URL disagree")
    data = download(url, MAX_DB)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("published asset size/digest mismatch")
    if data[:8] != b"TIRITHDB" or int.from_bytes(data[20:28], "little") != sequence:
        raise ValueError("published database identity/sequence mismatch")
    format_version = int.from_bytes(data[8:12], "little")
    if format_version != asset.get("format", 1):
        raise ValueError("published database format mismatch")
    verify_signature(data[:108] + data[172:], data[108:172], key)
    return {"url": url, "sha256": digest, "format": format_version, "sequence": sequence}


def verify_publication(sequence, v2_enabled, key, download=fetch):
    checked = []
    for label, prefix in [("primary", PRIMARY), ("fallback", FALLBACK)]:
        manifest = signed_document(download(prefix + "threatdb-manifest.json", 65536), key)
        if set(manifest) != {"sha256", "size", "url", "version"}:
            raise ValueError(f"{label} legacy pointer has wrong schema")
        if isinstance(manifest["version"], int) and manifest["version"] < sequence:
            raise PublicationLag(f"{label} legacy pointer still exposes an earlier generation")
        if manifest["version"] != sequence:
            raise ValueError(f"{label} legacy pointer has wrong schema or generation")
        checked.append({"surface": label, **validate_asset(manifest, sequence, key, download)})
        if v2_enabled:
            index = signed_document(download(prefix + "threatdb-index-v2.json", 65536), key)
            if set(index) != {"assets", "manifest_version", "sequence"} or index["manifest_version"] != 2:
                raise ValueError(f"{label} v2 pointer has wrong schema")
            if isinstance(index["sequence"], int) and index["sequence"] < sequence:
                raise PublicationLag(f"{label} v2 pointer still exposes an earlier generation")
            if index["sequence"] != sequence:
                raise ValueError(f"{label} v2 pointer has wrong schema or generation")
            if sorted(asset.get("format", 0) for asset in index["assets"]) != [1, 2]:
                raise ValueError("published index is not a complete generation")
            for asset in index["assets"]:
                checked.append({"surface": label, **validate_asset(asset, sequence, key, download)})
            generation = re.fullmatch(r"tirith-threatdb-(?:v2-)?([0-9]+-[0-9]+)\.dat", index["assets"][0]["filename"])[1]
            integrity = signed_document(download(FALLBACK + f"threatdb-source-integrity-{generation}.json", 1024 * 1024), key)
            provenance = json.loads(download(FALLBACK + f"threatdb-source-provenance-{generation}.json", 1024 * 1024))
            compiler = provenance.pop("compiler_parse")
            provenance.pop("integrity_bindings")
            if integrity["sequence"] != sequence or integrity["manifest_version"] != 1:
                raise ValueError("published source evidence generation mismatch")
            if hashlib.sha256(canonical(provenance) + b"\n").hexdigest() != integrity["source_transaction_sha256"] or hashlib.sha256(canonical(compiler)).hexdigest() != integrity["compiler_metadata_sha256"]:
                raise ValueError("published provenance integrity mismatch")
            for asset in index["assets"]:
                if integrity[f"v{asset['format']}_sha256"] != asset["sha256"]:
                    raise ValueError("source evidence does not bind published generation")
    return {"schema_version": 1, "status": "verified", "sequence": sequence, "checked": checked}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--v2", choices=["true", "false"], required=True)
    parser.add_argument("--verify-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for attempt in range(3):
        try:
            report = verify_publication(args.sequence, args.v2 == "true", args.verify_key.read_bytes())
            break
        except PublicationLag:
            if attempt == 2:
                raise
            time.sleep(10 * (attempt + 1))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
