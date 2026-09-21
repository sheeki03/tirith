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
import sys
import tempfile
import time

PRIMARY = "https://raw.githubusercontent.com/sheeki03/tirith/main/"
FALLBACK = "https://github.com/sheeki03/tirith/releases/download/threatdb-current/"
MAX_DB = 256 * 1024 * 1024
MAX_SEQUENCE = 9_007_199_254_740_990


class PublicationLag(ValueError):
    """A verified discovery pointer has not propagated the expected generation."""


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def object_document(data):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, "duplicate JSON key")
            result[name] = value
        return result
    def constant(_value):
        raise ValueError("non-finite JSON number")
    result = json.loads(data, object_pairs_hook=unique, parse_constant=constant)
    require(type(result) is dict, "published document must be an object")
    return result


def integer(value, maximum, label):
    require(type(value) is int and 0 <= value <= maximum, label + " must be a bounded integer")
    return value


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
    document = object_document(data)
    encoded = document.pop("signature", None)
    require(type(encoded) is str, "missing or invalid signature")
    signature = base64.b64decode(encoded, validate=True)
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


def asset_declaration(asset, format_version):
    require(type(asset) is dict, "published asset must be an object")
    required = {"filename", "format", "sha256", "size", "url"}
    require(required <= set(asset) <= required | {"min_tirith_version"}, "published asset has wrong schema")
    require(type(asset["format"]) is int and asset["format"] == format_version,
            "published asset format has wrong schema")
    if "min_tirith_version" in asset:
        require(type(asset["min_tirith_version"]) is str and 0 < len(asset["min_tirith_version"]) <= 128,
                "published minimum client version has wrong schema")
    url, size, digest = asset["url"], asset["size"], asset["sha256"]
    if type(size) is not int or not 172 <= size <= MAX_DB:
        raise ValueError("invalid published asset size")
    if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid published asset digest")
    prefix = "tirith-threatdb-" + ("v2-" if format_version == 2 else "")
    match = re.fullmatch(re.escape(prefix) + r"([1-9][0-9]*-[1-9][0-9]*)\.dat", asset["filename"]) if type(asset["filename"]) is str else None
    if type(url) is not str or not match or url != FALLBACK + asset["filename"]:
        raise ValueError("asset is outside the expected immutable publication namespace")
    return match[1]


def legacy_asset(manifest):
    require(set(manifest) == {"sha256", "size", "url", "version"}, "legacy pointer has wrong schema")
    integer(manifest["version"], MAX_SEQUENCE, "legacy sequence")
    require(type(manifest["url"]) is str, "legacy asset URL must be text")
    asset = {name: manifest[name] for name in ("sha256", "size", "url")}
    asset.update(filename=manifest["url"][len(FALLBACK):], format=1)
    asset_declaration(asset, 1)
    return asset


def index_assets(index):
    require(set(index) == {"assets", "manifest_version", "sequence"} and
            type(index["manifest_version"]) is int and index["manifest_version"] == 2,
            "v2 pointer has wrong schema")
    integer(index["sequence"], MAX_SEQUENCE, "v2 sequence")
    assets = index["assets"]
    require(type(assets) is list and len(assets) == 2 and all(type(row) is dict for row in assets),
            "published index is not a complete generation")
    require(all(type(row.get("format")) is int for row in assets) and
            sorted(row["format"] for row in assets) == [1, 2], "published index is not a complete generation")
    generations = {asset_declaration(row, row["format"]) for row in assets}
    require(len(generations) == 1, "published index mixes immutable run generations")
    return sorted(assets, key=lambda row: row["format"])


def validate_asset(asset, sequence, key, download):
    asset_declaration(asset, asset["format"])
    url, size, digest = asset["url"], asset["size"], asset["sha256"]
    data = download(url, MAX_DB)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("published asset size/digest mismatch")
    if data[:8] != b"TIRITHDB" or int.from_bytes(data[20:28], "little") != sequence:
        raise ValueError("published database identity/sequence mismatch")
    format_version = int.from_bytes(data[8:12], "little")
    if format_version != asset["format"] or data[76:108] != hashlib.sha256(key).digest():
        raise ValueError("published database format mismatch")
    verify_signature(data[:108] + data[172:], data[108:172], key)
    return {"url": url, "sha256": digest, "format": format_version, "sequence": sequence}


def verify_publication(sequence, v2_enabled, key, download=fetch):
    integer(sequence, MAX_SEQUENCE, "expected sequence")
    require(type(v2_enabled) is bool, "v2 mode must be boolean")
    # Validate every signed pointer's complete declaration before classifying
    # propagation lag. An earlier primary must not hide an invalid fallback.
    surfaces = []
    identities = {}
    lag = False
    for label, prefix in [("primary", PRIMARY), ("fallback", FALLBACK)]:
        manifest = signed_document(download(prefix + "threatdb-manifest.json", 65536), key)
        legacy = legacy_asset(manifest)
        documents = [("legacy", manifest["version"], manifest)]
        index, assets = None, []
        if v2_enabled:
            index = signed_document(download(prefix + "threatdb-index-v2.json", 65536), key)
            assets = index_assets(index)
            documents.append(("v2", index["sequence"], index))
            if index["sequence"] == manifest["version"]:
                require(all(legacy[name] == assets[0][name] for name in legacy),
                        "legacy and v2 pointers disagree at the same sequence")
        for kind, observed, document in documents:
            require(observed <= sequence, label + " pointer exposes an unexpected future generation")
            identity = canonical(document)
            previous = identities.setdefault((kind, observed), identity)
            require(previous == identity, "primary and fallback pointers equivocate at the same sequence")
            lag |= observed < sequence
        surfaces.append((label, legacy, index, assets))
    if lag:
        raise PublicationLag("a verified discovery pointer still exposes an earlier generation")
    checked = []
    for label, legacy, index, assets in surfaces:
        checked.append({"surface": label, **validate_asset(legacy, sequence, key, download)})
        if v2_enabled:
            for asset in assets:
                checked.append({"surface": label, **validate_asset(asset, sequence, key, download)})
            generation = asset_declaration(assets[0], 1)
            integrity = signed_document(download(FALLBACK + f"threatdb-source-integrity-{generation}.json", 1024 * 1024), key)
            provenance = object_document(download(FALLBACK + f"threatdb-source-provenance-{generation}.json", 1024 * 1024))
            require(type(provenance.get("schema_version")) is int and provenance["schema_version"] == 2 and
                    type(provenance.get("compiler_parse")) is dict and
                    type(provenance["compiler_parse"].get("schema_version")) is int and
                    provenance["compiler_parse"]["schema_version"] == 1, "unsupported source provenance schema")
            compiler = provenance.pop("compiler_parse")
            provenance.pop("integrity_bindings")
            expected = {"sequence", "manifest_version", "source_transaction_sha256", "registry_snapshot_sha256",
                        "compiler_metadata_sha256", "v1_filename", "v1_sha256", "v2_filename", "v2_sha256"}
            require(set(integrity) == expected, "published source evidence has wrong schema")
            require(all(type(integrity[name]) is str and re.fullmatch(r"[0-9a-f]{64}", integrity[name])
                        for name in expected if name.endswith("_sha256")), "published source evidence has invalid digest fields")
            if integer(integrity["sequence"], MAX_SEQUENCE, "source evidence sequence") != sequence or type(integrity["manifest_version"]) is not int or integrity["manifest_version"] != 1:
                raise ValueError("published source evidence generation mismatch")
            if hashlib.sha256(canonical(provenance) + b"\n").hexdigest() != integrity["source_transaction_sha256"] or hashlib.sha256(canonical(compiler)).hexdigest() != integrity["compiler_metadata_sha256"]:
                raise ValueError("published provenance integrity mismatch")
            for asset in assets:
                if integrity[f"v{asset['format']}_sha256"] != asset["sha256"] or integrity[f"v{asset['format']}_filename"] != asset["filename"]:
                    raise ValueError("source evidence does not bind published generation")
    return {"schema_version": 1, "status": "verified", "sequence": sequence, "checked": checked}


def verify_with_propagation_retry(sequence, v2_enabled, key, download=fetch, sleep=time.sleep):
    for attempt in range(3):
        try:
            return verify_publication(sequence, v2_enabled, key, download)
        except PublicationLag:
            if attempt == 2:
                raise
            sleep(10 * (attempt + 1))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--v2", choices=["true", "false"], required=True)
    parser.add_argument("--verify-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_with_propagation_retry(args.sequence, args.v2 == "true", args.verify_key.read_bytes())
        code = 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        category = ("propagation_timeout" if isinstance(error, PublicationLag) else
                    "transport_or_verifier_failure" if isinstance(error, (OSError, subprocess.SubprocessError)) else
                    "invalid_publication")
        report = {"schema_version": 1, "status": "refused", "sequence": args.sequence,
                  "failure_class": category, "error": str(error)[:2048]}
        code = 1
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
