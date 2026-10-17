#!/usr/bin/env python3
"""Capture or compare a quiescent directory tree without mutating its contents."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

CHUNK_SIZE = 1024 * 1024
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ManifestError(Exception):
    """Only fixed error codes, never file contents or arbitrary OS messages."""


def _plain(metadata):
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT:
        raise ManifestError("LINK_OR_REPARSE_POINT")


def _absolute(value):
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ManifestError("ABSOLUTE_PATH_REQUIRED")
    # Check before resolve(), which would otherwise conceal a junction/symlink.
    for component in [*reversed(path.parents), path]:
        _plain(component.lstat())
    return path.resolve(strict=True)


def _root(value):
    path = _absolute(value)
    if not path.is_dir():
        raise ManifestError("DIRECTORY_REQUIRED")
    return path


def _outside_file(value, root, *, must_exist):
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise ManifestError("ABSOLUTE_PATH_REQUIRED")
    parent = _absolute(candidate.parent)
    if not parent.is_dir():
        raise ManifestError("OUTPUT_PARENT_REQUIRED")
    path = parent / candidate.name
    if path == root or path.is_relative_to(root):
        raise ManifestError("EVIDENCE_MUST_BE_OUTSIDE_TREE")
    if must_exist:
        path = _absolute(path)
        if not path.is_file():
            raise ManifestError("MANIFEST_FILE_REQUIRED")
    elif os.path.lexists(path):
        raise ManifestError("OUTPUT_ALREADY_EXISTS")
    return path


def _signature(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _inventory(root):
    files, directories, signatures = {}, [], {}

    def visit(directory):
        metadata = directory.lstat()
        _plain(metadata)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ManifestError("TREE_CHANGED_DURING_SCAN")
        relative = directory.relative_to(root).as_posix()
        signatures[relative] = _signature(metadata)
        if directory != root:
            directories.append(relative)
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            child = directory / entry.name
            metadata = child.lstat()
            _plain(metadata)
            relative = child.relative_to(root).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                visit(child)
            elif stat.S_ISREG(metadata.st_mode):
                files[relative] = _signature(metadata)
                signatures[relative] = files[relative]
            else:
                raise ManifestError("UNSUPPORTED_FILE_TYPE")

    visit(root)
    return files, sorted(directories), signatures


def _hash_file(path, expected, advance):
    before = path.lstat()
    _plain(before)
    if _signature(before) != expected:
        raise ManifestError("TREE_CHANGED_DURING_SCAN")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = _signature(os.fstat(stream.fileno()))
        # Windows stat/lstat and fstat can give ctime different semantics.
        # Compare identity/size/mtime across APIs; compare ctime only within
        # the same API before and after the read, retaining both safeguards.
        if opened[:-1] != expected[:-1]:
            raise ManifestError("TREE_CHANGED_DURING_SCAN")
        digest, size = hashlib.sha256(), 0
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            advance(len(chunk))
        if _signature(os.fstat(stream.fileno())) != opened or size != before.st_size:
            raise ManifestError("TREE_CHANGED_DURING_SCAN")
    after = path.lstat()
    _plain(after)
    if _signature(after) != expected:
        raise ManifestError("TREE_CHANGED_DURING_SCAN")
    return size, digest.hexdigest()


def snapshot(root, progress=None):
    root = _root(root)
    files, directories, signatures = _inventory(root)
    records, total = [], 0

    def advance(count):
        nonlocal total
        total += count
        if progress:
            progress(len(records), total)

    for relative, signature in sorted(files.items()):
        size, digest = _hash_file(root / relative, signature, advance)
        records.append({"path": relative, "size": size, "sha256": digest})
    # Detect additions/removals and changes to files hashed earlier in this pass.
    if _inventory(root)[2] != signatures:
        raise ManifestError("TREE_CHANGED_DURING_SCAN")
    return {"schemaVersion": 1, "algorithm": "sha256", "sourceRoot": str(root),
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "files": records, "directories": directories,
            "counts": {"files": len(records), "directories": len(directories), "bytes": total}}


def _relative(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\x00" in value:
        raise ManifestError("INVALID_MANIFEST")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts) or PurePosixPath(value).is_absolute():
        raise ManifestError("INVALID_MANIFEST")
    return value


def validate_manifest(value):
    fields = {"schemaVersion", "algorithm", "sourceRoot", "capturedAt", "files", "directories", "counts"}
    if not isinstance(value, dict) or set(value) != fields or type(value["schemaVersion"]) is not int:
        raise ManifestError("INVALID_MANIFEST")
    if value["schemaVersion"] != 1 or value["algorithm"] != "sha256":
        raise ManifestError("INVALID_MANIFEST")
    if not all(isinstance(value[key], str) and value[key] for key in ["sourceRoot", "capturedAt"]):
        raise ManifestError("INVALID_MANIFEST")
    if not isinstance(value["files"], list) or not isinstance(value["directories"], list):
        raise ManifestError("INVALID_MANIFEST")
    seen, total = set(), 0
    directories = [_relative(item) for item in value["directories"]]
    if directories != sorted(set(directories)):
        raise ManifestError("INVALID_MANIFEST")
    for record in value["files"]:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise ManifestError("INVALID_MANIFEST")
        name = _relative(record["path"])
        if name in seen or name in directories or type(record["size"]) is not int or record["size"] < 0:
            raise ManifestError("INVALID_MANIFEST")
        if not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise ManifestError("INVALID_MANIFEST")
        seen.add(name)
        total += record["size"]
    if [item["path"] for item in value["files"]] != sorted(seen):
        raise ManifestError("INVALID_MANIFEST")
    directory_set = set(directories)
    for name in seen | directory_set:
        for parent in PurePosixPath(name).parents:
            if str(parent) != "." and str(parent) not in directory_set:
                raise ManifestError("INVALID_MANIFEST")
    expected = {"files": len(seen), "directories": len(directories), "bytes": total}
    if not isinstance(value["counts"], dict) or set(value["counts"]) != set(expected):
        raise ManifestError("INVALID_MANIFEST")
    if any(type(value["counts"][key]) is not int or value["counts"][key] != count for key, count in expected.items()):
        raise ManifestError("INVALID_MANIFEST")
    return value


def compare(expected, actual):
    validate_manifest(expected)
    validate_manifest(actual)
    before = {item["path"]: (item["size"], item["sha256"]) for item in expected["files"]}
    after = {item["path"]: (item["size"], item["sha256"]) for item in actual["files"]}
    return {"filesAdded": sorted(after.keys() - before.keys()),
            "filesRemoved": sorted(before.keys() - after.keys()),
            "filesChanged": sorted(name for name in before.keys() & after.keys() if before[name] != after[name]),
            "directoriesAdded": sorted(set(actual["directories"]) - set(expected["directories"])),
            "directoriesRemoved": sorted(set(expected["directories"]) - set(actual["directories"]))}


def write_new(path, value):
    # Exclusive creation preserves an existing checkpoint, including on failure.
    # Interrupted/partial JSON is rejected on load; use a new output path on retry.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def capture(root, manifest, progress=None):
    root = _root(root)
    destination = _outside_file(manifest, root, must_exist=False)
    value = snapshot(root, progress)
    validate_manifest(value)
    write_new(destination, value)
    return value


def verify(root, manifest, report, progress=None):
    root = _root(root)
    source = _outside_file(manifest, root, must_exist=True)
    destination = _outside_file(report, root, must_exist=False)
    if source == destination:
        raise ManifestError("OUTPUT_ALREADY_EXISTS")
    try:
        expected = validate_manifest(json.loads(source.read_text(encoding="utf-8")))
    except (ValueError, UnicodeError) as error:
        raise ManifestError("INVALID_MANIFEST") from error
    actual = snapshot(root, progress)
    differences = compare(expected, actual)
    value = {"schemaVersion": 1, "status": "matched" if not any(differences.values()) else "mismatch",
             "expectedRoot": expected["sourceRoot"], "verifiedRoot": str(root),
             "checkedAt": datetime.now(timezone.utc).isoformat(),
             "counts": actual["counts"], "differences": differences}
    write_new(destination, value)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ["capture", "verify"]:
        child = commands.add_parser(command)
        child.add_argument("--root", required=True)
        child.add_argument("--manifest", required=True)
        if command == "verify":
            child.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    started, last = time.monotonic(), 0.0

    def progress(files, size):
        nonlocal last
        now = time.monotonic()
        if now - last >= 5:
            print(json.dumps({"status": "hashing", "files": files, "bytes": size,
                              "elapsedSeconds": round(now - started, 1)}), file=sys.stderr, flush=True)
            last = now

    try:
        if args.command == "capture":
            value = capture(args.root, args.manifest, progress)
            result = {"status": "captured", **value["counts"]}
        else:
            value = verify(args.root, args.manifest, args.report, progress)
            result = {"status": value["status"], **value["counts"],
                      "differenceCounts": {key: len(rows) for key, rows in value["differences"].items()}}
        print(json.dumps(result), flush=True)
        return 1 if result["status"] == "mismatch" else 0
    except ManifestError as error:
        code = str(error)
    except PermissionError:
        code = "PERMISSION_DENIED"
    except FileNotFoundError:
        code = "PATH_UNAVAILABLE"
    except FileExistsError:
        code = "OUTPUT_ALREADY_EXISTS"
    except OSError:
        code = "FILESYSTEM_ERROR"
    except KeyboardInterrupt:
        code = "INTERRUPTED"
    print(json.dumps({"status": "stopped", "code": code}), flush=True)
    return 2


if __name__ == "__main__":
    sys.exit(main())
