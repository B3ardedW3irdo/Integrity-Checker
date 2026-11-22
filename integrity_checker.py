#!/usr/bin/env python3
"""Hash files, verify checksums, and baseline a directory for later comparison."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SUPPORTED_ALGOS = ("sha256", "sha1", "md5")
DEFAULT_ALGO = "sha256"
# 1 MiB chunks keep memory use flat when hashing a large ISO or disk image.
CHUNK_SIZE = 1024 * 1024
BASELINE_VERSION = 1

# GNU coreutils: "<hash>  <name>" (text) or "<hash> *<name>" (binary).
GNU_CHECKSUM_LINE = re.compile(r"^([0-9a-fA-F]+) [ *](.+)$")
DIGEST_LENGTHS = {64: "sha256", 40: "sha1", 32: "md5"}


@dataclass
class FileRecord:
    path: str
    sha256: str
    size: int


@dataclass
class ModifiedFile:
    path: str
    old: FileRecord
    new: FileRecord


@dataclass
class CheckResult:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[ModifiedFile] = field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)


def normalize_digest(value: str) -> str:
    return value.strip().lower()


def supported_algorithm(name: str) -> str:
    algo = name.lower()
    if algo not in SUPPORTED_ALGOS:
        raise ValueError(
            f"Unsupported algorithm {name!r}. Use one of: {', '.join(SUPPORTED_ALGOS)}."
        )
    return algo


def infer_algorithm(digest: str) -> str:
    """Pick sha256, sha1, or md5 from the hex length of a digest."""
    cleaned = normalize_digest(digest)
    algo = DIGEST_LENGTHS.get(len(cleaned))
    if algo is None:
        raise ValueError(
            f"Cannot tell which algorithm that hash uses (length {len(cleaned)})."
        )
    return algo


def hash_file(
    path: Path,
    algorithm: str = DEFAULT_ALGO,
    chunk_size: int = CHUNK_SIZE,
) -> str:
    """Return the hex digest of a file, reading it in chunks."""
    algo = supported_algorithm(algorithm)
    digest = hashlib.new(algo)
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def hashes_match(actual: str, expected: str) -> bool:
    """Case-insensitive compare that uses hmac.compare_digest."""
    left = normalize_digest(actual)
    right = normalize_digest(expected)
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def parse_checksum_file(path: Path) -> list[tuple[str, str]]:
    """Read a SHA256SUMS-style file and return (filename, digest) pairs."""
    entries: list[tuple[str, str]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = GNU_CHECKSUM_LINE.match(line)
        if not match:
            raise ValueError(f"{path}: line {line_no} is not a recognized checksum line.")
        digest, name = match.group(1), match.group(2)
        entries.append((name, normalize_digest(digest)))
    return entries


def lookup_checksum(entries: list[tuple[str, str]], file_path: Path) -> str:
    """Find the expected hash for a file in a parsed checksum list."""
    candidates = [
        str(file_path),
        file_path.as_posix(),
        file_path.name,
    ]
    # If the checksum file was written from another directory, the stored
    # name is often just the basename or a relative path.
    for candidate in candidates:
        matches = [digest for name, digest in entries if name == candidate]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"Checksum file lists {candidate} more than once.")

    basename_hits = [digest for name, digest in entries if Path(name).name == file_path.name]
    if len(basename_hits) == 1:
        return basename_hits[0]
    if len(basename_hits) > 1:
        raise ValueError(
            f"Checksum file has more than one entry named {file_path.name}. "
            "Pass the path the way it appears in the checksum file."
        )
    raise ValueError(f"No checksum entry found for {file_path}.")


def iter_regular_files(root: Path) -> list[Path]:
    """All regular files under root, in a stable order. Symlinks are skipped."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            files.append(path)
    return files


def relative_posix(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def build_baseline(root: Path) -> dict:
    """Snapshot every regular file under root: relative path, sha256, size."""
    records = []
    for path in iter_regular_files(root):
        rel = relative_posix(path, root)
        records.append(
            {
                "path": rel,
                "sha256": hash_file(path, DEFAULT_ALGO),
                "size": path.stat().st_size,
            }
        )
    records.sort(key=lambda item: item["path"])
    return {
        "version": BASELINE_VERSION,
        "algorithm": DEFAULT_ALGO,
        "files": records,
    }


def write_baseline(baseline: dict, output: Path) -> None:
    output.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict[str, FileRecord]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "files" not in data:
        raise ValueError(f"{path} does not look like a baseline file.")
    records: dict[str, FileRecord] = {}
    for item in data["files"]:
        record = FileRecord(
            path=item["path"],
            sha256=normalize_digest(item["sha256"]),
            size=int(item["size"]),
        )
        records[record.path] = record
    return records


def compare_to_baseline(root: Path, expected: dict[str, FileRecord]) -> CheckResult:
    current = build_baseline(root)
    actual = {
        item["path"]: FileRecord(item["path"], item["sha256"], item["size"])
        for item in current["files"]
    }

    added = sorted(set(actual) - set(expected))
    removed = sorted(set(expected) - set(actual))
    modified = []
    for name in sorted(set(actual) & set(expected)):
        if actual[name].sha256 != expected[name].sha256 or actual[name].size != expected[name].size:
            modified.append(ModifiedFile(path=name, old=expected[name], new=actual[name]))
    return CheckResult(added=added, removed=removed, modified=modified)


def format_verify(path: Path, matched: bool, actual: str, expected: str) -> str:
    status = "MATCH" if matched else "MISMATCH"
    lines = [f"{status}  {path}"]
    if not matched:
        lines.append(f"  expected: {normalize_digest(expected)}")
        lines.append(f"  actual:   {normalize_digest(actual)}")
    return "\n".join(lines)


def format_check(result: CheckResult) -> str:
    if not result.has_changes():
        return "No changes."

    lines: list[str] = []
    if result.added:
        lines.append(f"Added ({len(result.added)}):")
        lines.extend(f"  {name}" for name in result.added)
    if result.removed:
        lines.append(f"Removed ({len(result.removed)}):")
        lines.extend(f"  {name}" for name in result.removed)
    if result.modified:
        lines.append(f"Modified ({len(result.modified)}):")
        for item in result.modified:
            lines.append(f"  {item.path}")
            if item.old.size != item.new.size:
                lines.append(f"    size: {item.old.size} -> {item.new.size}")
            lines.append(f"    sha256: {item.old.sha256} -> {item.new.sha256}")
    return "\n".join(lines)


def resolve_expected_hash(args: argparse.Namespace) -> str:
    if args.expected_hash and args.checksum_file:
        raise ValueError("Pass either an expected hash or --checksum-file, not both.")
    if args.expected_hash:
        return normalize_digest(args.expected_hash)
    if args.checksum_file:
        entries = parse_checksum_file(Path(args.checksum_file))
        return lookup_checksum(entries, Path(args.file))
    raise ValueError("Provide an expected hash or --checksum-file.")


def choose_algorithm(algo_flag: str | None, digest: str) -> str:
    inferred = infer_algorithm(digest)
    if algo_flag is None:
        return inferred
    chosen = supported_algorithm(algo_flag)
    if chosen != inferred:
        raise ValueError(
            f"The provided hash looks like {inferred} ({len(normalize_digest(digest))} hex chars), "
            f"but --algo was set to {chosen}."
        )
    return chosen


def cmd_hash(args: argparse.Namespace) -> int:
    path = Path(args.file)
    digest = hash_file(path, args.algo)
    # Same layout as sha256sum, so the output can be saved as a checksum file.
    print(f"{digest}  {path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    expected = resolve_expected_hash(args)
    algorithm = choose_algorithm(args.algo, expected)
    actual = hash_file(path, algorithm)
    matched = hashes_match(actual, expected)
    print(format_verify(path, matched, actual, expected))
    return 0 if matched else 1


def cmd_baseline(args: argparse.Namespace) -> int:
    root = Path(args.directory)
    if not root.is_dir():
        raise ValueError(f"{root} is not a directory.")
    output = Path(args.output)
    write_baseline(build_baseline(root), output)
    print(f"Wrote baseline to {output}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    root = Path(args.directory)
    if not root.is_dir():
        raise ValueError(f"{root} is not a directory.")
    result = compare_to_baseline(root, load_baseline(Path(args.baseline)))
    print(format_check(result))
    return 1 if result.has_changes() else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Hash a file, verify it against a published checksum, or baseline "
            "a directory and report files that were added, removed, or changed."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hash_cmd = sub.add_parser("hash", help="Print the hash of a file.")
    hash_cmd.add_argument("file", help="File to hash.")
    hash_cmd.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default=DEFAULT_ALGO,
        help=(
            "Hash algorithm (default: sha256). md5 and sha1 are for legacy "
            "checksums only; prefer sha256 when you have a choice."
        ),
    )
    hash_cmd.set_defaults(func=cmd_hash)

    verify_cmd = sub.add_parser(
        "verify",
        help="Compare a file to an expected hash or a SHA256SUMS-style file.",
    )
    verify_cmd.add_argument("file", help="File to check.")
    verify_cmd.add_argument(
        "expected_hash",
        nargs="?",
        help="Expected hex digest. Skip this if you pass --checksum-file.",
    )
    verify_cmd.add_argument(
        "--checksum-file",
        help="GNU coreutils-style checksum file (for example SHA256SUMS).",
    )
    verify_cmd.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default=None,
        help="Hash algorithm. If omitted, it is inferred from the digest length.",
    )
    verify_cmd.set_defaults(func=cmd_verify)

    baseline_cmd = sub.add_parser(
        "baseline",
        help="Record path, SHA-256, and size for every file in a directory.",
    )
    baseline_cmd.add_argument("directory", help="Directory to snapshot.")
    baseline_cmd.add_argument(
        "-o",
        "--output",
        required=True,
        help="Where to write the JSON baseline.",
    )
    baseline_cmd.set_defaults(func=cmd_baseline)

    check_cmd = sub.add_parser(
        "check",
        help="Compare a directory to a baseline and report changes.",
    )
    check_cmd.add_argument("directory", help="Directory to scan.")
    check_cmd.add_argument("baseline", help="JSON baseline from the baseline command.")
    check_cmd.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        missing = exc.filename or exc
        print(f"Not found: {missing}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Error reading a file: {exc}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
