# File Integrity Checker

A small command-line tool that hashes files, checks a download against a published checksum, and baselines a folder so you can see if anything changed later.

I built this as a portfolio project while finishing a cybersecurity degree. It is a learning project. For day-to-day work you would usually reach for tools like `sha256sum` or a dedicated file integrity monitor. This is me working through the same ideas in Python.

## What it does

- Prints the hash of a file (SHA-256 by default; SHA-1 and MD5 are there for older checksums)
- Verifies a file against a hex digest or a SHA256SUMS-style checksum file
- Builds a JSON baseline of a directory (relative path, SHA-256, and size for each file)
- Compares a directory to an earlier baseline and reports added, removed, and modified files

Large files are read in chunks, so the whole file does not have to fit in memory.

## Why integrity checking matters

A download can be truncated, corrupted in transit, or swapped for a tampered copy. Publishers often post a SHA-256 checksum next to the file so you can confirm what you got is what they published.

The same idea scales up to a folder. If you record a baseline of hashes, you can later tell whether a file was added, removed, or changed. That is the basic idea behind file integrity monitoring, which shows up in SOC and host-based detection work.

## Setup

```bash
git clone https://github.com/B3ardedW3irdo/file-integrity-checker.git
cd file-integrity-checker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Usage

Hash a file (SHA-256 by default):

```bash
python integrity_checker.py hash setup.bin
```

Use a different algorithm when a site still publishes an older checksum. Prefer SHA-256 when you have a choice; MD5 and SHA-1 are only included for those legacy checksums.

```bash
python integrity_checker.py hash setup.bin --algo md5
```

Verify against a published hash:

```bash
python integrity_checker.py verify setup.bin 3a7bd3e2360a3ba5538a54c4c0e7b1e5c0d2f0a1b2c3d4e5f6a7b8c9d0e1f2a3
```

Or against a checksum file in the usual `sha256sum` format:

```bash
python integrity_checker.py verify setup.bin --checksum-file SHA256SUMS
```

Record a baseline of a directory, then check it later:

```bash
python integrity_checker.py baseline ./lab -o baseline.json
python integrity_checker.py check ./lab baseline.json
```

Keep the baseline file outside the directory you are tracking, or it will show up as a new file on the next check.

The `verify` and `check` commands exit with 0 when everything matches and 1 when something does not. That makes them easy to use in a script.

## How it works

`hash` reads the file in 1 MiB chunks and feeds them to Python's `hashlib`. The output is a hex digest, printed in the same `hash  filename` layout that `sha256sum` uses, so you can redirect it into a checksum file.

`verify` hashes the file the same way, then compares the result to the expected digest with `hmac.compare_digest`. The comparison is case-insensitive. Using `compare_digest` avoids a short-circuiting string compare, which is the safer habit when you are checking a value that should not leak how close a guess was.

If you pass `--checksum-file`, the tool looks up the file in a GNU coreutils-style checksum list (`<hash>  <name>` or `<hash> *<name>`).

`baseline` walks a directory, hashes every regular file with SHA-256, and writes a JSON file of relative paths, hashes, and sizes. `check` builds a fresh inventory and diffs it against that snapshot.

## Tests

```bash
pytest
```

The tests hash known values, check match and mismatch paths, and use temporary directories to confirm that added, removed, and modified files are reported.

## Next steps

A few things worth adding later:

- A simple GUI so you can drop a downloaded file and a checksum onto a window
- Signing or a checksum of the baseline itself, so the snapshot cannot be quietly edited
- Optional watching of a directory for changes, instead of a one-shot check
- Following or recording symlinks more explicitly

## License

MIT
