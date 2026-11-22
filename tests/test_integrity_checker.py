import hashlib
import json

from integrity_checker import (
    build_baseline,
    compare_to_baseline,
    hash_file,
    hashes_match,
    infer_algorithm,
    load_baseline,
    lookup_checksum,
    main,
    parse_checksum_file,
    write_baseline,
)

# Well-known digests of the three-byte string "abc".
ABC = b"abc"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def write_file(path, data=ABC):
    path.write_bytes(data)
    return path


def test_hash_file_sha256_known_value(tmp_path):
    target = write_file(tmp_path / "sample.bin")
    assert hash_file(target) == ABC_SHA256
    assert hash_file(target, "sha256") == hashlib.sha256(ABC).hexdigest()


def test_hash_file_sha1_and_md5_known_values(tmp_path):
    target = write_file(tmp_path / "sample.bin")
    assert hash_file(target, "sha1") == ABC_SHA1
    assert hash_file(target, "md5") == ABC_MD5


def test_hash_file_empty(tmp_path):
    target = write_file(tmp_path / "empty.bin", b"")
    assert hash_file(target) == EMPTY_SHA256


def test_hash_file_reads_in_chunks(tmp_path):
    # Force tiny chunks so a short file still takes more than one read.
    data = b"abcdefghijklmnopqrstuvwxyz"
    target = write_file(tmp_path / "chunked.bin", data)
    assert hash_file(target, chunk_size=5) == hashlib.sha256(data).hexdigest()


def test_hashes_match_is_case_insensitive():
    assert hashes_match(ABC_SHA256, ABC_SHA256.upper())
    assert hashes_match("  " + ABC_SHA256.upper() + "\n", ABC_SHA256)


def test_hashes_match_detects_mismatch():
    other = hashlib.sha256(b"abd").hexdigest()
    assert not hashes_match(ABC_SHA256, other)
    assert not hashes_match(ABC_SHA256, ABC_SHA1)


def test_infer_algorithm_from_digest_length():
    assert infer_algorithm(ABC_SHA256) == "sha256"
    assert infer_algorithm(ABC_SHA1) == "sha1"
    assert infer_algorithm(ABC_MD5) == "md5"


def test_verify_match_exits_zero(tmp_path, capsys):
    target = write_file(tmp_path / "sample.bin")
    code = main(["verify", str(target), ABC_SHA256.upper()])
    captured = capsys.readouterr()
    assert code == 0
    assert "MATCH" in captured.out
    assert "MISMATCH" not in captured.out


def test_verify_mismatch_exits_one(tmp_path, capsys):
    target = write_file(tmp_path / "sample.bin")
    wrong = hashlib.sha256(b"nope").hexdigest()
    code = main(["verify", str(target), wrong])
    captured = capsys.readouterr()
    assert code == 1
    assert "MISMATCH" in captured.out
    assert wrong in captured.out


def test_verify_checksum_file_match(tmp_path, capsys):
    target = write_file(tmp_path / "setup.bin")
    checksum = tmp_path / "SHA256SUMS"
    checksum.write_text(f"{ABC_SHA256}  setup.bin\n", encoding="utf-8")
    code = main(["verify", str(target), "--checksum-file", str(checksum)])
    assert code == 0
    assert "MATCH" in capsys.readouterr().out


def test_verify_checksum_file_mismatch(tmp_path, capsys):
    target = write_file(tmp_path / "setup.bin")
    checksum = tmp_path / "SHA256SUMS"
    # Binary-mode marker (*) should still parse.
    checksum.write_text(f"{hashlib.sha256(b'other').hexdigest()} *setup.bin\n", encoding="utf-8")
    code = main(["verify", str(target), "--checksum-file", str(checksum)])
    assert code == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_parse_and_lookup_checksum_file(tmp_path):
    listing = tmp_path / "SHA256SUMS"
    listing.write_text(
        "\n".join(
            [
                "# comment",
                f"{ABC_SHA256}  docs/readme.txt",
                f"{ABC_MD5}  other.bin",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    entries = parse_checksum_file(listing)
    assert lookup_checksum(entries, tmp_path / "docs" / "readme.txt") == ABC_SHA256


def test_hash_command_prints_sha256sum_layout(tmp_path, capsys):
    target = write_file(tmp_path / "sample.bin")
    code = main(["hash", str(target)])
    out = capsys.readouterr().out.strip()
    assert code == 0
    assert out == f"{ABC_SHA256}  {target}"


def test_baseline_records_relative_path_hash_and_size(tmp_path):
    (tmp_path / "sub").mkdir()
    write_file(tmp_path / "root.txt", b"root")
    write_file(tmp_path / "sub" / "nested.txt", b"nested")

    baseline = build_baseline(tmp_path)
    paths = [item["path"] for item in baseline["files"]]
    assert paths == ["root.txt", "sub/nested.txt"]
    assert baseline["algorithm"] == "sha256"
    by_path = {item["path"]: item for item in baseline["files"]}
    assert by_path["root.txt"]["sha256"] == hashlib.sha256(b"root").hexdigest()
    assert by_path["root.txt"]["size"] == 4
    assert by_path["sub/nested.txt"]["sha256"] == hashlib.sha256(b"nested").hexdigest()


def test_check_detects_added_removed_and_modified(tmp_path):
    tracked = tmp_path / "lab"
    tracked.mkdir()
    write_file(tracked / "keep.txt", b"same")
    write_file(tracked / "gone.txt", b"leave")
    write_file(tracked / "change.txt", b"before")

    baseline_path = tmp_path / "baseline.json"
    write_baseline(build_baseline(tracked), baseline_path)
    expected = load_baseline(baseline_path)

    (tracked / "gone.txt").unlink()
    write_file(tracked / "change.txt", b"after")
    write_file(tracked / "new.txt", b"fresh")

    result = compare_to_baseline(tracked, expected)
    assert result.added == ["new.txt"]
    assert result.removed == ["gone.txt"]
    assert [item.path for item in result.modified] == ["change.txt"]
    assert result.has_changes()


def test_check_command_exits_nonzero_when_tree_changes(tmp_path, capsys):
    tracked = tmp_path / "lab"
    tracked.mkdir()
    write_file(tracked / "a.txt", b"one")
    baseline_path = tmp_path / "baseline.json"
    assert main(["baseline", str(tracked), "-o", str(baseline_path)]) == 0
    capsys.readouterr()

    write_file(tracked / "b.txt", b"two")
    code = main(["check", str(tracked), str(baseline_path)])
    out = capsys.readouterr().out
    assert code == 1
    assert "Added" in out
    assert "b.txt" in out


def test_check_command_exits_zero_when_unchanged(tmp_path, capsys):
    tracked = tmp_path / "lab"
    tracked.mkdir()
    write_file(tracked / "a.txt", b"one")
    baseline_path = tmp_path / "baseline.json"
    write_baseline(build_baseline(tracked), baseline_path)

    code = main(["check", str(tracked), str(baseline_path)])
    assert code == 0
    assert "No changes." in capsys.readouterr().out


def test_baseline_round_trip_json(tmp_path):
    write_file(tmp_path / "a.txt", b"one")
    output = tmp_path / "baseline.json"
    write_baseline(build_baseline(tmp_path), output)
    data = json.loads(output.read_text(encoding="utf-8"))
    loaded = load_baseline(output)
    assert data["version"] == 1
    assert "a.txt" in loaded
    assert loaded["a.txt"].size == 3
