"""Reading file content: decoding, classification and declared owners."""

from pathlib import Path
from typing import Dict, List, Set

import pytest

from codeowners.core.content import (
    SNIFF_SIZE,
    decode,
    decode_paths,
    decode_tree,
    has_blamable_lines,
    is_lfs_pointer,
    parse_declared_owners,
    sniff_head,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(b"src/main.py", "src/main.py", id="ascii"),
        pytest.param("документ.txt".encode(), "документ.txt", id="utf-8"),
        pytest.param(b"", "", id="empty"),
        pytest.param(b"caf\xe9.txt", "caf�.txt", id="not-valid-utf-8"),
    ],
)
def test_git_output_is_decoded_as_utf8(raw: bytes, expected: str) -> None:
    """Git output is read as UTF-8, with anything invalid replaced."""
    assert decode(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(b"a.txt\x00b.txt", {"a.txt", "b.txt"}, id="two-files"),
        pytest.param(b"a.txt\x00", {"a.txt"}, id="trailing-separator"),
        pytest.param(b"a.txt\x00\x00b.txt", {"a.txt", "b.txt"}, id="empty-between"),
        pytest.param(b"", set(), id="nothing-tracked"),
        pytest.param(
            "sub/документ.txt".encode(),
            {"sub/документ.txt"},
            id="outside-ascii",
        ),
        pytest.param(b"a file.txt", {"a file.txt"}, id="name-with-a-space"),
    ],
)
def test_tracked_files_are_read_from_nul_delimited_output(
    raw: bytes,
    expected: Set[str],
) -> None:
    """`git ls-files -z` output names exactly the files git listed."""
    assert decode_paths(raw) == {Path(name) for name in expected}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(
            b"100644 blob 4d7a21\tsrc/app.py\x00",
            {"src/app.py": "blob"},
            id="a-file",
        ),
        pytest.param(
            b"100644 blob 4d7a21\tsrc/app.py\x00100755 blob 9f2b11\trun.sh\x00",
            {"src/app.py": "blob", "run.sh": "blob"},
            id="several-files",
        ),
        pytest.param(
            b"160000 commit 9daf001\tvendor\x00",
            {"vendor": "commit"},
            id="a-submodule",
        ),
        pytest.param(
            b"100644 blob 4d7a21\ta file.txt\x00160000 commit 9daf001\tvendor\x00",
            {"a file.txt": "blob", "vendor": "commit"},
            id="a-name-with-a-space-beside-a-submodule",
        ),
        pytest.param(
            b"100644 blob 4d7a21\t leading-space.txt\x00",
            {" leading-space.txt": "blob"},
            id="a-name-that-starts-with-a-space",
        ),
        pytest.param(
            "100644 blob 4d7a21\tsub/\u0434\u043e\u043a.txt\x00".encode(),
            {"sub/\u0434\u043e\u043a.txt": "blob"},
            id="a-name-outside-ascii",
        ),
        pytest.param(b"", {}, id="an-empty-revision"),
        pytest.param(b"100644 blob 4d7a21 no-tab\x00", {}, id="a-record-without-a-tab"),
    ],
)
def test_the_kind_of_each_path_is_read_from_the_tree(
    raw: bytes,
    expected: Dict[str, str],
) -> None:
    """`git ls-tree -z` output says what git holds at each path."""
    assert decode_tree(raw) == {Path(path): kind for path, kind in expected.items()}


@pytest.mark.parametrize(
    ("head", "empty", "binary"),
    [
        pytest.param(b"", True, False, id="empty-file"),
        pytest.param(b"one\ntwo\n", False, False, id="text"),
        pytest.param("документ\n".encode(), False, False, id="text-outside-ascii"),
        pytest.param(b"\x00\x01\x02", False, True, id="nul-bytes"),
        pytest.param(b"text\x00more", False, True, id="nul-after-text"),
        pytest.param(b"\x7f", False, True, id="delete-character"),
        pytest.param(b"\t\n\r\f\x1b", False, False, id="the-control-codes-text-uses"),
    ],
)
def test_a_file_is_classified_by_the_bytes_it_starts_with(
    head: bytes,
    empty: bool,
    binary: bool,
) -> None:
    """A file is owned only if it is text with something in it."""
    assert sniff_head(head) == (empty, binary)


def test_classification_reads_no_further_than_it_says() -> None:
    """Bytes past the sniffed range cannot change what a file is taken for."""
    head = b"text".ljust(SNIFF_SIZE, b" ")

    assert sniff_head(head + b"\x00\x00\x00") == (False, False)


@pytest.mark.parametrize(
    "prefix",
    [
        pytest.param("#", id="hash"),
        pytest.param("//", id="slashes"),
        pytest.param("--", id="dashes"),
        pytest.param(";", id="semicolon"),
        pytest.param("%", id="percent"),
        pytest.param("<!--", id="markup"),
    ],
)
def test_a_declaration_is_read_whatever_comments_look_like(prefix: str) -> None:
    """Owners are declared in whichever comment syntax the file is written in."""
    head = f"{prefix} codeowner: @alice @bob\n".encode()

    assert parse_declared_owners(head) == {"@alice", "@bob"}


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        pytest.param(
            b"# codeowner: @alice\n# codeowner: @bob\n",
            {"@alice", "@bob"},
            id="one-owner-per-line",
        ),
        pytest.param(
            b"#!/bin/sh\n# codeowner: @alice\nprint('hello')\n",
            {"@alice"},
            id="below-a-shebang",
        ),
        pytest.param(
            b"/* codeowner: @alice */\n",
            {"@alice"},
            id="terminator-is-not-an-owner",
        ),
        pytest.param(
            b"<!-- codeowner: @alice -->\n",
            {"@alice"},
            id="markup-terminator-is-not-an-owner",
        ),
        pytest.param(b"# codeowner: @alice\r\n", {"@alice"}, id="carriage-returns"),
        pytest.param(b"# codeowner:@alice\n", {"@alice"}, id="no-space-after-marker"),
        pytest.param(b"# codeowner:\n", set(), id="declaring-nobody"),
        pytest.param(b"one\ntwo\n", set(), id="no-marker-at-all"),
        pytest.param(
            b"# the codeowner: of this file\n",
            set(),
            id="prose-is-not-a-declaration",
        ),
        pytest.param(
            b"codeowner: @alice\n",
            set(),
            id="a-declaration-needs-a-comment-prefix",
        ),
    ],
)
def test_declared_owners_are_read_from_the_head(
    head: bytes,
    expected: Set[str],
) -> None:
    """Every `codeowner:` line counts, and its owners are taken as written."""
    assert parse_declared_owners(head) == expected


def test_declared_owners_do_not_go_through_the_user_map() -> None:
    """Declaring owners is how a file overrides what its history says."""
    head = b"# codeowner: alice@example.com\n"

    assert parse_declared_owners(head) == {"alice@example.com"}


@pytest.mark.parametrize(
    ("head", "pointer"),
    [
        pytest.param(
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:4d7a214614ab2935c943f9e0ff69d22ea\n"
            b"size 12345\n",
            True,
            id="a-pointer-git-lfs-wrote",
        ),
        pytest.param(
            b"version https://git-lfs.github.com/spec/v1\n",
            True,
            id="the-version-line-alone",
        ),
        pytest.param(
            b"# version https://git-lfs.github.com/spec/v1\n",
            False,
            id="quoted-in-a-comment",
        ),
        pytest.param(b"version 2\n", False, id="another-version-line"),
        pytest.param(b"", False, id="empty-file"),
        pytest.param(b"\x89PNG\r\n\x1a\n", False, id="the-content-it-stands-for"),
    ],
)
def test_a_pointer_is_told_from_the_content_it_stands_for(
    head: bytes,
    pointer: bool,
) -> None:
    """A pointer is recognised by the version line git lfs writes first."""
    assert is_lfs_pointer(head) == pointer


@pytest.mark.parametrize(
    ("head", "blamable"),
    [
        pytest.param(b"one\ntwo\n", True, id="source-is-read-line-by-line"),
        pytest.param(
            b"# codeowner: @alice\n", True, id="a-declaration-is-in-its-lines"
        ),
        pytest.param("документ\n".encode(), True, id="text-outside-ascii"),
        pytest.param(b"", False, id="an-empty-file-has-no-lines"),
        pytest.param(
            b"\x89PNG\r\n\x1a\n\x00\x00",
            False,
            id="a-binary-file-has-no-lines-to-blame",
        ),
        pytest.param(
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:4d7a214614ab2935c943f9e0ff69d22ea\n"
            b"size 12345\n",
            False,
            id="a-pointer-stands-for-content-that-may-not-be-here",
        ),
    ],
)
def test_whether_a_file_can_say_who_wrote_which_part_of_it(
    head: bytes,
    blamable: bool,
) -> None:
    """Only a file with readable lines is blamed; the rest go by their history."""
    assert has_blamable_lines(head) == blamable


def test_a_declaration_past_the_head_is_not_read() -> None:
    """Only the head is read, so a declaration has to be near the top of the file."""
    head: List[bytes] = [b"x" * 8192, b"\n# codeowner: @alice\n"]

    assert parse_declared_owners(b"".join(head)[:4096]) == set()
