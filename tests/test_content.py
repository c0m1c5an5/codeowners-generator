"""Reading file content: decoding, classification and declared owners."""

from pathlib import Path
from typing import List, Optional, Set

import pytest

from codeowners.core.content import (
    SNIFF_SIZE,
    decode,
    decode_paths,
    owners_from_head,
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
    ("head", "expected"),
    [
        pytest.param(b"", set(), id="empty-file-is-settled"),
        pytest.param(b"\x00\x01\x02", set(), id="binary-file-is-settled"),
        pytest.param(b"# codeowner: @alice\n", {"@alice"}, id="declaration-is-taken"),
        pytest.param(b"one\ntwo\n", None, id="silence-is-left-to-the-history"),
        pytest.param(
            b"\x00# codeowner: @alice\n",
            set(),
            id="a-binary-file-declares-nothing",
        ),
    ],
)
def test_what_a_file_says_about_its_own_owners(
    head: bytes,
    expected: Optional[Set[str]],
) -> None:
    """Content settles ownership outright, or defers to blame by saying nothing."""
    assert owners_from_head(head) == expected


def test_a_declaration_past_the_head_is_not_read() -> None:
    """Only the head is read, so a declaration has to be near the top of the file."""
    head: List[bytes] = [b"x" * 8192, b"\n# codeowner: @alice\n"]

    assert parse_declared_owners(b"".join(head)[:4096]) == set()
