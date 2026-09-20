"""Blame parsing and owner selection."""

from typing import Dict, List, Set

import pytest

from codeowners.core.blame import (
    attribute_to_owners,
    is_blame_oid,
    parse_blame,
    parse_blame_author_mail,
    parse_blame_line_count,
    take_owners,
)
from codeowners.exceptions import GitAnnotateError, GitAuthorMissingError


@pytest.mark.parametrize(
    "field",
    [
        pytest.param("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", id="sha1"),
        pytest.param("c" * 64, id="sha256"),
        pytest.param("0123456789abcdef" * 4, id="mixed-digits"),
    ],
)
def test_an_object_id_marks_an_entry_header(field: str) -> None:
    """An object id of either length is what marks the start of an entry."""
    assert is_blame_oid(field)


@pytest.mark.parametrize(
    "field",
    [
        pytest.param("author-mail", id="a-field-name"),
        pytest.param("a" * 39, id="one-short"),
        pytest.param("a" * 41, id="one-long"),
        pytest.param("g" * 40, id="not-hexadecimal"),
        pytest.param("A" * 40, id="uppercase"),
        pytest.param("", id="empty"),
    ],
)
def test_other_fields_are_not_object_ids(field: str) -> None:
    """Nothing of the wrong length or alphabet is mistaken for a header."""
    assert not is_blame_oid(field)


@pytest.mark.parametrize(
    ("lines", "expected", "total"),
    [
        pytest.param(
            [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 3",
                "author A Committer",
                "author-mail <alice@example.com>",
                "author-time 1700000000",
                "author-tz +0000",
                "summary a commit",
                "filename some/file.txt",
            ],
            {"alice@example.com": 3},
            3,
            id="one-commit",
        ),
        pytest.param(
            [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 3",
                "author Alice",
                "author-mail <alice@example.com>",
                "summary a commit",
                "filename some/file.txt",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 4 4 7",
                "author Bob",
                "author-mail <bob@example.com>",
                "summary another commit",
                "filename some/file.txt",
            ],
            {"alice@example.com": 3, "bob@example.com": 7},
            10,
            id="two-commits",
        ),
        pytest.param(
            [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 3",
                "author Alice",
                "author-mail <alice@example.com>",
                "summary a commit",
                "filename some/file.txt",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 4 4 7",
                "author Bob",
                "author-mail <bob@example.com>",
                "summary another commit",
                "filename some/file.txt",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 11 11 5",
                "filename some/file.txt",
            ],
            {"alice@example.com": 8, "bob@example.com": 7},
            15,
            id="a-commit-blamed-twice",
        ),
        pytest.param(
            [
                "c" * 64 + " 1 1 4",
                "author Alice",
                "author-mail <alice@example.com>",
                "filename some/file.txt",
            ],
            {"alice@example.com": 4},
            4,
            id="sha256-repository",
        ),
        pytest.param(
            [
                "boundary",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 3",
                "author-mail <alice@example.com>",
                "committer-mail <someone@example.com>",
                "summary a commit mentioning author-mail",
                "previous 0123456789abcdef0123456789abcdef01234567 some/file.txt",
                "filename some/file.txt",
            ],
            {"alice@example.com": 3},
            3,
            id="fields-that-are-not-read",
        ),
    ],
)
def test_every_blamed_line_reaches_its_author(
    lines: List[str],
    expected: Dict[str, int],
    total: int,
) -> None:
    """Blamed lines are counted per committer, and the totals agree."""
    stream = "\n".join(lines) + "\n"

    (attributed, counted) = parse_blame(stream.splitlines(keepends=True), {})

    assert attributed == expected
    assert counted == total
    assert sum(attributed.values()) == counted


def test_a_mapped_committer_is_credited_under_their_user_id() -> None:
    """The user map is what turns a committer email into the owner written out."""
    stream = "\n".join(
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 3",
            "author-mail <alice@example.com>",
            "filename some/file.txt",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 4 4 7",
            "author-mail <bob@example.com>",
            "filename some/file.txt",
        )
    )

    (attributed, _) = parse_blame(stream.splitlines(), {"alice@example.com": "@alice"})

    assert attributed == {"@alice": 3, "bob@example.com": 7}


@pytest.mark.parametrize("length", (40, 64), ids=("sha1", "sha256"))
@pytest.mark.parametrize(
    "tail",
    [
        pytest.param("", id="no-line-numbers"),
        pytest.param(" 1 1", id="too-few-fields"),
        pytest.param(" 1 1 3 4", id="too-many-fields"),
        pytest.param(" 1 1 many", id="count-is-not-a-number"),
        pytest.param(" first 1 3", id="line-is-not-a-number"),
    ],
)
def test_an_unreadable_header_is_rejected(tail: str, length: int) -> None:
    """A header that is not shaped as expected means the stream cannot be trusted."""
    header = "a" * length + tail

    with pytest.raises(GitAnnotateError):
        parse_blame([header], {})


@pytest.mark.parametrize("length", (40, 64), ids=("sha1", "sha256"))
def test_the_line_count_is_read_from_the_header(length: int) -> None:
    """The third number of a header is how many lines the entry covers."""
    assert parse_blame_line_count("a" * length + " 12 34 56") == 56


@pytest.mark.parametrize("length", (40, 64), ids=("sha1", "sha256"))
def test_a_blamed_commit_without_an_author_is_rejected(length: int) -> None:
    """Lines cannot be credited to a commit git never described."""
    stream = "\n".join(("a" * length + " 1 1 3", "filename some/file.txt"))

    with pytest.raises(GitAuthorMissingError):
        parse_blame(stream.splitlines(), {})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param("<alice@example.com>", "alice@example.com", id="as-git-writes-it"),
        pytest.param(
            " <alice@example.com> ", "alice@example.com", id="surrounded-by-spaces"
        ),
        pytest.param("<>", "", id="no-address-at-all"),
    ],
)
def test_an_address_is_read_out_of_its_brackets(value: str, expected: str) -> None:
    """Angle brackets are how git writes an address, not part of the address."""
    assert parse_blame_author_mail(value) == expected


def test_attribution_totals_the_commits_an_owner_wrote() -> None:
    """An owner is credited with every line of every commit they authored."""
    lines_by_sha = {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": 3,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": 7,
        "dddddddddddddddddddddddddddddddddddddddd": 5,
    }
    owner_by_sha = {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "@alice",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": "@bob",
        "dddddddddddddddddddddddddddddddddddddddd": "@alice",
    }

    assert attribute_to_owners(lines_by_sha, owner_by_sha) == {"@alice": 8, "@bob": 7}


@pytest.mark.parametrize(
    "owner_by_sha",
    [
        pytest.param({}, id="never-described"),
        pytest.param(
            {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": ""},
            id="described-without-an-address",
        ),
    ],
)
def test_attribution_rejects_a_commit_without_an_owner(
    owner_by_sha: Dict[str, str],
) -> None:
    """A blamed commit whose author is unknown is an error, not an empty owner."""
    with pytest.raises(GitAuthorMissingError):
        attribute_to_owners(
            {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": 3}, owner_by_sha
        )


@pytest.mark.parametrize(
    ("relevance", "expected"),
    [
        pytest.param(0.0, {"@alice", "@bob", "@carol"}, id="everyone"),
        pytest.param(10.0, {"@alice", "@bob", "@carol"}, id="a-tenth"),
        pytest.param(50.0, {"@alice", "@bob"}, id="half-of-the-largest"),
        pytest.param(65.0, {"@alice"}, id="the-default"),
        pytest.param(100.0, {"@alice"}, id="the-largest-only"),
    ],
)
def test_owners_are_taken_by_their_share_of_the_largest(
    relevance: float,
    expected: Set[str],
) -> None:
    """Contributors are measured against the largest one, not against the file."""
    contributions = {"@alice": 100, "@bob": 60, "@carol": 10}

    assert take_owners(contributions, relevance) == expected


def test_a_tie_leaves_both_contributors_owning_the_file() -> None:
    """Two contributors of equal size are equally the author of the file."""
    assert take_owners({"@alice": 5, "@bob": 5}, 100.0) == {"@alice", "@bob"}


def test_a_lone_contributor_owns_the_file() -> None:
    """The only contributor qualifies, however small their share."""
    assert take_owners({"@alice": 1}, 100.0) == {"@alice"}


@pytest.mark.parametrize("length", (40, 64), ids=("sha1", "sha256"))
def test_lines_parse_the_same_with_or_without_their_newline(length: int) -> None:
    """The pipe hands over lines ending in a newline; bare ones parse alike."""
    lines = [
        "a" * length + " 1 1 3",
        "author-mail <alice@example.com>",
    ]

    assert parse_blame(lines, {}) == parse_blame([f"{line}\n" for line in lines], {})


def test_nothing_blamed_owns_nothing() -> None:
    """A file nothing was blamed on has no owners rather than an empty rule."""
    assert take_owners({}, 65.0) == set()
