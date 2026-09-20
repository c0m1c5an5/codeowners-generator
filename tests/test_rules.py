"""The codeowners file format: what is written, and what is read back."""

from pathlib import Path
from typing import Dict, Set

import pytest

from codeowners.core.rules import (
    equivalent_codeowners,
    escape_owner,
    escape_path,
    format_codeowners,
    parse_codeowners,
    render_codeowners,
)

# Named, so that the characters the format reserves stay visible in the tables.
NBSP = "\N{NO-BREAK SPACE}"
IDEOGRAPHIC_SPACE = "\N{IDEOGRAPHIC SPACE}"


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        pytest.param("src/main.py", "src/main.py", id="ordinary"),
        pytest.param("a b.txt", "a\\ b.txt", id="space"),
        pytest.param("a\tb.txt", "a\\\tb.txt", id="tab"),
        pytest.param(f"a{NBSP}b.txt", f"a\\{NBSP}b.txt", id="non-breaking-space"),
        pytest.param(
            f"a{IDEOGRAPHIC_SPACE}b.txt",
            f"a\\{IDEOGRAPHIC_SPACE}b.txt",
            id="ideographic-space",
        ),
        pytest.param("star*.txt", "star\\*.txt", id="star"),
        pytest.param("bang!.txt", "bang\\!.txt", id="bang"),
        pytest.param("[section].txt", "\\[section\\].txt", id="brackets"),
        pytest.param("back\\slash.txt", "back\\\\slash.txt", id="backslash"),
        pytest.param("trailing\\", "trailing\\\\", id="trailing-backslash"),
        pytest.param("#notes.txt", "\\#notes.txt", id="leading-hash"),
        pytest.param("C#/Program.cs", "C#/Program.cs", id="hash-inside"),
    ],
)
def test_a_path_is_escaped_against_what_the_format_reserves(
    file: str,
    expected: str,
) -> None:
    """A path is escaped so that a rule names the one file it was written for."""
    assert escape_path(file) == expected


@pytest.mark.parametrize(
    ("owner", "expected"),
    [
        pytest.param("@alice", "@alice", id="handle"),
        pytest.param("alice@example.com", "alice@example.com", id="email"),
        pytest.param("@big team", "@big\\ team", id="space"),
        pytest.param("alice\\", "alice\\\\", id="trailing-backslash"),
        pytest.param(f"big{NBSP}team", f"big\\{NBSP}team", id="non-breaking-space"),
        pytest.param("@team*", "@team*", id="star-is-not-a-glob-here"),
    ],
)
def test_an_owner_is_escaped_against_the_separator(owner: str, expected: str) -> None:
    """An owner is never matched as a glob, so only the separator is escaped."""
    assert escape_owner(owner) == expected


ROUND_TRIP_CASES = [
    pytest.param({Path("src/main.py"): {"@alice"}}, id="one-rule"),
    pytest.param(
        {Path("src/main.py"): {"@alice", "@bob"}, Path("docs/index.md"): {"@carol"}},
        id="several-rules",
    ),
    pytest.param({Path("a b.txt"): {"@alice"}}, id="path-with-space"),
    pytest.param({Path("a\tb.txt"): {"@alice"}}, id="path-with-tab"),
    pytest.param({Path(f"a{NBSP}b.txt"): {"@alice"}}, id="path-with-nbsp"),
    pytest.param(
        {Path(f"a{IDEOGRAPHIC_SPACE}b.txt"): {"@alice"}},
        id="path-with-ideographic-space",
    ),
    pytest.param({Path("trailing\\"): {"@alice", "@bob"}}, id="path-ending-in-escape"),
    pytest.param({Path("#notes.txt"): {"@alice"}}, id="path-reading-as-a-comment"),
    pytest.param({Path("[section].txt"): {"@alice"}}, id="path-reading-as-a-section"),
    pytest.param({Path("C#/Program.cs"): {"@alice"}}, id="path-with-inner-hash"),
    pytest.param({Path("glob*[a].txt"): {"@alice"}}, id="path-with-glob-characters"),
    pytest.param({Path("file.txt"): {"@big team", "@bob"}}, id="owner-with-space"),
    pytest.param({Path("file.txt"): {"alice\\", "bob"}}, id="owner-ending-in-escape"),
    pytest.param({Path("file.txt"): {f"big{NBSP}team"}}, id="owner-with-nbsp"),
]


@pytest.mark.parametrize("mapping", ROUND_TRIP_CASES)
def test_written_rules_are_read_back_unchanged(mapping: Dict[Path, Set[str]]) -> None:
    """Reading back a written file states exactly what was written."""
    written = format_codeowners(mapping)

    assert parse_codeowners(written.splitlines()) == render_codeowners(mapping)


@pytest.mark.parametrize("mapping", ROUND_TRIP_CASES)
def test_a_written_file_needs_no_rewrite(mapping: Dict[Path, Set[str]]) -> None:
    """What `--preserve` relies on: a file just written already states these owners."""
    stated_rules = parse_codeowners(format_codeowners(mapping).splitlines())

    assert equivalent_codeowners(stated_rules, mapping)


def test_a_file_stating_other_owners_is_not_equivalent() -> None:
    """A file that has fallen behind is not mistaken for one that has not."""
    stated_rules = {"file.txt": {"@alice"}}

    assert not equivalent_codeowners(stated_rules, {Path("file.txt"): {"@bob"}})
    assert not equivalent_codeowners(stated_rules, {})


def test_a_written_file_states_one_sorted_rule_per_path() -> None:
    """Paths and owners come out sorted and spaced, so diffs stay small."""
    written = format_codeowners(
        {
            Path("src/main.py"): {"@bob", "@alice"},
            Path("docs/index.md"): {"@carol"},
        }
    )

    assert written == "docs/index.md @carol\n\nsrc/main.py @alice @bob\n"


def test_insertion_order_does_not_reach_the_file() -> None:
    """The same owners always write the same file, whatever order they arrived in."""
    mapping = {Path("a.txt"): {"@alice"}, Path("b.txt"): {"@bob"}}
    reversed_mapping = dict(reversed(list(mapping.items())))

    assert format_codeowners(mapping) == format_codeowners(reversed_mapping)


def test_owning_nothing_writes_an_empty_file() -> None:
    """An empty mapping writes an empty file rather than a stray newline."""
    assert format_codeowners({}) == ""


def test_rendering_escapes_paths_and_owners() -> None:
    """Rendering states every field the way the file has to carry it."""
    rendered = render_codeowners({Path("a b.txt"): {"@big team"}})

    assert rendered == {"a\\ b.txt": {"@big\\ team"}}


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("# a comment", id="comment"),
        pytest.param("   # an indented comment", id="indented-comment"),
        pytest.param("# file.txt @alice", id="commented-out-rule"),
        pytest.param("[section] @alice", id="section"),
        pytest.param("file.txt", id="path-without-an-owner"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
        pytest.param("\\", id="lone-escape"),
    ],
)
def test_a_line_that_states_no_rule_is_skipped(line: str) -> None:
    """Only a path followed by at least one owner states a rule."""
    assert parse_codeowners([line]) == {}


def test_rules_are_read_from_the_lines_that_state_them() -> None:
    """A hand written file is read the way its author wrote it."""
    stream = "\n".join(
        (
            "# Frontend",
            "src/app.js @alice @bob",
            "",
            "docs/ @carol",
        )
    )

    assert parse_codeowners(stream.splitlines()) == {
        "src/app.js": {"@alice", "@bob"},
        "docs/": {"@carol"},
    }
