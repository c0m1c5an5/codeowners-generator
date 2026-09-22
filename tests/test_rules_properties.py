"""Invariants the codeowners file format holds for every input.

The cases that pin down particular inputs live in `test_rules.py`.
"""

from pathlib import Path
from typing import Dict, List, Set

from hypothesis import given
from hypothesis import strategies as st

from codeowners.core.rules import (
    BEGIN_BOUNDARY,
    END_BOUNDARY,
    RULE_FIELD_RE,
    escape_owner,
    escape_path,
    format_codeowners,
    frame_codeowners,
    parse_codeowners,
    render_codeowners,
    split_boundaries,
)

one_line = st.text(min_size=1).filter(lambda value: value.splitlines() == [value])
r"""Anything on one line, such as "0", "src/main.py", "a b.txt" or "\x8a".

A file can be named almost anything, but a line based format cannot carry a
name that ends the line it is written on.
"""

mappings = st.dictionaries(
    one_line.map(Path),
    st.sets(one_line, min_size=1, max_size=3),
    max_size=3,
)
"""A few files, each owned by a few owners: {PosixPath("a b"): {"@alice"}}."""

hand_written = st.lists(st.text(alphabet="ab /@*#.", max_size=12), max_size=3)
"""Lines a hand wrote around the boundaries, such as ["# a note", "*.md @ab"].

No dash, so that none of them can be read back as a boundary of its own.
"""


@given(one_line)
def test_an_escaped_path_is_read_back_as_one_field(text: str) -> None:
    """However a file is named, its path is one field of the rule."""
    escaped = escape_path(text)

    assert RULE_FIELD_RE.findall(escaped) == [escaped]


@given(one_line)
def test_an_escaped_owner_is_read_back_as_one_field(text: str) -> None:
    """However a user map names an owner, the owner is one field of the rule."""
    escaped = escape_owner(text)

    assert RULE_FIELD_RE.findall(escaped) == [escaped]


@given(mappings)
def test_a_written_file_states_what_it_was_written_from(
    mapping: Dict[Path, Set[str]],
) -> None:
    """Reading a file back gives exactly the rules it was written from."""
    written = format_codeowners(mapping)

    assert parse_codeowners(written.splitlines()) == render_codeowners(mapping)


@given(hand_written, mappings, hand_written)
def test_only_the_lines_between_the_boundaries_are_written(
    above: List[str],
    mapping: Dict[Path, Set[str]],
    below: List[str],
) -> None:
    """Whatever a hand wrote outside the boundaries is still there afterwards."""
    # Written the way a file is: ending in the newline that closes its last line.
    stated = "\n".join(
        (*above, BEGIN_BOUNDARY, "gone.txt @nobody", END_BOUNDARY, *below, "")
    )
    rules = format_codeowners(mapping)

    written = frame_codeowners(stated, rules)

    assert split_boundaries(written) == (above, rules.splitlines(), below)


@given(hand_written, mappings)
def test_a_file_this_tool_wrote_is_written_the_same_way_again(
    above: List[str],
    mapping: Dict[Path, Set[str]],
) -> None:
    """A run over a file stating these rules already leaves it exactly as it is."""
    rules = format_codeowners(mapping)
    written = frame_codeowners("\n".join(above), rules)

    assert frame_codeowners(written, rules) == written
