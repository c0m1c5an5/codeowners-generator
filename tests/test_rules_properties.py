"""Invariants the codeowners file format holds for every input.

The cases that pin down particular inputs live in `test_rules.py`.
"""

from pathlib import Path
from typing import Dict, Set

from hypothesis import given
from hypothesis import strategies as st

from codeowners.core.rules import (
    RULE_FIELD_RE,
    escape_owner,
    escape_path,
    format_codeowners,
    parse_codeowners,
    render_codeowners,
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
