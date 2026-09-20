"""Invariants blame parsing and owner selection hold for every input.

The cases that pin down particular inputs live in `test_blame.py`.
"""

from typing import Dict, List

from hypothesis import given
from hypothesis import strategies as st

from codeowners.core.blame import parse_blame, take_owners

line_counts = st.lists(
    st.integers(min_value=1, max_value=1000),
    min_size=1,
    max_size=5,
)
"""How many lines each entry of a blame covers, such as [1] or [217, 260]."""

contributions = st.dictionaries(
    st.text(min_size=1),
    st.integers(min_value=1, max_value=1000),
    min_size=1,
    max_size=5,
)
"""Lines blamed on each owner of a file, such as {"@alice": 127, "@bob": 473}."""

relevances = st.floats(min_value=0, max_value=100)
"""The share of the largest contribution an owner must reach: 0.0, 27.9, 100.0."""

sha_lengths = st.sampled_from((40, 64))
"""How long an object id is: 40 in a sha1 repository, 64 in a sha256 one."""


@given(line_counts, sha_lengths)
def test_no_blamed_line_is_lost(counts: List[int], sha_length: int) -> None:
    """However many entries git writes, every line it blames is counted once."""
    sha = "a" * sha_length
    stream: List[str] = []

    for count in counts:
        stream += [f"{sha} 1 1 {count}", "author-mail <alice@example.com>"]

    assert parse_blame(stream, {}) == ({"alice@example.com": sum(counts)}, sum(counts))


@given(contributions, relevances)
def test_a_blamed_file_always_has_an_owner(
    lines_by_owner: Dict[str, int],
    relevance: float,
) -> None:
    """The largest contributor always qualifies, so a blamed file states a rule."""
    assert take_owners(lines_by_owner, relevance)


@given(contributions, relevances, relevances)
def test_raising_relevance_only_takes_owners_away(
    lines_by_owner: Dict[str, int],
    one: float,
    other: float,
) -> None:
    """Asking for a larger share can only narrow the owners, never widen them."""
    (lower, higher) = sorted((one, other))

    assert take_owners(lines_by_owner, higher) <= take_owners(lines_by_owner, lower)
