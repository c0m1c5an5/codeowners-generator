"""Invariants the committer email to user id map holds for every input.

The cases that pin down particular inputs live in `test_users.py`.
"""

import json
from typing import Dict

from hypothesis import given
from hypothesis import strategies as st

from codeowners.core.users import parse_user_map

handles = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10).map(
    lambda name: "".join(("@", name))
)
"""An address and a user id as a map states them: "@k" or "@gekkuiyyfo"."""

user_maps = st.dictionaries(handles, handles, max_size=5)
"""A map as a file states it, such as {"@buqcbdtwv": "@ygunynmik"}."""


@given(user_maps)
def test_a_written_map_is_read_back_whatever_it_states(
    user_map: Dict[str, str],
) -> None:
    """A user map survives the trip through the file it is stored in."""
    assert parse_user_map(json.dumps(user_map)) == user_map
