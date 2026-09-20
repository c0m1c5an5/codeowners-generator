"""Invariants reading file content holds for every input.

The cases that pin down particular inputs live in `test_content.py`.
"""

from pathlib import Path
from typing import List

from hypothesis import given
from hypothesis import strategies as st

from codeowners.core.content import (
    decode,
    decode_paths,
    parse_declared_owners,
    sniff_head,
)

file_names = st.text(
    st.characters(codec="utf-8", exclude_characters="\x00"), min_size=1
)
r"""A file name git can hand over, such as "src/main.py" or "\U0003aad5".

Anything but the NUL that delimits them; the codec keeps the name encodable.
"""

handles = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10).map(
    lambda name: "".join(("@", name))
)
"""An owner as a file header states one: "@a", "@oqx" or "@vzuutbgvov"."""

file_heads = st.binary()
r"""The bytes a file starts with, such as b"", b"3\xeb\xca" or b"\xdavL"."""

tracked_files = st.lists(file_names, max_size=5)
"""What one `git ls-files -z` run listed, such as ["a.txt", "sub/b.txt"]."""

declarations = st.lists(handles, min_size=1, max_size=4, unique=True)
"""The owners one file declares, such as ["@a"] or ["@rmnp", "@u", "@wray"]."""


@given(file_heads)
def test_git_output_always_decodes(raw: bytes) -> None:
    """Whatever bytes git holds, decoding them gives a string rather than an error."""
    assert isinstance(decode(raw), str)


@given(file_heads)
def test_only_a_file_with_no_bytes_is_empty(head: bytes) -> None:
    """A file counts as empty exactly when it has no bytes at all."""
    (empty, _) = sniff_head(head)

    assert empty == (head == b"")


@given(tracked_files)
def test_every_listed_file_is_named(names: List[str]) -> None:
    """`git ls-files -z` output names exactly the files git listed."""
    raw = "\x00".join(names).encode()

    assert decode_paths(raw) == {Path(name) for name in names}


@given(declarations)
def test_declared_owners_are_read_back(stated: List[str]) -> None:
    """Owners a file declares for itself are taken exactly as written."""
    head = f"# codeowner: {' '.join(stated)}\n".encode()

    assert parse_declared_owners(head) == set(stated)
