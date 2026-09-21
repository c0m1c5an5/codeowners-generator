"""Reading file content: decoding, classification and declared owners."""

import re
from pathlib import Path
from typing import Dict, Set, Tuple

TEXTCHARS = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
SNIFF_SIZE = 2048
HEAD_SIZE = 4096
TREE_ENTRY_FIELDS = 3
LFS_POINTER_MARKER = b"version https://git-lfs.github.com/spec/v1"
DECLARED_OWNER_MARKER = b"codeowner:"
# Codeowner comment format allows for different single line comment prefixes:
#     # codeowner: @alice        // codeowner: @bob        -- codeowner: @team
DECLARED_OWNER_RE = re.compile(
    rb"^[ \t]*[^\w\s]{1,4}[ \t]*codeowner:[ \t]*(?P<owners>[^\r\n]*)\r?$",
    re.MULTILINE,
)


def decode(raw: bytes) -> str:
    """Decode git output, replacing anything that is not valid UTF-8.

    Args:
        raw (bytes): Raw bytes from git.

    Returns:
        str: Decoded string.
    """
    return raw.decode(encoding="utf-8", errors="replace")


def decode_paths(raw: bytes) -> Set[Path]:
    """Split NUL-delimited git output into paths.

    Args:
        raw (bytes): NUL-delimited output.

    Returns:
        Set[Path]: Paths it named.
    """
    return {Path(decode(item)) for item in raw.split(b"\x00") if item}


def decode_tree(raw: bytes) -> Dict[Path, str]:
    r"""Split `git ls-tree` output into the kind of each path.

    Args:
        raw (bytes): NUL-delimited output, one entry to a record.

    Returns:
        Dict[Path, str]: Kind of entry the tree holds at each path.
    """
    tree: Dict[Path, str] = {}

    for record in raw.split(b"\x00"):
        (entry, tab, path) = decode(record).partition("\t")
        fields = entry.split(" ")

        if tab and len(fields) == TREE_ENTRY_FIELDS:
            tree[Path(path)] = fields[1]

    return tree


def sniff_head(head: bytes) -> Tuple[bool, bool]:
    """Check whether a file is empty and whether it is binary.

    Args:
        head (bytes): Leading bytes of the file.

    Returns:
        Tuple[bool, bool]: Is the file empty, is the file binary.
    """
    sample = head[:SNIFF_SIZE]

    return (not sample, bool(sample.translate(None, TEXTCHARS)))


def is_lfs_pointer(head: bytes) -> bool:
    """Check whether a file is a Git LFS pointer, not the content it stands for.

    Args:
        head (bytes): Leading bytes of the file.

    Returns:
        bool: Whether the file is a pointer.
    """
    return head.startswith(LFS_POINTER_MARKER)


def parse_declared_owners(head: bytes) -> Set[str]:
    """Read the owners a file declares for itself.

    Every `codeowner:` line in the head counts, so owners may be listed one per
    line or several to a line. They are taken verbatim: declaring them is how a
    file overrides what its history says, so they do not go through the user id
    map.

    Args:
        head (bytes): Leading bytes of the file.

    Returns:
        Set[str]: Declared owners, empty if the file declares none.
    """
    # Cheap reject first, so files declaring nothing never reach the regex.
    if DECLARED_OWNER_MARKER not in head:
        return set()

    owners: Set[str] = set()

    for match in DECLARED_OWNER_RE.finditer(head):
        for token in decode(match.group("owners")).split():
            # Drops a trailing comment terminator such as `*/` or `-->`, which
            # no owner can look like.
            if any(character.isalnum() for character in token):
                owners.add(token)

    return owners


def has_blamable_lines(head: bytes) -> bool:
    """Check whether a file's own lines can say who wrote which part of it.

    Args:
        head (bytes): Leading bytes of the file.

    Returns:
        bool: Whether the file can be blamed line by line.
    """
    (empty, binary) = sniff_head(head)

    return not (empty or binary or is_lfs_pointer(head))
