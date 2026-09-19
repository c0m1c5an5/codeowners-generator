"""Reading file content: decoding, classification and declared owners."""

import re
from pathlib import Path
from typing import Optional, Set, Tuple

TEXTCHARS = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
SNIFF_SIZE = 2048
# Enough both to classify a file and to hold a declared owners block, so
# neither costs a read of its own.
HEAD_SIZE = 4096
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


def sniff_head(head: bytes) -> Tuple[bool, bool]:
    """Check whether a file is empty and whether it is binary.

    Args:
        head (bytes): Leading bytes of the file.

    Returns:
        Tuple[bool, bool]: Is the file empty, is the file binary.
    """
    sample = head[:SNIFF_SIZE]

    return (not sample, bool(sample.translate(None, TEXTCHARS)))


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


def owners_from_head(head: bytes) -> Optional[Set[str]]:
    """Decide what a file's own content says about its owners.

    Args:
        head (bytes): Leading bytes of the file.

    Returns:
        Optional[Set[str]]: The owners the file declares, an empty set when
            the file cannot be owned at all, or None when its content settles
            nothing and its history has to be blamed.
    """
    (empty, binary) = sniff_head(head)

    if empty or binary:
        return set()

    return parse_declared_owners(head) or None
