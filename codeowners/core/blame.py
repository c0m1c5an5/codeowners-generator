"""Turning `git blame --incremental` output into file owners."""

from collections import defaultdict
from typing import Dict, Iterable, NamedTuple, Set, Tuple

from codeowners.exceptions import GitAnnotateError, GitAuthorMissingError

BLAME_HEADER_TAIL_FIELDS = 3
BLAME_OID_LENGTHS = frozenset({40, 64})
BLAME_AUTHOR_MAIL = "author-mail"
BLAME_HEX_DIGITS = "0123456789abcdef"


class OwnerRules(NamedTuple):
    """How blamed lines are turned into owners.

    Attributes:
        relevance (float): Percentage of the largest contribution that a
            contributor must reach to own the file.
        user_id_map (Dict[str, str]): Mapping of committer emails to user ids.
    """

    relevance: float
    user_id_map: Dict[str, str]


def is_blame_oid(field: str) -> bool:
    """Whether a field is an object id, which is what marks an entry header.

    Args:
        field (str): Field to test.

    Returns:
        bool: Whether the field is an object id.
    """
    # `strip` leaves anything that is not a hex digit behind, so an empty
    # result means every character was one.
    return len(field) in BLAME_OID_LENGTHS and not field.strip(BLAME_HEX_DIGITS)


def parse_blame_line_count(header: str) -> int:
    """Read the line count from the "<orig line> <final line> <count>" of a header.

    All three are required to be numbers: together with the object id they are
    what identifies a header, so a partial match means the stream is not shaped
    the way this parser assumes.

    Args:
        header (str): The entry header, object id included.

    Raises:
        GitAnnotateError: The header is malformed.

    Returns:
        int: Number of lines the entry covers.
    """
    (_, _, tail) = header.partition(" ")
    fields = tail.split(" ")

    if len(fields) != BLAME_HEADER_TAIL_FIELDS or not all(
        field.isdigit() for field in fields
    ):
        raise GitAnnotateError(header)

    return int(fields[-1])


def parse_blame_author_mail(value: str) -> str:
    """Read the address out of the value of an "author-mail" line.

    Args:
        value (str): Value the line carried.

    Returns:
        str: Author email, stripped of its angle brackets.
    """
    return value.strip().strip("<>")


def attribute_to_owners(
    lines_by_sha: Dict[str, int],
    owner_by_sha: Dict[str, str],
) -> Dict[str, int]:
    """Total each owner's blamed lines across the commits they wrote.

    Args:
        lines_by_sha (Dict[str, int]): Lines blamed on each commit.
        owner_by_sha (Dict[str, str]): Owner of each commit.

    Raises:
        GitAuthorMissingError: A commit was blamed but never given an author.

    Returns:
        Dict[str, int]: Lines attributed per owner.
    """
    contributions: Dict[str, int] = defaultdict(int)

    for sha, lines in lines_by_sha.items():
        owner = owner_by_sha.get(sha)
        if not owner:
            raise GitAuthorMissingError(sha)
        contributions[owner] += lines

    return contributions


def parse_blame(
    lines: Iterable[str],
    user_id_map: Dict[str, str],
) -> Tuple[Dict[str, int], int]:
    """Count blamed lines per owner in `git blame --incremental` output.

    Args:
        lines (Iterable[str]): Lines of `git blame --incremental` output. Read
            straight off the pipe, so a trailing newline on each is expected,
            but a list of bare lines parses the same.
        user_id_map (Dict[str, str]): Mapping of committer emails to user ids.

    Raises:
        GitAnnotateError: Failed to parse blame output.
        GitAuthorMissingError: A blamed commit had no author.

    Returns:
        Tuple[Dict[str, int], int]: Lines attributed per owner and total lines.
    """
    lines_by_sha: Dict[str, int] = defaultdict(int)
    owner_by_sha: Dict[str, str] = {}
    lines_total = 0

    sha = ""

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        (key, _, value) = line.partition(" ")

        if is_blame_oid(key):
            sha = key
            entry_lines = parse_blame_line_count(line)
            lines_by_sha[sha] += entry_lines
            lines_total += entry_lines
        elif key == BLAME_AUTHOR_MAIL:
            email = parse_blame_author_mail(value)
            owner_by_sha[sha] = user_id_map.get(email, email)

    return (attribute_to_owners(lines_by_sha, owner_by_sha), lines_total)


def take_owners(contributions: Dict[str, int], relevance: float) -> Set[str]:
    """Take everyone who wrote a comparable share of a file to its main author.

    Measuring each contributor against the largest one keeps the comparison
    between people rather than against the file: a quarter of a file earns
    ownership beside another quarter, and does not beside three quarters. The
    largest contributor always qualifies, so a blamed file always has an owner.

    Args:
        contributions (Dict[str, int]): Lines attributed per owner.
        relevance (float): Percentage of the largest contribution a contributor
            must reach to own the file.

    Returns:
        Set[str]: File owners, empty only when nothing was blamed.
    """
    if not contributions:
        return set()

    largest = max(contributions.values())

    return {
        owner
        for owner, lines in contributions.items()
        if (lines * 100) / largest >= relevance
    }
