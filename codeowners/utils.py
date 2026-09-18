import os
import re
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, NamedTuple, Set, TextIO, Tuple

import jsonschema

from codeowners.exceptions import (
    GitAnnotateError,
    GitAuthorMissingError,
    GitEmailEmptyError,
)

TEXTCHARS = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
GLOBCHARS = frozenset({" ", "*", "!", "\\", "[", "]"})
ESCAPE_GLOB_TABLE = {ord(char): "\\" + char for char in GLOBCHARS}
SNIFF_SIZE = 2048
HEAD_SIZE = 4096
DECLARED_OWNER_MARKER = b"codeowner:"
# Codeowner comment format allows for different single line comment prefixes:
#     # codeowner: @alice        // codeowner: @bob        -- codeowner: @team
DECLARED_OWNER_RE = re.compile(
    rb"^[ \t]*[^\w\s]{1,4}[ \t]*codeowner:[ \t]*(?P<owners>[^\r\n]*)\r?$",
    re.MULTILINE,
)
BLAME_HEADER_TAIL_FIELDS = 3
BLAME_OID_LENGTHS = frozenset({40, 64})
BLAME_AUTHOR_MAIL = "author-mail"
BLAME_HEX_DIGITS = "0123456789abcdef"
USER_ID_MAP_SCHEMA = {
    "type": "object",
    "patternProperties": {
        r"^[a-zA-Z0-9!#$%&*+=?^_`{|}~().,:;<>@'\"\-\[\]\/\\ ]+$": {
            "type": "string",
            "pattern": r"^[a-zA-Z0-9!#$%&*+=?^_`{|}~().,:;<>@'\"\-\[\]\/\\ ]+$",
            "description": "Commit email to user mapping.",
        },
    },
}


class OwnerRules(NamedTuple):
    """How blamed lines are turned into owners.

    Attributes:
        relevance (float): Percentage of the largest contribution that a
            contributor must reach to own the file.
        user_id_map (Dict[str, str]): Mapping of committer emails to user ids.
    """

    relevance: float
    user_id_map: Dict[str, str]


def decode(raw: bytes) -> str:
    """Decode git output, replacing anything that is not valid UTF-8.

    Args:
        raw (bytes): Raw bytes from git.

    Returns:
        str: Decoded string.
    """
    return raw.decode(encoding="utf-8", errors="replace")


def escape_glob(input: str) -> str:
    """Escape glob special characters in string.

    Args:
        input (str): Input string.

    Returns:
        str: Escaped string.
    """
    return input.translate(ESCAPE_GLOB_TABLE)


def read_head(file: Path) -> bytes:
    """Read the start of a file, in one read.

    Enough both to classify the file and to hold a declared owners block, so
    neither costs a read of its own.

    Args:
        file (Path): File to read.

    Returns:
        bytes: Leading bytes of the file.
    """
    with file.open("rb") as f:
        return f.read(HEAD_SIZE)


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


def decode_paths(raw: bytes) -> Set[Path]:
    """Split NUL-delimited git output into paths.

    Args:
        raw (bytes): NUL-delimited output.

    Returns:
        Set[Path]: Paths it named.
    """
    return {Path(decode(item)) for item in raw.split(b"\x00") if item}


def get_git_files() -> Set[Path]:
    """Get every file tracked in the working tree.

    Listed with `-z`, so a path outside ASCII arrives as git stored it rather
    than in the escaped form git quotes for terminals.

    Raises:
        CalledProcessError: Git command failed.

    Returns:
        Set[Path]: Tracked files.
    """
    files_output = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        check=True,
    )

    return decode_paths(files_output.stdout)


def get_cpu_count() -> int:
    """Get how many CPUs this process may use.

    `os.process_cpu_count` honours CPU affinity, which matters under `taskset`
    or in a container, but it only exists from Python 3.13.

    Returns:
        int: Usable CPU count, at least one.
    """
    count = getattr(os, "process_cpu_count", os.cpu_count)()

    return count or 1


def get_git_root() -> Path:
    """Get git root directory.

    Returns:
        Path: Git root directory path.
    """
    rev_parse_output = subprocess.run(
        ("git", "rev-parse", "--show-toplevel"),
        text=True,
        capture_output=True,
        check=True,
    )
    git_root = Path(rev_parse_output.stdout.strip())

    return git_root


def create_worktree_commit(author_email: str) -> str:
    """Snapshot the index and working tree as a dangling commit object.

    Args:
        author_email (str): Email to attribute uncommitted lines to.


    Returns:
        str: Hash of the snapshot, or "HEAD" when the tree is clean and git
            therefore has nothing to snapshot.
    """
    stash_output = subprocess.run(
        ("git", "stash", "create"),
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "codeowners",
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_COMMITTER_NAME": "codeowners",
            "GIT_COMMITTER_EMAIL": author_email,
        },
        capture_output=True,
        check=True,
        text=True
    )

    return stash_output.stdout.strip() or "HEAD"


def validate_user_map(user_map: Dict[str, str]) -> None:
    """Validate user map data structure.

    Args:
        user_map (Dict): User map.

    Raises:
        ValidationError: When data is invalid.
    """
    jsonschema.validate(user_map, USER_ID_MAP_SCHEMA)


def get_git_email() -> str:
    """Get current git user email.

    Raises:
        GitEmailEmptyError: Email is an empty string.

    Returns:
        str: Email
    """
    config_output = subprocess.run(
        ("git", "config", "user.email"),
        text=True,
        capture_output=True,
        check=True,
    )
    email = config_output.stdout.strip()
    if not email:
        raise GitEmailEmptyError()

    return email


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


def get_git_owners(file: Path, rules: OwnerRules, revision: str) -> Set[str]:
    """Calculate owners of file based on git blame output.

    Args:
        file (Path): Target file.
        rules (OwnerRules): How to turn blamed lines into owners.
        revision (str): Revision to blame.

    Raises:
        GitAnnotateError: Failed to parse blame output.
        GitAuthorMissingError: A blamed commit had no author.
        CalledProcessError: Git command failed.

    Returns:
        Set[str]: File owners.
    """
    with subprocess.Popen(
        ("git", "blame", "--incremental", revision, "--", str(file)),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="replace",
    ) as process:
        (contributions, _) = parse_blame(process.stdout, rules.user_id_map)

    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, process.args)

    return take_owners(contributions, rules.relevance)

def dump_codeowners(codeowners: TextIO, owners_mapping: Dict[Path, Set[str]]) -> None:
    """Dump codeowners rules to a file.

    Args:
        codeowners (TextIO): Codeowners IO stream.
        owners_mapping (Dict[str, Set[str]]): Map of file paths to owners.

    """
    posix_owners_mapping = {k.as_posix(): v for k, v in owners_mapping.items()}

    rules = [
        escape_glob(file) + " " + " ".join(sorted(posix_owners_mapping[file]))
        for file in sorted(posix_owners_mapping)
    ]

    if rules:
        codeowners.write("\n\n".join(rules) + "\n")


def generate_owners_mapping(
    files: Set[Path],
    codeowners_file: Path,
    default_email: str,
    rules: OwnerRules,
    jobs: int,
) -> Dict[Path, Set[str]]:
    """Map each file to its owners.

    A file that declares owners in a header block is taken at its word; the
    rest are blamed.

    Args:
        files (Set[Path]): Files to generate owners for.
        codeowners_file (Path): Codeowners file to exclude from the result.
        default_email (str): Email to attribute uncommitted lines to.
        rules (OwnerRules): How to turn blamed lines into owners.
        jobs (int): Number of blames to run concurrently.

    Raises:
        GitAnnotateError: Failed to parse blame output.
        GitAuthorMissingError: A blamed commit had no author.

    Returns:
        Dict[Path, Set[str]]: Map of files to owners.
    """
    revision = create_worktree_commit(default_email)

    def resolve(file: Path) -> Tuple[Path, Set[str]]:
        if file == codeowners_file:
            return (file, set())

        head = read_head(file)
        (empty, binary) = sniff_head(head)
        if empty or binary:
            return (file, set())

        declared = parse_declared_owners(head)
        if declared:
            return (file, declared)

        return (file, get_git_owners(file, rules, revision))

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        return {
            file: owners for (file, owners) in executor.map(resolve, files) if owners
        }
