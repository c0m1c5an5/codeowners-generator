"""Reading and writing the files the run depends on."""

from pathlib import Path
from typing import Dict, Set

from codeowners.core.content import HEAD_SIZE
from codeowners.core.rules import (
    equivalent_codeowners,
    format_codeowners,
    parse_codeowners,
)
from codeowners.core.users import parse_user_map


def read_head(file: Path) -> bytes:
    """Read the start of a file, in one read.

    Args:
        file (Path): File to read.

    Returns:
        bytes: Leading bytes of the file.
    """
    with file.open("rb") as head_stream:
        return head_stream.read(HEAD_SIZE)


def load_user_map(user_map_file: Path) -> Dict[str, str]:
    """Read and validate a committer email to user id map.

    Args:
        user_map_file (Path): File to read.

    Returns:
        Dict[str, str]: Mapping of committer emails to user ids.
    """
    return parse_user_map(user_map_file.read_text())


def states_owners(
    codeowners_file: Path,
    owners_mapping: Dict[Path, Set[str]],
) -> bool:
    """Whether the file already states exactly these owners.

    Args:
        codeowners_file (Path): File to read.
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.

    Returns:
        bool: Whether rewriting the file would leave its rules unchanged.
    """
    if not codeowners_file.is_file():
        return False

    with codeowners_file.open("r") as codeowners_in_stream:
        stated_rules = parse_codeowners(codeowners_in_stream)

    return equivalent_codeowners(stated_rules, owners_mapping)


def write_codeowners(
    codeowners_file: Path,
    owners_mapping: Dict[Path, Set[str]],
) -> None:
    """Write the owners mapping out as a codeowners file.

    Args:
        codeowners_file (Path): File to write.
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.
    """
    codeowners_file.write_text(format_codeowners(owners_mapping))
