"""Reading and writing the files the run depends on."""

from pathlib import Path
from typing import Dict, Set

from codeowners.core.rules import (
    equivalent_codeowners,
    format_codeowners,
    frame_codeowners,
    parse_codeowners,
    split_boundaries,
)
from codeowners.core.users import parse_user_map


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

    Only the rules between the boundaries are read, since the rest of the file
    is not this tool's to state or to rewrite.

    Args:
        codeowners_file (Path): File to read.
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.

    Returns:
        bool: Whether rewriting the file would leave its rules unchanged.
    """
    if not codeowners_file.is_file():
        return False

    (_, generated, _) = split_boundaries(codeowners_file.read_text())

    return equivalent_codeowners(parse_codeowners(generated), owners_mapping)


def write_codeowners(
    codeowners_file: Path,
    owners_mapping: Dict[Path, Set[str]],
) -> None:
    """Write the owners mapping out as a codeowners file.

    Only what is between the boundaries is written; the rules a hand wrote
    above or below them are read back out of the file and kept.

    Args:
        codeowners_file (Path): File to write.
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.
    """
    stated = codeowners_file.read_text() if codeowners_file.is_file() else ""

    codeowners_file.write_text(
        frame_codeowners(stated, format_codeowners(owners_mapping))
    )
