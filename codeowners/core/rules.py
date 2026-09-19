"""The CODEOWNERS file format: rendering, parsing and comparison."""

import re
from pathlib import Path
from typing import Dict, Iterable, Set

GLOBCHARS = frozenset({" ", "*", "!", "\\", "[", "]"})
ESCAPE_GLOB_TABLE = {ord(char): "\\" + char for char in GLOBCHARS}
MINIMUM_RULE_TOKENS = 2
RULE_FIELDS_RE = re.compile(r"(?<!\\)\s+")


def escape_glob(input: str) -> str:
    """Escape glob special characters in string.

    Args:
        input (str): Input string.

    Returns:
        str: Escaped string.
    """
    return input.translate(ESCAPE_GLOB_TABLE)


def render_codeowners(owners_mapping: Dict[Path, Set[str]]) -> Dict[str, Set[str]]:
    """Render an owners mapping as codeowners line format.

    Args:
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.

    Returns:
        Dict[str, Set[str]]: Owners stated per path.
    """
    return {
        escape_glob(file.as_posix()): owners for file, owners in owners_mapping.items()
    }


def parse_codeowners(lines: Iterable[str]) -> Dict[str, Set[str]]:
    """Parse lines of a codeowners file.

    Args:
        lines (Iterable[str]): Lines of the codeowners file.

    Returns:
        Dict[str, Set[str]]: Owners stated per path.
    """
    rules: Dict[str, Set[str]] = {}

    for line in lines:
        tokens = [field for field in RULE_FIELDS_RE.split(line.strip()) if field]

        if len(tokens) < MINIMUM_RULE_TOKENS or tokens[0].startswith(("#", "[")):
            continue

        rules[tokens[0]] = set(tokens[1:])

    return rules


def format_codeowners(owners_mapping: Dict[Path, Set[str]]) -> str:
    """Format an owners mapping as the contents of a codeowners file.

    Args:
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.

    Returns:
        str: File contents, empty when nothing is owned.
    """
    rendered = render_codeowners(owners_mapping)

    rules = [" ".join((path, *sorted(rendered[path]))) for path in sorted(rendered)]

    if not rules:
        return ""

    return "\n\n".join(rules) + "\n"


def equivalent_codeowners(
    stated_rules: Dict[str, Set[str]],
    owners_mapping: Dict[Path, Set[str]],
) -> bool:
    """Whether stated rules say exactly what this owners mapping says.

    Args:
        stated_rules (Dict[str, Set[str]]): Rules a codeowners file states.
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.

    Returns:
        bool: Whether rewriting the file would leave its rules unchanged.
    """
    return stated_rules == render_codeowners(owners_mapping)
