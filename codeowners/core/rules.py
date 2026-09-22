"""The CODEOWNERS file format: rendering, parsing and comparison."""

import re
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

MINIMUM_RULE_TOKENS = 2
# What a path has to be escaped against: the whitespace that separates the
# fields of a rule, the characters a path is glob matched with, and the
# backslash that escapes any of them. Written as a class rather than a table so
# that it stays the same `\s` the fields below are found with.
PATH_ESCAPE_RE = re.compile(r"([\s\\*!\[\]])")
# An owner is never matched as a glob, so only the separator has to be escaped.
OWNER_ESCAPE_RE = re.compile(r"([\s\\])")
# One field of a rule: escaped pairs, and anything that is neither a separator
# nor an escape. Reading a pair whole is what keeps an escaped backslash at the
# end of a path from escaping the space that follows it.
RULE_FIELD_RE = re.compile(r"(?:\\.|[^\s\\])+")
# A leading `#` opens a comment and a leading `[` a section, so a rule states
# neither.
RULE_PREFIXES_IGNORED = ("#", "[")
# The boundaries the generated rules are written between, armoured the way
# openssh and gpg armour a block of their own. Both are comments, so a reader
# of the file passes over them, and whatever a hand writes outside them is
# left where it was written.
BEGIN_BOUNDARY = "# -----BEGIN CODEOWNERS-----"
END_BOUNDARY = "# -----END CODEOWNERS-----"


def escape_path(file: str) -> str:
    """Escape a path so that it is read back as the one file it names.

    Args:
        file (str): Path to escape.

    Returns:
        str: Escaped path.
    """
    escaped = PATH_ESCAPE_RE.sub(r"\\\1", file)

    # `#` means a comment only where a rule would start, so it is escaped only
    # there, leaving a path such as `C#/Program.cs` as it is written elsewhere.
    if escaped.startswith("#"):
        return "\\" + escaped

    return escaped


def escape_owner(owner: str) -> str:
    """Escape an owner so that it is read back as the one owner it names.

    Args:
        owner (str): Owner to escape.

    Returns:
        str: Escaped owner.
    """
    return OWNER_ESCAPE_RE.sub(r"\\\1", owner)


def can_be_stated(file: Path) -> bool:
    """Check whether a rule can be written for a file at all.

    A rule is one line, and there is no escape for a line break that a reader
    going line by line would not read as the end of the rule. Git hands such a
    name over intact, since it delimits its own output with NULs, but nothing
    can be stated about it here.

    Args:
        file (Path): File to state a rule for.

    Returns:
        bool: Whether the path fits on the one line a rule has.
    """
    path = file.as_posix()

    return path.splitlines() == [path]


def render_codeowners(owners_mapping: Dict[Path, Set[str]]) -> Dict[str, Set[str]]:
    """Render an owners mapping as codeowners line format.

    Args:
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.

    Returns:
        Dict[str, Set[str]]: Owners stated per path, as the file states them.
    """
    return {
        escape_path(file.as_posix()): {escape_owner(owner) for owner in owners}
        for file, owners in owners_mapping.items()
    }


def parse_codeowners(lines: Iterable[str]) -> Dict[str, Set[str]]:
    """Parse lines of a codeowners file.

    Fields are left escaped, which is how `render_codeowners` states them, so
    the two can be compared without either having to guess at the other.

    Args:
        lines (Iterable[str]): Lines of the codeowners file.

    Returns:
        Dict[str, Set[str]]: Owners stated per path.
    """
    rules: Dict[str, Set[str]] = {}

    for line in lines:
        tokens = RULE_FIELD_RE.findall(line)

        if len(tokens) < MINIMUM_RULE_TOKENS or tokens[0].startswith(
            RULE_PREFIXES_IGNORED
        ):
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


def find_closing_boundary(stated: List[str], begin: int) -> int:
    """Find where the generated rules end.

    An opening boundary with nothing closing it takes the rest of the file, so
    that a closing line lost to an edit costs the rules below it rather than
    the hand written ones above.

    Args:
        stated (List[str]): Lines of a codeowners file, each stripped.
        begin (int): Line the opening boundary is stated on.

    Returns:
        int: Line the closing boundary is stated on, or the end of the file.
    """
    following = stated[begin:]

    if END_BOUNDARY in following:
        return begin + following.index(END_BOUNDARY)

    return len(stated)


def split_boundaries(stated: str) -> Tuple[List[str], List[str], List[str]]:
    """Split a codeowners file at the boundaries the generated rules sit between.

    A file stating no boundaries is one this tool wrote before it stated any,
    so all of it is taken as generated.

    Args:
        stated (str): Contents of a codeowners file.

    Returns:
        Tuple[List[str], List[str], List[str]]: The lines written above, between
            and below the boundaries, the boundaries themselves left out.
    """
    lines = stated.splitlines()
    boundaries = [line.strip() for line in lines]

    if BEGIN_BOUNDARY not in boundaries:
        return ([], lines, [])

    begin = boundaries.index(BEGIN_BOUNDARY)
    end = find_closing_boundary(boundaries, begin)

    return (lines[:begin], lines[begin + 1 : end], lines[end + 1 :])


def frame_codeowners(stated: str, rules: str) -> str:
    """Write generated rules between the boundaries, leaving every other line.

    Args:
        stated (str): Contents the codeowners file already has.
        rules (str): Generated rules, as `format_codeowners` states them.

    Returns:
        str: Contents stating these rules between the boundaries, and outside
            them only what was written there by hand.
    """
    (above, _, below) = split_boundaries(stated)
    generated = (BEGIN_BOUNDARY, *rules.splitlines(), END_BOUNDARY)

    return "\n".join((*above, *generated, *below)) + "\n"
