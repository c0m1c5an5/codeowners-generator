import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from subprocess import CalledProcessError
from typing import Dict, Set, TextIO, Tuple

import jsonschema

from codeowners.exceptions import (
    CommandError,
    GitAnnotateError,
    GitEmailEmptyError,
    MissingOwnersError,
    SectionsNotSupportedError,
)

EMAIL_RE = re.compile(r"^[a-z\d]+\s+\(<([\d\w.@]+?)>.*$")
TEXTCHARS = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
GLOBCHARS = {" ", "*", "!", "\\", "[", "]"}
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


def escape_glob(input: str) -> str:
    """Escape glob special characters in string.

    Args:
        input (str): Input string.

    Returns:
        str: Escaped string.
    """
    escaped_str = ""
    for char in input:
        if char in GLOBCHARS:
            escaped_str += "\\" + char
        else:
            escaped_str += char
    return escaped_str


def unescape_glob(input: str) -> str:
    """Unescape glob special characters in string.

    Args:
        input (str): Input string.

    Returns:
        _type_: Unescaped string.
    """
    unescaped_str = ""
    input_length = len(input)
    i = 0

    while i < input_length:
        char = input[i]
        if char == "\\" and i + 1 < input_length and input[i + 1] in GLOBCHARS:
            unescaped_str += input[i + 1]
            i += 2
            continue
        unescaped_str += char
        i += 1
    return unescaped_str


def is_binary_file(file: Path) -> bool:
    """Check if file is binary.

    Args:
        file (Path): File to check.

    Returns:
        bool: Is the file binary.
    """
    with file.open("rb") as f:
        data = f.read(2048)
        return bool(data.translate(None, TEXTCHARS))


def is_empty(file: Path) -> bool:
    """Check if file is empty.

    Args:
        file (Path): File to check.

    Returns:
        bool: Is the file empty.
    """
    return file.stat().st_size == 0


def get_git_root() -> Path:
    """Get git root directory.

    Raises:
        CommandError: Git command failed.

    Returns:
        Path: Git root directory path.
    """
    try:
        rev_parse_output = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            text=True,
            universal_newlines=True,
            capture_output=True,
            check=True,
        )
        git_root = Path(rev_parse_output.stdout.strip())
    except CalledProcessError as e:
        stderr: str = e.stderr.decode(encoding="utf-8")
        stderr = json.dumps(stderr.strip())
        raise CommandError(stderr) from e
    else:
        return git_root


def get_git_staged_files() -> Set[Path]:
    """Get all staged files.

    Raises:
        CommandError: Git command failed.

    Returns:
        Set[Path]: Staged files.
    """
    try:
        files_output = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--deduplicate",
                "--empty-directory",
                "--full-name",
            ],
            capture_output=True,
            check=True,
        )
        items = files_output.stdout.split(b"\x00")
        compact_items = [ i for i in items if bool(i) ]
        result: set[Path] = set()
        for item in compact_items:
            path = item.decode(encoding="utf-8")
            result.add(Path(path))
    except CalledProcessError as e:
        stderr: str = e.stderr.decode(encoding="utf-8")
        stderr = json.dumps(stderr.strip())
        raise CommandError(stderr) from e
    else:
        return result


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
        CommandError: Git command failed.

    Returns:
        str: Email
    """
    try:
        config_output = subprocess.run(
            ["git", "config", "user.email"],
            text=True,
            universal_newlines=True,
            capture_output=True,
            check=True,
        )
        email = config_output.stdout.strip()
        if not email:
            raise GitEmailEmptyError()
    except CalledProcessError as e:
        stderr: str = e.stderr
        stderr = json.dumps(stderr.strip())
        raise CommandError(stderr) from e
    else:
        return email


def get_git_owners(
    file: Path,
    default_email: str,
    threshold: float,
    user_id_map: Dict[str, str],
) -> Set[str]:
    """Calculate owners of file based on git annotate output.

    Args:
        file (Path): Target file.
        default_email (str): Email to replace <not.committed.yet> with.
        threshold (float): Contribution percentage required for committer to be considered an owner.
        user_id_map (Dict[str, str]): Mapping of committer emails to user ids.

    Raises:
        GitAnnotateError: Failed to parse annotate output.
        CommandError: Git command failed.

    Returns:
        Set[str]: File owners.
    """
    try:
        annotate_output = subprocess.run(
            ["git", "annotate", "-e", str(file)],
            text=True,
            universal_newlines=True,
            capture_output=True,
            check=True,
        )
    except CalledProcessError as e:
        stderr: str = e.stderr
        stderr = json.dumps(stderr.strip())
        raise CommandError(stderr) from e

    contributions: Dict[str, int] = defaultdict(int)
    lines_total = 0

    for line in annotate_output.stdout.splitlines():
        match = EMAIL_RE.match(line)
        if match is None:
            raise GitAnnotateError()

        email = match.group(1)
        contributions[email] += 1
        lines_total += 1

    owners: Set[str] = set()

    for committer_email, lines in contributions.items():
        email = committer_email

        if email == "not.committed.yet":
            email = default_email

        if email in user_id_map:
            email = user_id_map[email]

        percent = (lines * 100) / lines_total
        if percent > threshold:
            owners.add(email)

    return owners


def parse_codeowners(
    codeowners: TextIO,
) -> Tuple[Dict[Path, Set[str]], Set[Path]]:
    """Parse codeowners file into a dict.

    Args:
        codeowners (TextIO): Codeowners IO stream.
        workdir (Path): Parse root directory.

    Raises:
        SectionsNotSupportedError: Encountered section.
        MissingOwnersError: No owner provided for file.

    Returns:
        Tuple[Dict[Path, Set[str]], Set[Path]]: Map of files to owners and a set of merge conflict files.
    """
    line_number = 0
    conflict_files: Set[Path] = set()
    owners_mapping: Dict[Path, Set[str]] = {}

    while True:
        line = codeowners.readline()
        line_number += 1
        if not line:
            break

        tokens = line.split()

        if (
            not tokens
            or tokens[0].startswith("#")
            or tokens[0] in ["<<<<<<<", "=======", ">>>>>>>"]
        ):
            continue
        elif tokens[0].startswith("["):
            raise SectionsNotSupportedError(line_number)
        elif len(tokens) < 2:
            raise MissingOwnersError(line_number)

        (path, owners) = (unescape_glob(tokens[0]), set(tokens[1:]))
        file = Path(path)

        if owners_mapping.get(file):
            conflict_files.add(file)
        else:
            owners_mapping[file] = owners

    return (owners_mapping, conflict_files)


def dump_codeowners(codeowners: TextIO, owners_mapping: Dict[Path, Set[str]]) -> None:
    """Dump codeowners rules to a file.

    Args:
        codeowners (TextIO): Codeowners IO stream.
        owners_mapping (Dict[str, Set[str]]): Map of file paths to owners.

    """
    codeowners.write(
        "#####################################################################\n"
        "# This file is generated by pre-commit. Do not edit it manually.    #\n"
        "# Leave merge conflicts as is. They will be resolved by pre-commit. #\n"
        "#####################################################################\n\n"
    )

    posix_owners_mapping = {str(k.as_posix()): v for k, v in owners_mapping.items()}

    for file in sorted(posix_owners_mapping.keys()):
        codeowners.write(
            escape_glob(file)
            + " "
            + " ".join(sorted(posix_owners_mapping[file]))
            + "\n"
        )


def update_owners_mapping(  # noqa: PLR0913
    owners_mapping: Dict[Path, Set[str]],
    files: Set[Path],
    codeowners_file: Path,
    default_email: str,
    threshold: float,
    user_id_map: Dict[str, str],
) -> Dict[Path, Set[str]]:
    """Update file entries in owners mapping.

    Args:
        owners_mapping (Dict[Path, Set[str]]): Source map of file paths to owners.
        files (List[Path]): Files to update.
        codeowners_file (Path): Codeowners file to exclude from update.
        default_email (str): Email to replace <not.committed.yet> with.
        threshold (float): Contribution percentage required for committer to be considered an owner.
        user_id_map (Dict[str, str]): Mapping of committer emails to user ids.

    Raises:
        GitAnnotateError: Failed to parse annotate output.
        CommandError: Git command failed.

    Returns:
        Dict[Path, Set[str]]: Map of files to owners.
    """
    result: Dict[Path, Set[str]] = owners_mapping.copy()
    for file in files:
        owners = set()
        if not (file == codeowners_file or is_empty(file) or is_binary_file(file)):
            owners = get_git_owners(file, default_email, threshold, user_id_map)

        if owners:
            result[file] = owners
        elif result.get(file):
            del result[file]

    return result
