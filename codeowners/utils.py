import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from subprocess import CalledProcessError
from typing import Dict, List, Set

import jsonschema
from jsonschema.exceptions import ValidationError

from codeowners.exceptions import (
    AnnotateError,
    DumpError,
    EmailError,
    ParseError,
    UpdateError,
    UserMapError,
)

EMAIL_RE = re.compile(r"^[a-z\d]+\s+\(<([\d\w.@]+?)>.*$")
TEXTCHARS = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
user_id_map_SCHEMA = {
    "type": "object",
    "patternProperties": {
        r"^[a-zA-Z0-9!#$%&*+=?^_`{|}~().,:;<>@'\"\-\[\]\/\\ ]+$": {
            "type": "string",
            "pattern": r"^[a-zA-Z0-9!#$%&*+=?^_`{|}~().,:;<>@'\"\-\[\]\/\\ ]+$",
            "description": "Commit email to user mapping.",
        },
    },
}


def is_binary_file(file: Path) -> bool:
    with file.open("rb") as f:
        data = f.read(2048)
        return bool(data.translate(None, TEXTCHARS))


def is_empty(file: Path) -> bool:
    return file.stat().st_size == 0


def load_user_id_map(map_file: Path) -> Dict:
    """Load user map to dict.

    Args:
        map_file (Path): Json file.

    Raises:
        UserMapError: When unable to access the file.
        UserMapError: When json schema validation fails.

    Returns:
        Dict: Mapping of commiter emails to user ids.
    """
    try:
        with map_file.open("r") as f:
            data = json.load(f)
    except OSError as e:
        raise UserMapError(e.strerror) from e
    try:
        jsonschema.validate(data, user_id_map_SCHEMA)
    except ValidationError as e:
        raise UserMapError(e.message) from e

    return data


def get_git_email() -> str:
    """Get current git user email.

    Raises:
        EmailError: When email acquisition fails.

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
            raise EmailError("Git config returned no email")
        return email
    except CalledProcessError as e:
        stderr = e.stderr.strip()
        raise EmailError(stderr) from e


def get_git_owners(
    path: str, default_email: str, threshold: float, user_id_map: Dict[str, str]
) -> Set[str]:
    """Calculate owners of file based on git annotate output.

    Args:
        path (str): Path of target file.
        default_email (str): Email to replace <not.committed.yet> with.
        threshold (float): Contribution percentage required for commiter to be considered an owner.
        user_id_map (Dict[str, str]): Mapping of commiter emails to user ids.

    Raises:
        AnnotateError: When git annotate command fails.

    Returns:
        Set[str]: Set of file owners.
    """
    try:
        blame_output = subprocess.run(
            ["git", "annotate", "-e", path],
            text=True,
            universal_newlines=True,
            capture_output=True,
            check=True,
        )
    except CalledProcessError as e:
        stderr = e.stderr.strip()
        if "no such path" in stderr and "in HEAD" in stderr:
            message = (
                "File path is not in git. Run 'git add' to add the file before use."
            )
        else:
            message = stderr
        raise AnnotateError(message) from e

    contributions: Dict[str, int] = defaultdict(int)
    lines_total = 0

    for line in blame_output.stdout.splitlines():
        match = EMAIL_RE.match(line)
        if match is None:
            raise AnnotateError("Git annotate line does not match email regex.")

        email = match.group(1)
        contributions[email] += 1
        lines_total += 1

    owners: Set[str] = set()

    for email, lines in contributions.items():
        if email == "not.committed.yet":
            email = default_email

        if email in user_id_map:
            email = user_id_map[email]

        percent = (lines * 100) / lines_total
        if percent > threshold:
            owners.add(email)

    return owners


def parse_codeowners(codeowners_file: Path) -> Dict[str, Set[str]]:
    """Parse codeowners file into a dict.

    Args:
        codeowners_file (Path): Codeowners file.

    Raises:
        ParseError: When unable to access file.
        ParseError: When file contents are malformed.

    Returns:
        Dict[str, Set[str]]: Map of file paths to owners.
    """
    owners_mapping: Dict[str, Set[str]] = dict()
    line_number = 0

    try:
        with codeowners_file.open("r") as f:
            while True:
                line = f.readline()
                line_number += 1
                if not line:
                    break

                tokens = line.split()

                if not tokens or tokens[0].startswith("#"):
                    continue
                elif tokens[0].startswith("["):
                    raise ParseError(
                        "Sections are not supported: line {line_number}",
                    )
                elif len(tokens) < 2:
                    raise ParseError(
                        "At least one owner has to be provided: line {line_number}",
                    )

                (file, owners) = (tokens[0], set(tokens[1:]))
                current_owners = owners_mapping.get(file)
                if current_owners:
                    owners_mapping[file] = current_owners.union(owners)
                else:
                    owners_mapping[file] = owners
        return owners_mapping
    except OSError as e:
        raise ParseError(e.strerror) from e


def dump_codeowners(codeowners_file: Path, owners_mapping: Dict[str, Set[str]]) -> None:
    """Dump codeowners rules to a file.

    Args:
        codeowners_file (Path): Codeowners file.
        owners_mapping (Dict[str, Set[str]]): Map of file paths to owners.

    Raises:
        DumpError: When unable to access file.
    """
    try:
        with codeowners_file.open("w") as f:
            for path in sorted(owners_mapping.keys()):
                f.write(path + " " + " ".join(sorted(owners_mapping[path])) + "\n")
    except OSError as e:
        raise DumpError(e.strerror) from e


def update_owners_mapping(
    owners_mapping: Dict[str, Set[str]],
    files: List[Path],
    default_email: str,
    threshold: float,
    codeowners_path: str,
    user_id_map: Dict[str, str],
) -> Dict[str, Set[str]]:
    """Update file entries in owners mapping.

    Args:
        owners_mapping (Dict[str, Set[str]]): Source map of file paths to owners.
        files (List[Path]): Files to update.
        default_email (str): Email to replace <not.committed.yet> with.
        threshold (float): Contribution percentage required for commiter to be considered an owner.
        codeowners_path (str): Path of codeowners file to exclude from mapping.
        user_id_map (Dict[str, str]): Mapping of commiter emails to user ids.

    Raises:
        UpdateError: When file owner calculation fails.

    Returns:
        Dict[str, Set[str]]: Map of file paths to owners.
    """
    result = owners_mapping.copy()
    for file in files:
        path = str(file)
        owners = set()

        try:
            if file.is_file() and not (
                is_binary_file(file) or is_empty(file) or path == codeowners_path
            ):
                owners = get_git_owners(path, default_email, threshold, user_id_map)
        except AnnotateError as e:
            raise UpdateError(
                f"Calculating contributions of '{str(file)}' failed: {str(e)}"
            ) from e

        if owners:
            result[path] = owners
        elif result.get(path):
            del result[path]

    return result
