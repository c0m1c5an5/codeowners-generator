"""Running git and handing its output to the core."""

import os
import subprocess
from pathlib import Path
from typing import Set, TextIO, cast

from codeowners.core.blame import OwnerRules, parse_blame, take_owners
from codeowners.core.content import decode_paths
from codeowners.exceptions import GitEmailEmptyError


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
        ("git", "ls-files", "-z"),
        capture_output=True,
        check=True,
    )

    return decode_paths(files_output.stdout)


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
        text=True,
    )

    return stash_output.stdout.strip() or "HEAD"


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
        (contributions, _) = parse_blame(
            cast(TextIO, process.stdout), rules.user_id_map
        )

    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, process.args)

    return take_owners(contributions, rules.relevance)
