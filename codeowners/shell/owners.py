"""Resolving the owners of many files at once."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Set, Tuple

from codeowners.core.blame import OwnerRules
from codeowners.core.content import owners_from_head
from codeowners.shell.fs import read_head
from codeowners.shell.git import create_worktree_commit, get_git_owners


def get_cpu_count() -> int:
    """Get how many CPUs this process may use.

    `os.process_cpu_count` honours CPU affinity, which matters under `taskset`
    or in a container, but it only exists from Python 3.13.

    Returns:
        int: Usable CPU count, at least one.
    """
    count = getattr(os, "process_cpu_count", os.cpu_count)()

    return count or 1


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

        declared = owners_from_head(read_head(file))
        if declared is not None:
            return (file, declared)

        return (file, get_git_owners(file, rules, revision))

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        return {
            file: owners for (file, owners) in executor.map(resolve, files) if owners
        }
