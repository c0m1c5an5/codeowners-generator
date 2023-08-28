# ruff: noqa: C901, PLR0911, PLR0912, PLR0915
# C901 function is too complex
# PLR0911 Too many return statements
# PLR0912 Too many branches
# PLR0915 Too many statements

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Set

from codeowners.exceptions import Error
from codeowners.utils import (
    dump_codeowners,
    get_git_email,
    get_git_staged_files,
    load_user_map,
    parse_codeowners,
    print_err,
    update_owners_mapping,
)


def cli(argv: List[str] = sys.argv[1:]) -> int:
    """Codeowners cli.

    Args:
        argv (List[str], optional): Input arguments. Defaults to sys.argv[1:].

    Returns:
        int: Return code
    """
    parser = argparse.ArgumentParser(
        description="Generate CODEOWNERS file from git repo.",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path("./CODEOWNERS"),
        help="path to codeowners file",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=25.0,
        help="percent threshold",
    )
    parser.add_argument(
        "-m",
        "--user-map",
        type=Path,
        required=False,
        help="path to user map",
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="paths to files",
    )

    args = parser.parse_args()
    codeowners_file: Path = args.out
    user_map_file: Path = args.user_map
    threshold: float = args.threshold
    files: Set[Path] = set(args.files)
    user_id_map: Dict[str, str] = {}
    workdir: Path = Path.cwd()

    try:
        default_email = get_git_email()
    except Error as e:
        print_err(f"Error: Unable to get email form git: {e!s}")
        return 1

    try:
        staged_files = get_git_staged_files()
        staged_files.discard(codeowners_file.resolve())
    except Error as e:
        print_err(f"Error: Unable to staged files form git: {e!s}")
        return 1

    try:
        if user_map_file:
            user_id_map = load_user_map(user_map_file)
        else:
            print_err(
                "Warning: User map not provided. All owners will appear as committer email."
            )
    except Error as e:
        print_err(f"Error: Decoding user map '{user_map_file!s}' failed: {e!s}")
        return 1

    try:
        (owners_mapping, conflict_files) = parse_codeowners(codeowners_file)
    except Error as e:
        print_err(f"Error: Parsing '{codeowners_file!s}' failed: {e!s}")
        return 1

    filtered_owners_mapping: Dict[Path, Set[str]] = {}
    for k, v in owners_mapping.items():
        if workdir in k.parents and k in staged_files:
            filtered_owners_mapping[k] = v

    filtered_files: Set[Path] = set()
    for f in files.union(conflict_files):
        file = f.resolve()
        if workdir in file.parents and file in staged_files:
            files.add(file)

    try:
        updated_owners_mapping = update_owners_mapping(
            filtered_owners_mapping,
            filtered_files,
            codeowners_file,
            default_email,
            threshold,
            user_id_map,
        )
    except Error as e:
        print_err(f"Error: Updating owners table failed: {e!s}")
        return 1

    try:
        dump_codeowners(codeowners_file, workdir, updated_owners_mapping)
    except Error as e:
        print_err(f"Error: Dumping rules to '{codeowners_file!s}' failed: {e!s}")
        return 1

    return 0
