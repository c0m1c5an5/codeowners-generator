import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Set

from codeowners.utils import (
    OwnerRules,
    dump_codeowners,
    generate_owners_mapping,
    get_cpu_count,
    get_git_email,
    get_git_files,
    get_git_root,
    parse_codeowners,
    render_codeowners,
    validate_user_map,
)

logging.basicConfig(format="%(levelname)s: %(filename)s:%(lineno)d %(message)s")
logger = logging.getLogger(__name__)
VERBOSITY = (logging.WARNING, logging.INFO, logging.DEBUG)
PRESERVE_VARIABLE = "CODEOWNERS_PRESERVE"
PRESERVE_ON = frozenset({"1", "yes", "true", "True"})


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser.

    Returns:
        argparse.ArgumentParser: Parser for the command line.
    """
    parser = argparse.ArgumentParser(
        prog="codeowners", description="Generate CODEOWNERS file from git repo."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase verbosity (repeatable)",
    )
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path("./CODEOWNERS"),
        help="path to codeowners file",
    )
    parser.add_argument(
        "-p",
        "--preserve",
        action="store_true",
        default=os.environ.get(PRESERVE_VARIABLE) in PRESERVE_ON,
        help=(
            f"leave the codeowners file untouched when equivalent (env:{PRESERVE_VARIABLE})"
        ),
    )
    parser.add_argument(
        "-r",
        "--relevance",
        type=float,
        default=65.0,
        help="percent of the largest contribution an owner must reach",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=get_cpu_count(),
        help="number of blames to run concurrently",
    )
    parser.add_argument(
        "-m",
        "--user-map",
        type=Path,
        required=False,
        help="path to user map",
    )
    parser.add_argument(
        "-a",
        "--admin",
        action="append",
        type=str,
        default=[],
        help="ids of admin uses (added as codeowner to every file)",
    )
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="paths to files, defaults to every tracked file",
    )

    return parser


def equivalent_codeowners(
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
        return parse_codeowners(codeowners_in_stream) == render_codeowners(
            owners_mapping
        )


def load_user_map(user_map_file: Path) -> Dict[str, str]:
    """Read and validate a committer email to user id map.

    Args:
        user_map_file (Path): File to read.

    Returns:
        Dict[str, str]: Mapping of committer emails to user ids.
    """
    with user_map_file.open("r") as user_map_stream:
        user_id_map: Dict[str, str] = json.load(user_map_stream)

    validate_user_map(user_id_map)

    return user_id_map


def write_codeowners(
    codeowners_file: Path,
    owners_mapping: Dict[Path, Set[str]],
) -> None:
    """Write the owners mapping out as a codeowners file.

    Args:
        codeowners_file (Path): File to write.
        owners_mapping (Dict[Path, Set[str]]): Map of files to owners.
    """
    with codeowners_file.open("w") as codeowners_out_stream:
        dump_codeowners(codeowners_out_stream, owners_mapping)


def cli(argv: List[str] = sys.argv[1:]) -> int:
    """Codeowners cli.

    Args:
        argv (List[str], optional): Input arguments. Defaults to sys.argv[1:].

    Returns:
        int: Return code.

    Raises:
        Exception: Whatever git, json or the filesystem raised. Letting it
            reach the caller keeps the traceback, which says more about a
            failed run than a re-worded message would.
    """
    args = build_parser().parse_args(argv)
    codeowners_file: Path = args.out
    admins: Set[str] = set(args.admin)
    user_id_map: Dict[str, str] = {}

    logger.setLevel(VERBOSITY[min(args.verbose, len(VERBOSITY) - 1)])
    logger.debug("Args: %s", args._get_kwargs())

    os.chdir(get_git_root())

    if args.user_map:
        user_id_map = load_user_map(args.user_map)
    else:
        logger.warning(
            "User map not provided. All owners will appear as committer email."
        )

    owners_mapping = generate_owners_mapping(
        set(args.files) or get_git_files(),
        codeowners_file,
        get_git_email(),
        OwnerRules(args.relevance, user_id_map),
        args.jobs,
    )

    if admins:
        owners_mapping = {
            file: owners | admins for file, owners in owners_mapping.items()
        }

    if args.preserve and equivalent_codeowners(codeowners_file, owners_mapping):
        logger.info("Left '%s' as it already states these owners", codeowners_file)
        return 0

    write_codeowners(codeowners_file, owners_mapping)
    logger.info("Wrote %s rules to '%s'", len(owners_mapping), codeowners_file)

    return 0
