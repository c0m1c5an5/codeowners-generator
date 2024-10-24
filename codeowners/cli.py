# ruff: noqa: C901, PLR0911, PLR0912, PLR0915
# C901 function is too complex
# PLR0911 Too many return statements
# PLR0912 Too many branches
# PLR0915 Too many statements

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Set

from codeowners.utils import (
    dump_codeowners,
    get_git_email,
    get_git_root,
    get_git_staged_files,
    parse_codeowners,
    update_owners_mapping,
    validate_user_map,
)

logging.basicConfig(format="%(levelname)s: %(filename)s:%(lineno)d %(message)s")
logger = logging.getLogger(__name__)


def cli(argv: List[str] = sys.argv[1:]) -> int:
    """Codeowners cli.

    Args:
        argv (List[str], optional): Input arguments. Defaults to sys.argv[1:].

    Returns:
        int: Return code.
    """
    parser = argparse.ArgumentParser(
        prog="codeowners", description="Generate CODEOWNERS file from git repo."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="verbose output"
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
        "-a",
        "--admin",
        action="append",
        type=str,
        default=[],
        help="ids of admin uses (added as codeowner to every file)",
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
    admins: Set[str] = set(args.admin)
    files: Set[Path] = set(args.files)
    user_id_map: Dict[str, str] = {}
    verbose: bool = args.verbose

    if verbose or os.environ.get("DEBUG") not in [None, "false", "no", "0"]:
        logger.setLevel(logging.DEBUG)

    logger.debug(f"Args: {args._get_kwargs()}")

    try:
        git_root = get_git_root()
    except Exception as e:
        logger.error(f"Unable to get git root: {e!s}", exc_info=verbose)
        return 1

    logger.debug(f"Git root: {git_root}")

    os.chdir(git_root)

    try:
        default_email = get_git_email()
    except Exception as e:
        logger.error(f"Unable to get email form git: {e!s}", exc_info=verbose)
        return 1

    logger.debug(f"Default email: {default_email}")

    try:
        staged_files = get_git_staged_files()
        staged_files.discard(codeowners_file)
    except Exception as e:
        logger.error(f"Unable to staged files form git: {e!s}", exc_info=verbose)
        return 1

    logger.debug(f"Staged files: {staged_files}")

    if user_map_file:
        try:
            with user_map_file.open("r") as user_map_stream:
                try:
                    user_id_map = json.load(user_map_stream)
                except Exception as e:
                    logger.error(
                        f"Failed load json file '{user_map_file!s}': {e!s}",
                        exc_info=verbose,
                    )
                    return 1
        except OSError as e:
            logger.error(
                f"Failed to access '{user_map_file!s}': {e.strerror}", exc_info=verbose
            )
            return 1
        except Exception as e:
            logger.error(
                f"Failed to access '{user_map_file!s}': {e!s}", exc_info=verbose
            )
            return 1

        logger.debug(f"User map: {user_id_map}")

        try:
            validate_user_map(user_id_map)
        except Exception as e:
            logger.error(
                f"Invalid user map '{user_map_file!s}': {e!s}", exc_info=verbose
            )
            return 1
    else:
        logger.warn("User map not provided. All owners will appear as committer email.")

    owners_mapping: Dict[Path, Set[str]] = {}
    conflict_files: Set[Path] = set()

    if codeowners_file.is_file():
        try:
            with codeowners_file.open("r") as codeowners_in_stream:
                (owners_mapping, conflict_files) = parse_codeowners(
                    codeowners_in_stream
                )
        except OSError as e:
            logger.error(
                f"Parsing '{codeowners_file!s}' failed {e.strerror}", exc_info=verbose
            )
            return 1
        except Exception as e:
            logger.error(
                f"Parsing '{codeowners_file!s}' failed {e!s}", exc_info=verbose
            )
            return 1

    logger.debug(f"Owners mapping: {owners_mapping!s}")
    logger.debug(f"Conflict files: {conflict_files!s}")

    filtered_owners_mapping = { k: v for k, v in owners_mapping.items() if k in staged_files }
    logger.debug(f"Filtered owners mapping: {filtered_owners_mapping!s}")

    filtered_files = set(f for f in files.union(conflict_files) if f in staged_files)
    logger.debug(f"Filtered files: {filtered_files!s}")

    try:
        updated_owners_mapping = update_owners_mapping(
            filtered_owners_mapping,
            filtered_files,
            codeowners_file,
            default_email,
            threshold,
            user_id_map,
        )
    except Exception as e:
        logger.error(f"Updating owners table failed: {e!s}", exc_info=verbose)
        return 1

    logger.debug(f"Updated owners mapping: {updated_owners_mapping!s}")

    if admins:
        updated_owners_mapping = { k: v.union(admins) for k, v in updated_owners_mapping.items() }
        logger.debug(f"Updated owners mapping with admins: {updated_owners_mapping!s}")

    try:
        with codeowners_file.open("w") as codeowners_out_stream:
            dump_codeowners(codeowners_out_stream, updated_owners_mapping)
    except OSError as e:
        logger.error(
            f"Dumping rules to '{codeowners_file!s}' failed: {e.strerror}",
            exc_info=verbose,
        )
        return 1
    except Exception as e:
        logger.error(
            f"Dumping rules to '{codeowners_file!s}' failed: {e!s}", exc_info=verbose
        )
        return 1
    else:
        logger.debug(f"Dumping rules to '{codeowners_file!s}' succeeded")

    return 0
