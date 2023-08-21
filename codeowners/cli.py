import argparse
import sys
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import Dict, List

from codeowners.exceptions import DumpError, EmailError, ParseError, UpdateError
from codeowners.utils import (
    dump_codeowners,
    get_git_email,
    load_user_id_map,
    parse_codeowners,
    update_owners_mapping,
)


def cli(argv: List[str] = sys.argv[1:]) -> int:
    parser = argparse.ArgumentParser(
        description="Generate CODEOWNERS file from git repo."
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
        "-m", "--user-map", type=Path, required=False, help="path to user map"
    )
    parser.add_argument(
        "files",
        type=Path,
        nargs="+",
        help="files to update the ownership",
    )

    args = parser.parse_args()
    codeowners_file: Path = args.out
    files: List[Path] = args.files
    threshold: float = args.threshold
    user_id_map: Dict[str, str] = dict()

    try:
        if args.user_map:
            user_id_map = load_user_id_map(args.user_map)
        else:
            print(
                "Warning: User map not provided. All owners will appear as commiter email.",
                file=sys.stderr,
            )
    except JSONDecodeError as e:
        print(
            f"Error: Decoding user map '{str(args.user_map)}' failed: {str(e)}",
            file=sys.stderr,
        )
        return 1

    try:
        owners_mapping = parse_codeowners(codeowners_file)
    except ParseError as e:
        print(
            f"Error: Parsing '{str(codeowners_file)}' failed: {str(e)}", file=sys.stderr
        )
        return 1

    try:
        default_email = get_git_email()
    except EmailError as e:
        print(f"Error: Receiving email from git failed: {str(e)}", file=sys.stderr)
        return 1

    try:
        updated_owners_mapping = update_owners_mapping(
            owners_mapping,
            files,
            default_email,
            threshold,
            str(codeowners_file),
            user_id_map,
        )
    except UpdateError as e:
        print(f"Error: Updating owners table failed: {str(e)}", file=sys.stderr)
        return 1

    try:
        dump_codeowners(codeowners_file, updated_owners_mapping)
    except DumpError as e:
        print(
            f"Error: Dumping rules to '{str(codeowners_file)}' failed: {str(e)}",
            file=sys.stderr,
        )
        return 1

    return 0
