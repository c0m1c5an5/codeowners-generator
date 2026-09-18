import sys

from codeowners.cli import cli


def main() -> None:
    """Run the cli and exit with its return code."""
    sys.exit(cli())


if __name__ == "__main__":
    main()
