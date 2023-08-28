import sys

from codeowners.cli import cli


def main() -> None:  # noqa: D103
    sys.exit(cli())


if __name__ == "__main__":
    main()
