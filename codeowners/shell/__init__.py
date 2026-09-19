"""Imperative shell: everything that touches git, the filesystem or the clock.

Each function here does one effect and hands the bytes or lines it got to
`codeowners.core`, which holds the parsing, the arithmetic and the formatting.
Nothing in this package is imported by the core, and the `lint-imports`
contracts in `pyproject.toml` keep it that way.
"""
