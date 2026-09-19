"""Functional core: pure functions over values, no I/O and no globals.

Every module here takes what it needs as an argument and returns a value.
Reading a file, running git and writing the result out all live in
`codeowners.shell`, which is what makes this half straightforward to test and
reason about: the same input always gives the same answer.

The boundary is enforced by the `lint-imports` contracts in `pyproject.toml`.
"""
