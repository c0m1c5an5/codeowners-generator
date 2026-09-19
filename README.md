codeowners-generator
================
Automatically generate and update COEOWNERS file from git blame data.

### Using gitlab-ci-tools with pre-commit
Add this to your `.pre-commit-config.yaml`

```yaml
- repo: https://github.com/c0m1c5an5/codeowners-pre-commit.git
  rev: 2.0.1
  hooks:
    - id: codeowners
```

### Hooks available

#### `codeowners`
Automatically generate and update COEOWNERS file from git blame data.
- Provide user map file with `-m` flag, otherwise users will be refferenced as thei email.
- Set treshold with `-t` flag. By default uset is considered an owner if they have created at least 25% of the lines.
- If you would like to set alternative CODEOWNERS file destination use `-o` flag.

Example user map file (compatible with .gitownrc):
```json
{
  "user@example.com": "@example",
  "admin@google.com": "@google"
}
```  

### Development
The package is split into a functional core and an imperative shell:

- `codeowners/core/` — pure functions over values: decoding git output, parsing
  blame, picking owners, rendering and parsing the CODEOWNERS format. No I/O, no
  globals, no clock, so the same input always gives the same answer.
- `codeowners/shell/` — everything with an effect: running git, reading file
  heads, writing the CODEOWNERS file and the thread pool that drives them. Each
  function does its effect and hands the bytes or lines it got to the core.
- `codeowners/cli.py` — argument parsing and the order the effects happen in.

The boundary is enforced rather than just documented. `lint-imports`
([import-linter](https://github.com/seddonym/import-linter)) builds the real
import graph and checks two contracts declared in `pyproject.toml`:

- **Functional core, imperative shell** — a layers contract: `cli` may import
  `shell`, `shell` may import `core`, and nothing points back up.
- **Core is pure** — a forbidden contract: nothing under `codeowners.core` may
  reach `subprocess`, `os`, `logging`, `time` and friends, whether directly or
  through something it imports.

Run it with `uv run lint-imports`, or let `pre-commit` run it.

# Issues and proposals
Feel free to create an issue, report a bug or suggest improvements in the "Issues" section.
