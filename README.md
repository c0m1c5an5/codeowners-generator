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

### Static rules
Only the rules between the boundaries are rewritten, so anything written
outside them is kept from run to run:

```
# Kept, and matched first
*.lock @build-team

# -----BEGIN CODEOWNERS-----
src/main.py @alice
# -----END CODEOWNERS-----

# Kept, and wins over the generated rules above it
security/ @security
```

The last rule that matches a file is the one that applies, so a static rule
that has to override a generated one goes below the closing boundary. A file
without boundaries is rewritten whole, and written back with them.

# Issues and proposals
Feel free to create an issue, report a bug or suggest improvements in the "Issues" section.
