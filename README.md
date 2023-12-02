codeowners-generator
================
Automatically generate and update COEOWNERS file from git blame data.

### Using gitlab-ci-tools with pre-commit
Add this to your `.pre-commit-config.yaml`

```yaml
- repo: https://github.com/c0m1c5an5/codeowners-pre-commit.git
  rev: 1.0.0
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

# Issues and proposals
Feel free to create an issue, report a bug or suggest improvements in the "Issues" section.
