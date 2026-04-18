---
name: codebase-security-scan
description: "DevOps pre-merge security scan for Snowflake/SQL codebases. Scans for hardcoded secrets, PATs, passwords, and API keys (blocking) and outdated Snowflake Cortex AI model references in AI_COMPLETE, AI_CLASSIFY, AI_EXTRACT, etc. (warnings). Called via GitHub Actions on PR create and merge to main. Use when: setting up security scan, checking for leaked credentials, auditing Cortex AI model versions, CI/CD pre-merge checks, devops security gate."
---

# Codebase Security Scan

DevOps skill for scanning a codebase before merge. Designed to run as a GitHub Actions pre-check.

## What It Checks

| Category | Severity | Behavior |
|---|---|---|
| Hardcoded PATs, passwords, API keys, tokens | **ERROR** | Fails pipeline (exit 1) |
| AWS access keys, private key blocks | **ERROR** | Fails pipeline (exit 1) |
| Outdated Cortex AI model in AI_COMPLETE / AI_CLASSIFY / etc. | WARNING | Annotates PR, does not fail |

## Outdated Models Flagged

| Model | Replacement |
|---|---|
| `llama2-70b-chat` | `llama3.3-70b` or `llama3.1-70b` |
| `llama3-8b` | `llama3.1-8b` or `llama3.2-3b` |
| `llama3-70b` | `llama3.3-70b` or `llama3.1-70b` |
| `mistral-large` | `mistral-large2` |
| `gemma-7b` | `llama3.2-3b` or `mistral-7b` |
| `mixtral-8x7b` | `mistral-large2` |
| `claude-3-haiku` | `claude-3-5-haiku` |
| `claude-3-sonnet` | `claude-3-5-sonnet` |
| `claude-3-opus` | `claude-3-7-sonnet` |
| `jamba-instruct` | `jamba-1.5-mini` or `jamba-1.5-large` |

## Workflow

### Step 1: Add the workflow to the target repo

The scanner is a composite action hosted at
`sfc-gh-bleboeuf/cortex-skill-codebase-security-scan` — no files need
to be copied into the target repo. Just add the workflow:

```bash
SKILL_DIR="$HOME/.snowflake/cortex/skills/codebase-security-scan"
TARGET_REPO="/path/to/your/repo"

mkdir -p "$TARGET_REPO/.github/workflows"
cp "$SKILL_DIR/github/security-scan.yml" \
   "$TARGET_REPO/.github/workflows/security-scan.yml"
```

Commit it:
```bash
git add .github/workflows/security-scan.yml
git commit -m "ci: add codebase security and AI model scan"
```

The workflow uses `uses: sfc-gh-bleboeuf/cortex-skill-codebase-security-scan@main`
— GitHub fetches the action and runs `scan.py` from the action repo automatically.
Updates to the scanner propagate to all repos without any file changes.

**⚠️ STOP**: Confirm files are committed before proceeding.

---

### Step 2: Run the scanner locally

```bash
# Scan current directory, colored text output
python ~/.snowflake/cortex/skills/codebase-security-scan/scripts/scan.py .

# Scan a specific repo
python ~/.snowflake/cortex/skills/codebase-security-scan/scripts/scan.py /path/to/repo

# Simulate GitHub Actions output format
python ~/.snowflake/cortex/skills/codebase-security-scan/scripts/scan.py . --format github
```

Exit codes:
- `0` — clean (or warnings only)
- `1` — blocking errors found (hardcoded secrets)
- `2` — bad arguments / directory not found

---

### Step 3: Interpret results

**Blocking errors (pipeline fails):**
```
ERROR    src/config.py:42
         Hardcoded password
         DB_PASSWORD = "example_changeme_value"
```
Action: remove the secret, use environment variables or a secrets manager.

**Warnings (pipeline passes, PR annotated):**
```
WARNING  models/customer_summary.sql:17
         Outdated model "llama2-70b-chat": Use llama3.3-70b or llama3.1-70b
         SELECT AI_COMPLETE('llama2-70b-chat', prompt) ...
```
Action: update the model string to the recommended replacement.

---

### Step 4: Fix false positives

If a legitimate match is flagged incorrectly, add a suppression comment on the same line:

```python
# noscan
DB_PASSWORD = os.environ["DB_PASSWORD"]  # noscan - this reads from env, not hardcoded
```

Any line containing `# noscan` or `-- noscan` is skipped by the scanner.

> To add `noscan` support, edit `scan.py` and add this check before the secret loop:
> ```python
> if "noscan" in line.lower():
>     continue
> ```

---

## Tools

### Script: scan.py

**Description**: Standalone Python scanner (stdlib only, no dependencies).

**Usage:**
```bash
python <SKILL_DIR>/scripts/scan.py [directory] [--format text|github] [--no-color]
```

**Arguments:**
- `directory`: Path to scan (default: `.`)
- `--format text`: Human-readable colored output (default)
- `--format github`: GitHub Actions `::error` / `::warning` annotations
- `--no-color`: Disable ANSI color

---

## Stopping Points

- ✋ Step 1: Confirm scanner is committed to target repo
- ✋ Step 3: User reviews findings before pushing fixes

## Output

- Exit code `0` or `1` (used by GitHub Actions to pass/fail the pipeline)
- GitHub PR inline annotations for both errors and warnings
- Human-readable text output for local runs
