#!/usr/bin/env python3
"""
scan.py - Codebase security and AI model scanner

Scans for:
  1. Hardcoded secrets (PATs, passwords, API keys) - BLOCKING (exit 1)
  2. Outdated Snowflake Cortex AI model references - WARNING (exit 0)

Usage:
    python scan.py [directory] [--format text|github]

GitHub Actions annotation format uses ::error and ::warning markers
that render inline on PR diffs.
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Secret patterns — any match is a BLOCKING error
# Each tuple: (regex_pattern, human_description)
# ---------------------------------------------------------------------------
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub PAT (classic) — ghp_*"),
    (r"github_pat_[0-9a-zA-Z_]{82}", "GitHub fine-grained PAT — github_pat_*"),
    (r"ghs_[0-9a-zA-Z]{36}", "GitHub Actions token — ghs_*"),
    (r"ghr_[0-9a-zA-Z]{36}", "GitHub refresh token — ghr_*"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']", "Hardcoded password"),
    (r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*[\"'][^\"']{8,}[\"']", "Hardcoded API key"),
    (r"(?i)secret(?:[_\-]?key)?\s*[=:]\s*[\"'][^\"']{8,}[\"']", "Hardcoded secret"),
    (r"(?i)(?:auth[_\-]?token|access[_\-]?token|bearer[_\-]?token)\s*[=:]\s*[\"'][^\"']{8,}[\"']", "Hardcoded auth token"),
    (r"(?i)snowflake[^\n]*password\s*=\s*[\"'][^\"']{3,}[\"']", "Snowflake hardcoded password"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "Private key block"),
    # .env-style: TOKEN=abc123xyz (bare assignment, no quotes, long enough to be real)
    (r"(?i)^(?:export\s+)?(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|PAT)\s*=\s*(?!<|{{|\$|\*|example|changeme|your_)[^\s#]{12,}", ".env-style secret assignment"),
]

# Common placeholder values that indicate a non-secret (false positive suppression)
PLACEHOLDER_FRAGMENTS = [
    "<password>", "<token>", "<secret>", "<api_key>", "<pat>",
    "example", "placeholder", "your_password", "your_token", "your_secret",
    "changeme", "change_me", "xxxx", "****", "1234", "abcd",
    "my_password", "my_token", "my_key", "dummy", "fake",
    "test_token", "sample", "redacted", "${", "%(", "env(",
]

# ---------------------------------------------------------------------------
# Outdated Snowflake Cortex AI models — any match is a WARNING
# Key: exact model string as it would appear inside quotes in code/SQL
# Value: suggested replacement
# ---------------------------------------------------------------------------
OUTDATED_MODELS = {
    "llama2-70b-chat":      "Use llama3.3-70b or llama3.1-70b",
    "llama3-8b":            "Use llama3.1-8b or llama3.2-3b",
    "llama3-70b":           "Use llama3.3-70b or llama3.1-70b",
    "mistral-large":        "Use mistral-large2",
    "gemma-7b":             "Use llama3.2-3b or mistral-7b",
    "mixtral-8x7b":         "Use mistral-large2",
    "claude-3-haiku":       "Use claude-3-5-haiku",
    "claude-3-sonnet":      "Use claude-3-5-sonnet",
    "claude-3-opus":        "Use claude-3-7-sonnet or claude-3-5-sonnet",
    "reka-core-20240501":   "Use reka-core (latest)",
    "reka-flash-20240226":  "Use reka-flash (latest)",
    "jamba-instruct":       "Use jamba-1.5-mini or jamba-1.5-large",
}

# Snowflake Cortex AI functions that accept a model argument
AI_FUNCTIONS = [
    "AI_COMPLETE", "AI_CLASSIFY", "AI_EXTRACT", "AI_FILTER",
    "AI_SENTIMENT", "AI_SUMMARIZE", "AI_TRANSLATE", "AI_EMBED", "AI_AGG",
    # Legacy form
    r"SNOWFLAKE\.CORTEX\.COMPLETE",
]
AI_FUNC_PATTERN = re.compile(
    r"\b(?:" + "|".join(AI_FUNCTIONS) + r")\b",
    re.IGNORECASE,
)

# Directories and file extensions to skip entirely
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox",
    ".eggs", "htmlcov", "site-packages",
}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".lock", ".whl", ".pyc", ".pyo", ".so", ".dylib", ".dll",
    ".bin", ".exe", ".parquet", ".avro", ".orc",
}
# Files whose names suggest they are intentionally documenting patterns
SKIP_FILENAME_FRAGMENTS = [
    "test_scan", "scan_test", ".example", ".sample", ".template",
]


@dataclass
class Finding:
    file: str
    line: int
    content: str
    description: str
    severity: str  # "error" | "warning"


def _is_placeholder(line: str) -> bool:
    lower = line.lower()
    return any(p in lower for p in PLACEHOLDER_FRAGMENTS)


def _should_skip_file(path: Path) -> bool:
    name_lower = path.name.lower()
    if any(frag in name_lower for frag in SKIP_FILENAME_FRAGMENTS):
        return True
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    return False


def _should_skip_dir(dir_name: str) -> bool:
    return dir_name in SKIP_DIRS or dir_name.startswith(".")


def scan_file(path: Path, base_dir: Path) -> List[Finding]:
    findings: List[Finding] = []
    try:
        rel = str(path.relative_to(base_dir))
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.rstrip()
        stripped = line.lstrip()

        # Skip obvious comment lines (heuristic — not language-specific)
        if stripped.startswith(("#", "//", "--", "/*", "*", "<!--")):
            continue

        # Inline suppression: any line containing noscan is skipped
        if "noscan" in line.lower():
            continue

        # --- Secret scan (blocking) ---
        for pattern, description in SECRET_PATTERNS:
            if re.search(pattern, line):
                if _is_placeholder(line):
                    continue
                findings.append(Finding(
                    file=rel, line=lineno, content=line,
                    description=description, severity="error",
                ))
                break  # one error per line is enough

        # --- Outdated AI model scan (warning) ---
        if AI_FUNC_PATTERN.search(line):
            for model, suggestion in OUTDATED_MODELS.items():
                # Match model name only when surrounded by quotes (exact string)
                if re.search(r"""['"]""" + re.escape(model) + r"""['"]""", line, re.IGNORECASE):
                    findings.append(Finding(
                        file=rel, line=lineno, content=line,
                        description=f'Outdated model "{model}": {suggestion}',
                        severity="warning",
                    ))

    return findings


def collect_files(base_dir: Path):
    for path in sorted(base_dir.rglob("*")):
        if not path.is_file():
            continue
        # Skip unwanted directories (check every component relative to base)
        rel_parts = path.relative_to(base_dir).parts
        if any(_should_skip_dir(p) for p in rel_parts[:-1]):
            continue
        if _should_skip_file(path):
            continue
        yield path


def format_text(findings: List[Finding], use_color: bool) -> str:
    if not findings:
        return ""

    RED   = "\033[31m" if use_color else ""
    YELLOW = "\033[33m" if use_color else ""
    RESET = "\033[0m"  if use_color else ""
    BOLD  = "\033[1m"  if use_color else ""

    lines = []
    for f in findings:
        color = RED if f.severity == "error" else YELLOW
        tag   = "ERROR  " if f.severity == "error" else "WARNING"
        lines.append(
            f"{color}{BOLD}{tag}{RESET}  {f.file}:{f.line}\n"
            f"         {f.description}\n"
            f"         {f.content[:120]}\n"
        )
    return "\n".join(lines)


def format_github(findings: List[Finding]) -> str:
    lines = []
    for f in findings:
        level = "error" if f.severity == "error" else "warning"
        msg   = f.description.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        lines.append(f"::{level} file={f.file},line={f.line}::{msg}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a codebase for hardcoded secrets and outdated Cortex AI models."
    )
    parser.add_argument(
        "directory", nargs="?", default=".",
        help="Root directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--format", choices=["text", "github"], default="text",
        help="Output format: 'text' (default) or 'github' (Actions annotations)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color in text output",
    )
    args = parser.parse_args()

    base_dir = Path(args.directory).resolve()
    if not base_dir.is_dir():
        print(f"ERROR: '{base_dir}' is not a directory.", file=sys.stderr)
        return 2

    all_findings: List[Finding] = []
    files_scanned = 0

    for path in collect_files(base_dir):
        files_scanned += 1
        all_findings.extend(scan_file(path, base_dir))

    errors   = [f for f in all_findings if f.severity == "error"]
    warnings = [f for f in all_findings if f.severity == "warning"]

    use_color = not args.no_color and args.format == "text" and sys.stdout.isatty()

    if args.format == "github":
        output = format_github(all_findings)
    else:
        output = format_text(all_findings, use_color)

    if output:
        print(output)

    # Summary line
    GREEN = "\033[32m" if use_color else ""
    RED   = "\033[31m" if use_color else ""
    RESET = "\033[0m"  if use_color else ""

    status_color = RED if errors else GREEN
    print(
        f"{status_color}Scanned {files_scanned} file(s) — "
        f"{len(errors)} blocking error(s), {len(warnings)} warning(s).{RESET}"
    )

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
