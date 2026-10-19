#!/usr/bin/env python3
"""
sanitize.py -- strip secrets out of text files in this repo, in place.

Use it before committing files copied from a server that may contain
hard-coded keys or passwords: every value matching a rule below is replaced
with a REDACTED_* placeholder. Only files in this repo are changed.

Usage:  python3 tools/sanitize.py [path ...]     (default: whole repo)
Then:   python3 tools/scan_secrets.py            (must print CLEAN before committing)
"""
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKIP_DIRS = {".git", "tools"}
TEXT_EXT = {".py", ".sh", ".conf", ".yml", ".yaml", ".json", ".hbs", ".md", ".txt", ".cfg",
            ".ini", ".env", ".service", ".crontab", ".html", ".js", ".toml", ".xml", ""}

RULES = [
    # (name, compiled regex, replacement)
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"), "REDACTED_ANTHROPIC_API_KEY"),
    ("ghost_admin_key", re.compile(r"\b[0-9a-f]{24}:[0-9a-f]{64}\b"), "REDACTED_GHOST_ADMIN_KEY"),
    ("ghost_content_key", re.compile(r"(?i)(key=)[0-9a-f]{26}\b"), r"\1REDACTED_GHOST_CONTENT_KEY"),
    ("listmonk_api_token", re.compile(r"\bapi:[A-Za-z0-9]{16,}"), "api:REDACTED"),
    ("bearer", re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.=]{20,}"), r"\1REDACTED"),
    ("assignment",
     re.compile(r"(?i)\b((?:[A-Za-z0-9_]*)(?:password|passwd|secret|token|api_?key|apikey|pass)[A-Za-z0-9_]*"
                r"\s*[=:]\s*)([\"'])([^\"'\n]{6,})\2"),
     lambda m: f"{m.group(1)}{m.group(2)}REDACTED{m.group(2)}"),
    ("yaml_env_unquoted",
     re.compile(r"(?im)^(\s*-?\s*[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api_?key|adminpass|private_?key)[A-Za-z0-9_.\-]*\s*[:=]\s*(?:&[A-Za-z0-9_-]+\s+)?)(?![\"'$*]|REDACTED|CHANGE_ME)([^\s#]{3,})"),
     r"\1REDACTED"),
    ("json_secret_pair",
     re.compile(r"(?i)(\"[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api_?key|private_?key|credential)[A-Za-z0-9_.\-]*\"\s*:\s*)\"(?!REDACTED)([^\"]{4,})\""),
     r'\1"REDACTED"'),
    ("env_export",
     re.compile(r"(?m)^(\s*export\s+[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*=)([\"']?)[^\"'\s]{8,}\2"),
     lambda m: f"{m.group(1)}{m.group(2)}REDACTED{m.group(2)}"),
    ("inline_env",
     re.compile(r"\b((?:GHOST_ADMIN_KEY|ANTHROPIC_API_KEY|[A-Z_]*TOKEN|[A-Z_]*SECRET|[A-Z_]*PASSWORD)=)[^\s\"']{8,}"),
     r"\1REDACTED"),
]


def is_text_path(path):
    return os.path.splitext(path)[1].lower() in TEXT_EXT


def sanitize_text(text):
    counts = {}
    for name, rx, repl in RULES:
        text, n = rx.subn(repl, text)
        if n:
            counts[name] = counts.get(name, 0) + n
    return text, counts


def main(paths):
    roots = paths or [REPO]
    total_files = total_subs = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if not is_text_path(p):
                    continue
                try:
                    with open(p, encoding="utf-8") as f:
                        text = f.read()
                except (UnicodeDecodeError, OSError):
                    continue
                new, counts = sanitize_text(text)
                if counts:
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(new)
                    total_files += 1
                    total_subs += sum(counts.values())
                    print(f"  sanitized {os.path.relpath(p, REPO)}: {counts}")
    print(f"\n{total_subs} secret value(s) redacted across {total_files} file(s).")


if __name__ == "__main__":
    main(sys.argv[1:])
