#!/usr/bin/env python3
"""
scan_secrets.py -- independent check that no secrets are left in the repo.
Uses different, deliberately broader heuristics than sanitize.py. Prints
file:line and the rule that fired, NEVER the matched value. Exit 1 if any hit.

Usage:  python3 tools/scan_secrets.py [--staged]
"""
import math
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKIP_DIRS = {".git"}
SKIP_FILES = {"sanitize.py", "scan_secrets.py"}

SPECIFIC = [
    ("anthropic-key", re.compile(r"sk-ant-(?!.*REDACTED)[A-Za-z0-9_\-]{10,}")),
    ("ghost-admin-key", re.compile(r"\b[0-9a-f]{24}:[0-9a-f]{40,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("url-credentials", re.compile(r"://[^/\s:@]+:(?!REDACTED)[^/\s@]{4,}@")),
    ("long-hex", re.compile(r"\b[0-9a-f]{40,}\b")),
    ("assign-secret",
     re.compile(r"(?i)(password|passwd|secret|token|api_?key)\w*\s*[=:]\s*[\"'](?!REDACTED)[^\"'\s]{8,}[\"']")),
]
QUOTED = re.compile(r"[\"']([A-Za-z0-9+/_\-=.]{28,})[\"']")
SAFE_HINTS = ("http", "www.", "/opt/", "/var/", "/etc/", "REDACTED", ".py", ".sh", ".json", ".hbs",
              ".html", ".xml", ".txt", ".log", ".db", ".conf", "claude-", "gpt-", "sha", "utf-8")


def entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def files(staged):
    if staged:
        out = subprocess.run(["git", "-C", REPO, "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                             capture_output=True, text=True).stdout.split()
        for f in out:
            yield os.path.join(REPO, f)
        return
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def main():
    staged = "--staged" in sys.argv
    hits = []
    for p in files(staged):
        if os.path.basename(p) in SKIP_FILES:
            continue
        try:
            with open(p, encoding="utf-8") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = os.path.relpath(p, REPO)
        for i, line in enumerate(lines, 1):
            if '"digest"' in line:   # Proxmox config checksums, not secrets
                continue
            for name, rx in SPECIFIC:
                if rx.search(line):
                    hits.append((rel, i, name))
            for m in QUOTED.finditer(line):
                s = m.group(1)
                if any(h in s for h in SAFE_HINTS) or s.count("/") > 2 or s.startswith("/"):
                    continue
                if len(set(s)) > 14 and entropy(s) > 4.2 and re.search(r"\d", s) and re.search(r"[A-Za-z]", s):
                    hits.append((rel, i, "high-entropy-string"))
    if hits:
        print(f"POSSIBLE SECRETS: {len(hits)} hit(s) (values not shown):")
        for rel, i, name in sorted(set(hits)):
            print(f"  {rel}:{i}  [{name}]")
        sys.exit(1)
    print("CLEAN: no secret-shaped strings found.")


if __name__ == "__main__":
    main()
