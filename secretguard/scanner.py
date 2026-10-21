"""Local-only, bounded secret scanning. No networking and no token validation."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__", ".pytest_cache", "dist", "build", "coverage", ".next"}
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so", ".dylib", ".mp4", ".mp3", ".ico", ".woff", ".woff2", ".sqlite", ".db"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    expression: re.Pattern[str]
    recommendation: str
    group: int = 0

RULES = [
    Rule("github-token", "Possible GitHub personal access token", "high", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), "Revoke/rotate the token and move it to an environment secret."),
    Rule("github-fine-grained", "Possible GitHub fine-grained token", "high", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "Revoke/rotate the token and store it in a secret manager."),
    Rule("gitlab-token", "Possible GitLab personal access token", "high", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "Rotate the token and remove it from the source."),
    Rule("slack-token", "Possible Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"), "Rotate the token in Slack and restrict its scopes."),
    Rule("stripe-live", "Possible Stripe live secret key", "critical", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), "Immediately rotate the live Stripe secret and review access logs."),
    Rule("stripe-test", "Possible Stripe test secret key", "medium", re.compile(r"\bsk_test_[A-Za-z0-9]{16,}\b"), "Keep test secrets out of source control as well."),
    Rule("aws-access-id", "Possible AWS access key ID (not a secret by itself)", "medium", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "Review whether the matching AWS secret key was also exposed; rotate if necessary."),
    Rule("private-key", "PEM private key header", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), "Replace the private key and check the repository history."),
    Rule("generic-assignment", "Hardcoded credential-like assignment", "medium", re.compile(r"(?i)\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|db[_-]?password|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{16,})"), "Use environment variables or a secret manager, not hardcoded credentials.", 1),
]

PLACEHOLDERS = ("example", "placeholder", "your_", "your-", "replace", "changeme", "not_a_real", "fake", "sample", "dummy", "process.env", "os.getenv", "os.environ", "xxxxxxxx", "000000")

@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    file: str
    line: int
    fingerprint: str
    recommendation: str

    def as_dict(self) -> dict:
        return asdict(self)


def _valid_generic(value: str) -> bool:
    lower = value.lower()
    if any(p in lower for p in PLACEHOLDERS):
        return False
    if len(set(value)) < 5:
        return False
    # Avoid reporting obvious code property references as credentials.
    if lower.startswith(("getenv", "get_secret", "env.", "settings.", "config.")):
        return False
    return True


def _files(root: Path) -> Iterator[Path]:
    if root.is_file():
        if not root.is_symlink():
            yield root
        return
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(base) / d).is_symlink())
        for name in sorted(files):
            path = Path(base) / name
            if not path.is_symlink() and path.suffix.lower() not in SKIP_EXTENSIONS:
                yield path


def scan(root: str | Path, max_files: int = 5000, max_bytes: int = 1_000_000) -> dict:
    root = Path(root).expanduser().resolve(strict=True)
    if not (root.is_dir() or root.is_file()):
        raise ValueError("Scan target must be a file or directory")
    if max_files < 1 or max_bytes < 1:
        raise ValueError("Scan limits must be positive")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    findings: list[Finding] = []
    warnings: list[str] = []
    scanned = 0
    visited = 0
    incomplete = False
    for path in _files(root):
        visited += 1
        if scanned >= max_files:
            warnings.append(f"File limit ({max_files}) reached; coverage incomplete")
            incomplete = True
            break
        relative = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            size = path.stat().st_size
            if size > max_bytes:
                warnings.append(f"Skipped oversized file: {relative}")
                incomplete = True
                continue
            data = path.read_bytes()
            if b"\x00" in data[:4096]:
                # Binary files are intentionally out of scope for this MVP.
                continue
            content = data.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            warnings.append(f"Could not scan {relative}: {type(exc).__name__}")
            incomplete = True
            continue
        scanned += 1
        for line_no, line in enumerate(content.splitlines(), start=1):
            if len(line) > 120_000:
                warnings.append(f"Skipped very long line: {relative}:{line_no}")
                incomplete = True
                continue
            spans: set[tuple[str, int, int]] = set()
            for rule in RULES:
                for match in rule.expression.finditer(line):
                    value = match.group(rule.group)
                    if rule.id == "generic-assignment" and not _valid_generic(value):
                        continue
                    loc = (rule.id, match.start(), match.end())
                    if loc in spans:
                        continue
                    spans.add(loc)
                    # Fingerprint is one-way and truncated; the actual value is never stored in the report.
                    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
                    findings.append(Finding(rule.id, rule.description, rule.severity, relative, line_no, fingerprint, rule.recommendation))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.rule_id))
    levels = {k: sum(f.severity == k for f in findings) for k in SEVERITY_ORDER}
    verdict = "INCOMPLETE" if incomplete else "ACTION REQUIRED" if findings else "NO MATCHES"
    return {"tool": "REQUIEM SecretGuard", "version": "0.3.0", "target": str(root), "scanned_at": started, "files_scanned": scanned, "files_considered": visited, "findings_count": len(findings), "severity_counts": levels, "incomplete": incomplete, "warnings": warnings, "verdict": verdict, "findings": [f.as_dict() for f in findings], "scope": "Local text files only. Pattern matches are leads, not verified exposures. Hidden/ignored directories, binary files and archives are out of scope."}


# The browser UI uses the *same* rules as the CLI scanner. File contents are
# supplied in memory by a folder picker; no files need to be stored server-side.
def scan_documents(documents: list[dict], *, target: str = "Browser-selected folder",
                   max_files: int = 1000, max_bytes: int = 1_000_000) -> dict:
    """Scan in-memory UTF-8 documents selected by the local browser UI.

    Never returns matched secret values; filenames are relative and validated.
    """
    if not isinstance(documents, list) or max_files < 1 or max_bytes < 1:
        raise ValueError("Invalid scan input")
    if len(documents) > max_files:
        raise ValueError(f"Too many files selected (limit: {max_files})")
    if not isinstance(target, str) or len(target) > 256:
        raise ValueError("Invalid scan target label")
    findings: list[Finding] = []
    warnings: list[str] = []
    scanned = 0
    incomplete = False
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError("Invalid file entry")
        name = document.get("path")
        if not isinstance(name, str) or len(name) > 1024 or not name:
            raise ValueError("Invalid file path")
        # Browser file paths are relative. Reject traversal, drive letters,
        # weird line controls, and absolute paths, even though nothing is written.
        name = name.replace("\\", "/")
        components = name.split("/")
        if (name.startswith("/") or any(c in ("", ".", "..") for c in components)
                or ":" in components[0] or any(ord(c) < 32 for c in name)):
            raise ValueError("Invalid relative file path")
        if any(c in SKIP_DIRS for c in components[:-1]) or Path(name).suffix.lower() in SKIP_EXTENSIONS:
            continue
        content = document.get("content")
        skipped_size = document.get("oversized", False)
        if skipped_size is True:
            incomplete = True
            warnings.append(f"Skipped oversized file: {name}")
            continue
        if not isinstance(content, str):
            raise ValueError("File contents must be UTF-8 text")
        if len(content.encode("utf-8")) > max_bytes:
            incomplete = True
            warnings.append(f"Skipped oversized file: {name}")
            continue
        if "\x00" in content[:4096]:
            continue
        scanned += 1
        for line_no, line in enumerate(content.splitlines(), start=1):
            if len(line) > 120_000:
                incomplete = True
                warnings.append(f"Skipped very long line: {name}:{line_no}")
                continue
            spans: set[tuple[str, int, int]] = set()
            for rule in RULES:
                for match in rule.expression.finditer(line):
                    value = match.group(rule.group)
                    if rule.id == "generic-assignment" and not _valid_generic(value):
                        continue
                    loc = (rule.id, match.start(), match.end())
                    if loc in spans:
                        continue
                    spans.add(loc)
                    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
                    findings.append(Finding(rule.id, rule.description, rule.severity, name, line_no,
                                            fingerprint, rule.recommendation))
                    if len(findings) >= 1000:
                        incomplete = True
                        warnings.append("Finding limit (1000) reached; coverage incomplete")
                        break
                if len(findings) >= 1000:
                    break
            if len(findings) >= 1000:
                break
        if len(findings) >= 1000:
            break
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.rule_id))
    levels = {k: sum(f.severity == k for f in findings) for k in SEVERITY_ORDER}
    verdict = "INCOMPLETE" if incomplete else "ACTION REQUIRED" if findings else "NO MATCHES"
    return {"tool": "REQUIEM SecretGuard", "version": "0.3.0", "target": target,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files_scanned": scanned, "files_considered": len(documents),
            "findings_count": len(findings), "severity_counts": levels, "incomplete": incomplete,
            "warnings": warnings[:100], "verdict": verdict,
            "findings": [f.as_dict() for f in findings],
            "scope": "Browser-selected local text files only; skipped build/vendor directories and binaries. Pattern matches are not verified exposures."}
