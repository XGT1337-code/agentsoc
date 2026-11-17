"""Create a complete, restorable backup of AgentSOC.

Captures the full working tree (source, configs, sandbox base data, databases,
gateway keys) into a single timestamped zip under backups/, EXCLUDING heavy or
regenerable dirs (.venv, .git, __pycache__, previous backups). A MANIFEST.txt
records the git commit and what was included.

Run:  python -m tools.backup
"""
from __future__ import annotations

import datetime as _dt
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUP_DIR = ROOT / "backups"
EXCLUDE_DIRS = {".venv", ".git", "__pycache__", "backups", ".pytest_cache",
                ".mypy_cache", "node_modules", ".ruff_cache"}
EXCLUDE_SUFFIX = {".pyc", ".pyo"}


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                              text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _included(path: Path) -> bool:
    parts = set(path.relative_to(ROOT).parts)
    if parts & EXCLUDE_DIRS:
        return False
    if path.suffix in EXCLUDE_SUFFIX:
        return False
    return True


def create_backup() -> Path:
    BACKUP_DIR.mkdir(exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = BACKUP_DIR / f"agentsoc-backup-{ts}.zip"

    commit = _git("rev-parse", "HEAD")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    status = _git("status", "--porcelain")

    files = [p for p in ROOT.rglob("*") if p.is_file() and _included(p)]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = [
            f"AgentSOC backup {ts}",
            f"git_branch: {branch}",
            f"git_commit: {commit}",
            f"uncommitted_changes: {'yes' if status else 'no'}",
            f"file_count: {len(files)}",
            "",
            "Dirty files at backup time:" if status else "Working tree clean.",
            status,
        ]
        z.writestr("MANIFEST.txt", "\n".join(manifest))
        for p in files:
            z.write(p, p.relative_to(ROOT).as_posix())
    return out


def main() -> None:
    try:
        out = create_backup()
    except Exception as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    size_mb = out.stat().st_size / (1024 * 1024)
    print(f"backup created: {out}  ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
