"""SHA-256 hash computation for skill files."""

import hashlib
import os
from pathlib import Path

from lib.collector import SKIP_DIRS


def hash_file(file_path: str, max_size: int = 50 * 1024 * 1024) -> str:
    """Compute SHA-256 hash of a single file.

    Skips symlinks and files larger than max_size (default 50MB).
    """
    if os.path.islink(file_path):
        return None
    try:
        if os.path.getsize(file_path) > max_size:
            return None
    except OSError:
        return None
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None


def hash_directory(directory: str, skip_dirs: set = None) -> dict:
    """Compute SHA-256 hashes for all files in a directory.

    Returns dict mapping relative file paths (forward slashes) to their hashes.
    """
    if skip_dirs is None:
        skip_dirs = SKIP_DIRS

    hashes = {}
    root = Path(directory)

    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in sorted(filenames):
            filepath = Path(dirpath) / filename
            if filepath.is_symlink():
                continue
            try:
                # Normalize to forward slashes for cross-platform determinism
                rel_path = str(filepath.relative_to(root)).replace(os.sep, "/")
                file_hash = hash_file(str(filepath))
                if file_hash is not None:
                    hashes[rel_path] = file_hash
            except (PermissionError, OSError):
                continue

    return hashes


def composite_hash(file_hashes: dict) -> str:
    """Compute a single composite hash from all file hashes.

    Sorts files alphabetically, concatenates 'path:hash' strings,
    then hashes the result. Deterministic and content-addressable.
    Returns "empty" if no files were hashed (avoids all empty skills
    sharing the same sha256-of-empty-string on the backend).
    """
    if not file_hashes:
        return "empty"
    sha256 = hashlib.sha256()
    for path in sorted(file_hashes.keys()):
        entry = f"{path}:{file_hashes[path]}\n"
        sha256.update(entry.encode("utf-8"))
    return sha256.hexdigest()


def skvil_kedavra_self_hash(base_dir: str) -> str:
    """Return the composite_hash of the running skvil-kedavra installation.

    Included in every output so the agent can detect scanner replacement:
    compare this value against the trusted hash from a prior run.
    A mismatch means skvil-kedavra was modified or replaced.
    """
    try:
        fh = hash_directory(base_dir)
        return f"sha256:{composite_hash(fh)}"
    except Exception:
        return "unavailable"
