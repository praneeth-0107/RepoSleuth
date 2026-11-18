"""Temporary, safe project loaders for ZIP archives and public GitHub URLs."""

from __future__ import annotations

import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from typing import Iterator

from .scanner import MANIFEST_NAMES, MAX_FILE_BYTES, MAX_FILES, MAX_MANIFEST_BYTES, SKIP_DIRS, TEXT_SUFFIXES


def _is_scannable(path: PurePosixPath) -> bool:
    return not any(part in SKIP_DIRS for part in path.parts) and (path.suffix.lower() in TEXT_SUFFIXES or path.name == "Dockerfile" or path.name.lower() in MANIFEST_NAMES)


@contextmanager
def load_project(source: str) -> Iterator[tuple[Path, str]]:
    """Yield (project directory, display name), cleaning temporary loads afterward."""
    if source.startswith(("https://", "http://")):
        parsed = urlsplit(source)
        if parsed.scheme != "https" or parsed.hostname != "github.com" or not parsed.path.strip("/"):
            raise ValueError("Git clone input must be an HTTPS URL for github.com.")
        label = f"https://github.com/{parsed.path.strip('/').removesuffix('.git')}"
        temp = tempfile.TemporaryDirectory(prefix="reposleuth-git-")
        target = Path(temp.name) / "repository"
        try:
            try:
                result = subprocess.run(["git", "clone", "--depth", "1", "--", source, str(target)], capture_output=True, text=True, timeout=600, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ValueError(f"Could not clone repository: {exc}") from exc
            if result.returncode:
                raise ValueError("Git clone failed. Check that Git is installed and the repository is publicly accessible.")
            yield target, label
        finally:
            temp.cleanup()
        return

    path = Path(source).expanduser().resolve()
    if path.is_dir():
        yield path, str(path)
        return
    if not path.is_file() or path.suffix.lower() != ".zip":
        raise ValueError("Input must be a project folder, a .zip archive, or an HTTPS GitHub URL.")

    temp = tempfile.TemporaryDirectory(prefix="reposleuth-zip-")
    root = Path(temp.name)
    try:
        file_count = 0
        total_size = 0
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                rel = PurePosixPath(info.filename)
                if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts) or not _is_scannable(rel):
                    continue
                file_count += 1
                if file_count > MAX_FILES:
                    raise ValueError("The ZIP contains more than 20,000 scannable files.")
                max_size = MAX_MANIFEST_BYTES if rel.name.lower() in MANIFEST_NAMES else MAX_FILE_BYTES
                if info.file_size > max_size:
                    continue
                total_size += info.file_size
                if total_size > 200 * 1024 * 1024 * 1024:
                    raise ValueError("Expanded source files exceed the 200 GB project limit.")
                target = root.joinpath(*rel.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source_file, target.open("wb") as output:
                    output.write(source_file.read(MAX_FILE_BYTES + 1))
        yield root, path.stem
    except zipfile.BadZipFile as exc:
        raise ValueError("The selected ZIP archive is invalid or corrupted.") from exc
    finally:
        temp.cleanup()
