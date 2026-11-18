"""Small dependency-free local web interface."""

from __future__ import annotations

import json
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, unquote, urlparse

from .scanner import MANIFEST_NAMES, MAX_MANIFEST_BYTES, scan, to_json, to_markdown

UPLOADS: dict[str, dict] = {}
UPLOADS_LOCK = threading.Lock()
MAX_UPLOAD_BYTES = 200 * 1024 * 1024 * 1024
MAX_UPLOAD_FILE_BYTES = 1_500_000
MAX_UPLOAD_MANIFEST_BYTES = MAX_MANIFEST_BYTES
SKIP_UPLOAD_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__", ".next", ".idea"}
UPLOAD_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".swift", ".scala", ".sh", ".bash", ".sql", ".html", ".css", ".scss", ".vue", ".svelte", ".json", ".yml", ".yaml", ".toml", ".ini", ".xml", ".tf"}


PAGE = Path(__file__).with_name("page.html").read_text(encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        print("[web] " + fmt % args)

    def do_GET(self) -> None:
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        data = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        endpoint = urlparse(self.path).path
        if endpoint not in {"/api/scan", "/api/upload/start", "/api/upload/file", "/api/upload/finish", "/api/upload/cancel"}:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 25 * 1024 * 1024:
                raise ValueError("A single upload request is too large.")
            payload = json.loads(self.rfile.read(length))
            if endpoint == "/api/scan":
                if length > 4096:
                    raise ValueError("Request is too large.")
                report = scan(payload.get("path", ""))
                report["markdown"] = to_markdown(report)
                self._json(200, report)
            elif endpoint == "/api/upload/start":
                self._json(200, self._start_upload(payload))
            elif endpoint == "/api/upload/file":
                self._json(200, self._upload_file(payload))
            elif endpoint == "/api/upload/cancel":
                self._cancel_upload(str(payload.get("upload_id", "")))
                self._json(200, {"ok": True})
            else:
                report = self._finish_upload(payload)
                report["markdown"] = to_markdown(report)
                self._json(200, report)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": f"Scan failed: {exc}"})

    @staticmethod
    def _start_upload(payload: dict) -> dict:
        total_bytes = payload.get("total_bytes")
        file_count = payload.get("file_count")
        if not isinstance(total_bytes, int) or total_bytes < 0 or total_bytes > MAX_UPLOAD_BYTES:
            raise ValueError("Selected folder exceeds the 200 GB upload limit.")
        if not isinstance(file_count, int) or file_count < 1 or file_count > 20000:
            raise ValueError("Choose a folder with between 1 and 20,000 supported files.")
        name = str(payload.get("name", "Uploaded project")).replace("\\", "/").split("/")[-1].replace("`", "'")
        temp = tempfile.TemporaryDirectory(prefix="reposleuth-")
        upload_id = secrets.token_urlsafe(24)
        with UPLOADS_LOCK:
            now = time.time()
            for key, session in list(UPLOADS.items()):
                if now - session["updated"] > 3 * 60 * 60:
                    session["temp"].cleanup()
                    del UPLOADS[key]
            UPLOADS[upload_id] = {"temp": temp, "root": Path(temp.name), "name": name or "Uploaded project", "expected_files": file_count, "received_files": 0, "received_bytes": 0, "updated": now}
        return {"upload_id": upload_id}

    @staticmethod
    def _upload_file(payload: dict) -> dict:
        upload_id = str(payload.get("upload_id", ""))
        rel_text = payload.get("path")
        content = payload.get("content")
        if not isinstance(rel_text, str) or not isinstance(content, str):
            raise ValueError("The uploaded file is invalid.")
        rel = PurePosixPath(rel_text)
        if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts) or "\\" in rel_text:
            raise ValueError("The upload contains an unsafe file path.")
        size = len(content.encode("utf-8"))
        max_file_size = MAX_UPLOAD_MANIFEST_BYTES if rel.name.lower() in MANIFEST_NAMES else MAX_UPLOAD_FILE_BYTES
        if size > max_file_size:
            raise ValueError("Source files over 1.5 MB and dependency manifests over 20 MB are skipped.")
        with UPLOADS_LOCK:
            session = UPLOADS.get(upload_id)
            if not session:
                raise ValueError("Upload session expired. Please choose the folder again.")
            if session["received_files"] >= session["expected_files"]:
                raise ValueError("The upload contains more files than expected.")
            if session["received_bytes"] + size > MAX_UPLOAD_BYTES:
                raise ValueError("Selected folder exceeds the 200 GB upload limit.")
            target = session["root"].joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            session["received_bytes"] += size
            session["received_files"] += 1
            session["updated"] = time.time()
            return {"files_received": session["received_files"]}

    @staticmethod
    def _cancel_upload(upload_id: str) -> None:
        with UPLOADS_LOCK:
            session = UPLOADS.pop(upload_id, None)
        if session:
            session["temp"].cleanup()

    @staticmethod
    def _finish_upload(payload: dict) -> dict:
        upload_id = str(payload.get("upload_id", ""))
        with UPLOADS_LOCK:
            session = UPLOADS.pop(upload_id, None)
        if not session:
            raise ValueError("Upload session expired. Please choose the folder again.")
        try:
            if session["received_files"] != session["expected_files"]:
                raise ValueError("Upload was incomplete. Please choose the folder and try again.")
            report = scan(session["root"])
            report["root"] = session["name"]
            return report
        finally:
            session["temp"].cleanup()

    def _json(self, status: int, obj: dict) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"RepoSleuth is running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping RepoSleuth.")
    finally:
        server.server_close()
