"""Heuristic, language-agnostic codebase checks with a few language-aware rules."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__", ".next", ".idea"}
MANIFEST_NAMES = {"requirements.txt", "requirements-dev.txt", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "cargo.lock", "go.mod", "go.sum", "yarn.lock", "pnpm-lock.yaml", "package-lock.json", "composer.json", "composer.lock", "gemfile", "gemfile.lock", "build.gradle", "build.gradle.kts", "directory.build.props"}
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".swift", ".scala", ".sh", ".bash", ".sql", ".html", ".css", ".scss", ".vue", ".svelte", ".json", ".yml", ".yaml", ".toml", ".ini", ".xml", ".tf",
}
MAX_FILE_BYTES = 1_500_000
MAX_MANIFEST_BYTES = 20 * 1024 * 1024
MAX_FILES = 20_000


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    file: str
    line: int
    evidence: str
    impact: str
    recommendation: str


RULES = [
    ("secret", "critical", "Security", "Possible hardcoded secret", re.compile(r"(?i)(?:api[_-]?key|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*['\"](?!\s*(?:your[_-].*|<.*>|\$\{|\$|process\.|os\.|env\.)['\"])[^'\"\s]{8,}['\"]"), "A credential may be committed in source and exposed to anyone with repository access.", "Remove the value, rotate the credential, and load it from a secret manager or environment variable."),
    ("sql-concat", "high", "Security", "Possible SQL injection", re.compile(r"(?i)(?:execute|executemany|query|raw)\s*\([^\n]*(?:\+\s*\w|\%\s*\w|\$\{\w|\bconcat\s*\()"), "Dynamic values may be inserted into a database query without parameterization.", "Use parameterized queries or the framework's safe query builder."),
    ("eval", "high", "Security", "Dynamic code execution", re.compile(r"\b(?:eval|exec)\s*\("), "Executing dynamically constructed code can let untrusted input run with application privileges.", "Avoid dynamic execution; if unavoidable, strictly constrain and validate the input."),
    ("shell-true", "high", "Security", "Subprocess uses a shell", re.compile(r"(?i)shell\s*=\s*True"), "Shell invocation with constructed input can enable command injection.", "Pass an argument list with shell disabled, and validate any user-controlled arguments."),
    ("tls-disabled", "high", "Security", "TLS certificate verification disabled", re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)"), "The connection may accept an impersonated server, exposing data to interception.", "Enable certificate verification and configure the correct trust roots."),
    ("debug-enabled", "medium", "Security", "Debug mode may be enabled", re.compile(r"(?i)(?:DEBUG\s*[:=]\s*True|debug\s*:\s*true|debug\s*=\s*true)"), "Detailed errors or development behavior may be exposed in a deployed environment.", "Disable debug mode in production and set it through an environment-specific configuration."),
    ("wildcard-cors", "medium", "Security", "Wildcard cross-origin policy", re.compile(r"(?i)(?:Access-Control-Allow-Origin\s*[:=]\s*['\"]\*|cors\s*\(\s*\{?\s*origin\s*:\s*['\"]\*)"), "Any website may be allowed to make cross-origin requests to this service.", "Restrict allowed origins to the specific trusted sites that need access."),
    ("unsafe-yaml", "high", "Security", "Potentially unsafe YAML deserialization", re.compile(r"\byaml\.load\s*\("), "Unsafe YAML loading can instantiate objects or execute code from untrusted documents, depending on the loader.", "Use a safe loader for untrusted YAML and validate the resulting data."),
    ("weak-hash", "low", "Security", "Weak hash algorithm used", re.compile(r"(?i)(?:hashlib\.(?:md5|sha1)|createHash\s*\(\s*['\"](?:md5|sha1)|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1))"), "MD5 and SHA-1 are unsuitable for collision-resistant security uses.", "Use a modern cryptographic hash for integrity, and a password hashing scheme for passwords."),
]


def iter_files(root: Path) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and (path.suffix.lower() in TEXT_SUFFIXES or path.name == "Dockerfile" or path.name.lower() in MANIFEST_NAMES):
            try:
                if path.stat().st_size <= MAX_FILE_BYTES:
                    yield path
                    count += 1
                    if count >= MAX_FILES:
                        return
            except OSError:
                continue


def recalculate_summary(report: dict) -> None:
    findings = report["findings"]
    counts = Counter(f["severity"] for f in findings)
    categories = Counter(f["category"] for f in findings)
    def score_for(items: list[dict]) -> int:
        return max(0, 100 - sum({"critical": 25, "high": 12, "medium": 5, "low": 1}.get(f["severity"], 0) for f in items))
    security = [f for f in findings if f["category"] == "Security"]
    quality = [f for f in findings if f["category"] != "Security"]
    security_score, quality_score = score_for(security), score_for(quality)
    prioritized = Counter(f["file"] for f in findings)
    report["summary"] = {"total": len(findings), "critical": counts["critical"], "high": counts["high"], "medium": counts["medium"], "low": counts["low"], "security_score": security_score, "code_quality_score": quality_score, "overall_score": round(security_score * 0.6 + quality_score * 0.4), "unfinished_tasks": categories["Loose end"] + categories["Implementation gap"], "category_counts": dict(categories), "files_needing_attention": [name for name, _ in prioritized.most_common(5)], "dependency_count": len(report.get("dependencies", []))}


def collect_dependencies(root: Path) -> list[dict]:
    """Build a best-effort dependency inventory from common manifest formats."""
    inventory = []
    for path in root.rglob("*"):
        if len(inventory) >= 1000:
            break
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        name = path.name.lower()
        if name not in MANIFEST_NAMES | {"package.json", "pyproject.toml", "cargo.toml", "composer.json"}:
            continue
        try:
            if path.stat().st_size > MAX_MANIFEST_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        deps = []
        ecosystem = {"package.json": "npm", "package-lock.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm", "requirements.txt": "PyPI", "requirements-dev.txt": "PyPI", "pipfile": "PyPI", "pipfile.lock": "PyPI", "poetry.lock": "PyPI", "uv.lock": "PyPI", "pyproject.toml": "PyPI", "go.mod": "Go", "go.sum": "Go", "cargo.toml": "crates.io", "cargo.lock": "crates.io", "composer.json": "Packagist", "composer.lock": "Packagist", "gemfile": "RubyGems", "gemfile.lock": "RubyGems", "build.gradle": "Maven", "build.gradle.kts": "Maven"}.get(name)
        if name in {"package.json", "composer.json"}:
            try:
                data = json.loads(text)
                for group in ("dependencies", "devDependencies", "optionalDependencies", "require", "require-dev"):
                    values = data.get(group, {})
                    if isinstance(values, dict):
                        deps.extend({"name": pkg, "version": str(version), "group": group} for pkg, version in values.items())
            except (json.JSONDecodeError, AttributeError):
                pass
        elif name in {"requirements.txt", "requirements-dev.txt"}:
            for line in text.splitlines():
                match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*([<>=!~]+[^;\s]+)?", line)
                if match and not line.lstrip().startswith(("#", "-")):
                    deps.append({"name": match.group(1), "version": (match.group(2) or "unspecified").strip(), "group": "runtime"})
        elif name == "package-lock.json":
            try:
                data = json.loads(text)
                packages = data.get("packages", {})
                for key, item in packages.items():
                    if not key or not isinstance(item, dict) or not item.get("version"):
                        continue
                    pkg = key.split("node_modules/")[-1]
                    deps.append({"name": pkg, "version": str(item["version"]), "group": "lockfile"})
                def walk(items: dict) -> None:
                    for pkg, item in items.items():
                        if isinstance(item, dict):
                            if item.get("version"):
                                deps.append({"name": pkg, "version": str(item["version"]), "group": "lockfile"})
                            walk(item.get("dependencies", {}))
                if not packages:
                    walk(data.get("dependencies", {}))
            except (json.JSONDecodeError, AttributeError):
                pass
        elif name == "pipfile.lock":
            try:
                data = json.loads(text)
                for group in ("default", "develop"):
                    for pkg, item in data.get(group, {}).items():
                        if isinstance(item, dict):
                            deps.append({"name": pkg, "version": str(item.get("version", "unspecified")).lstrip("="), "group": group})
            except (json.JSONDecodeError, AttributeError):
                pass
        elif name in {"poetry.lock", "uv.lock", "cargo.lock"}:
            current = {}
            for line in text.splitlines():
                if line.strip() in {"[[package]]", "[[Package]]"}:
                    if current.get("name") and current.get("version"):
                        deps.append({"name": current["name"], "version": current["version"], "group": "lockfile"})
                    current = {}
                match = re.match(r'\s*(name|version)\s*=\s*["\']([^"\']+)', line)
                if match:
                    current[match.group(1)] = match.group(2)
            if current.get("name") and current.get("version"):
                deps.append({"name": current["name"], "version": current["version"], "group": "lockfile"})
        elif name == "go.sum":
            for line in text.splitlines():
                match = re.match(r"([^\s]+)\s+(v\d+[^\s/]*)(?:/go\.mod)?\s+", line)
                if match and "/go.mod" not in line:
                    deps.append({"name": match.group(1), "version": match.group(2), "group": "lockfile"})
        elif name in {"yarn.lock", "pnpm-lock.yaml"}:
            for line in text.splitlines():
                match = re.match(r"\s*(?:version\s+[\"']?|/|['\"]?)(@?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@(?:npm:)?(v?\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)", line)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2), "group": "lockfile"})
        elif name in {"composer.lock", "gemfile.lock"}:
            try:
                data = json.loads(text) if name == "composer.lock" else None
                if data:
                    for group in ("packages", "packages-dev"):
                        deps.extend({"name": item["name"], "version": str(item["version"]).lstrip("v"), "group": group} for item in data.get(group, []) if item.get("name") and item.get("version"))
                else:
                    for match in re.finditer(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", text, re.MULTILINE):
                        deps.append({"name": match.group(1), "version": match.group(2), "group": "lockfile"})
            except (json.JSONDecodeError, AttributeError):
                pass
        elif name in {"go.mod", "cargo.toml", "pyproject.toml", "build.gradle", "build.gradle.kts"}:
            for line in text.splitlines():
                match = re.match(r"\s*([A-Za-z0-9_./@+-]+)\s+(v?\d[^\s,]*)", line)
                if match and not line.lstrip().startswith(("//", "#", "*")):
                    deps.append({"name": match.group(1), "version": match.group(2), "group": "manifest"})
        if deps:
            inventory.extend({"manifest": path.relative_to(root).as_posix(), "ecosystem": ecosystem, **dep} for dep in deps)
    return inventory[:1000]


def scan(root: str | Path) -> dict:
    base = Path(root).expanduser().resolve()
    if not base.exists() or not base.is_dir():
        raise ValueError("Choose an existing project directory.")
    findings: list[Finding] = []
    scanned = 0

    def add(rule: str, severity: str, category: str, title: str, path: Path, line: int, evidence: str, impact: str, recommendation: str) -> None:
        rel = path.relative_to(base).as_posix()
        findings.append(Finding(f"{rule}:{rel}:{line}", severity, category, title, rel, line, evidence.strip()[:220], impact, recommendation))

    for path in iter_files(base):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        lines = content.splitlines()
        for number, line in enumerate(lines, 1):
            for rule, severity, category, title, pattern, impact, recommendation in RULES:
                if pattern.search(line):
                    add(rule, severity, category, title, path, number, line, impact, recommendation)
            # Track explicit comment markers, not the scanner's own rule text or prose.
            if re.search(r"(?i)(?:#|//|/\*|\*|<!--|--)\s*(?:TODO|FIXME|XXX|HACK)\b", line):
                add("todo", "low", "Loose end", "Unresolved work marker", path, number, line, "This code may represent unfinished work or a known defect.", "Confirm the work is tracked and complete it, or remove the stale marker.")
            if not re.search(r"\bre\.search\s*\(\s*r[\"']", line) and re.search(r"(?i)\b(?:NotImplementedException|NotImplementedError)\b|\b(?:throw|raise)\s+new\s+NotImplemented", line):
                add("not-implemented", "medium", "Implementation gap", "Explicitly unimplemented behavior", path, number, line, "A reachable code path may fail instead of providing its intended behavior.", "Implement the behavior or make the unsupported state explicit at the interface boundary.")
            if re.search(r"(?i)\b(?:password|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]", line) and not any(x in line.lower() for x in ("example", "placeholder", "your_", "changeme", "dummy", "test")):
                # This lower-confidence fallback is intentionally medium severity.
                if not any(f.file == path.relative_to(base).as_posix() and f.line == number and f.id.startswith("secret:") for f in findings):
                    add("credential-literal", "medium", "Security", "Review credential-like literal", path, number, line, "A value resembling a credential is embedded in source.", "Verify that this is not a live credential; move real secrets to a secret manager and rotate exposed values.")
        if path.suffix.lower() == ".py":
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        body = node.body
                        if len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                            body = body[1:]
                        if len(body) == 1 and isinstance(body[0], ast.Pass):
                            add("empty-function", "medium", "Implementation gap", f"Empty function: {node.name}", path, node.lineno, f"def {node.name}(…): pass", "The function currently performs no work and may silently leave a feature incomplete.", "Implement the function, or raise a clear exception if it is intentionally unsupported.")
            except (SyntaxError, ValueError):
                pass

    # Only report exact repeated non-trivial lines; avoid common syntax and blank lines.
    for path in iter_files(base):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        occurrences: dict[str, list[int]] = {}
        for i, raw in enumerate(lines, 1):
            value = raw.strip()
            if len(value) >= 50 and not value.startswith(("//", "#", "*", "<!--")) and "send_header(" not in value:
                occurrences.setdefault(value, []).append(i)
        for value, nums in occurrences.items():
            if len(nums) == 2:
                add("duplicate-line", "low", "Code quality", "Repeated long code line", path, nums[1], value, "Repeated logic can drift as one copy changes without the other.", "Check whether the repeated line represents duplicated behavior that should be shared.")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (severity_order[f.severity], f.file, f.line, f.id))
    manifest_names = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "composer.lock", "Gemfile", "Gemfile.lock"}
    manifests = [p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file() and p.name in manifest_names and not any(part in SKIP_DIRS for part in p.parts)]
    report = {"root": str(base), "files_scanned": scanned, "dependency_manifests": sorted(manifests), "dependencies": collect_dependencies(base), "findings": [asdict(f) for f in findings]}
    recalculate_summary(report)
    return report


def to_markdown(report: dict) -> str:
    s = report["summary"]
    out = ["# Code Audit Report", "", f"**Project:** `{report['root']}`  ", f"**Files scanned:** {report['files_scanned']}  ", f"**Overall score:** {s['overall_score']}/100 · **Security:** {s['security_score']}/100 · **Code quality:** {s['code_quality_score']}/100", f"**Unfinished tasks:** {s['unfinished_tasks']}  ", "", f"**Findings:** {s['total']} — Critical {s['critical']} · High {s['high']} · Medium {s['medium']} · Low {s['low']}", ""]
    if report.get("dependency_manifests"):
        out += ["**Dependency manifests found:** " + ", ".join(f"`{m}`" for m in report["dependency_manifests"]), ""]
    out += [f"**Dependencies inventoried:** {s['dependency_count']}", ""]
    if s.get("files_needing_attention"):
        out += ["**Files needing immediate attention:** " + ", ".join(f"`{name}`" for name in s["files_needing_attention"]), ""]
    if s.get("category_counts"):
        out += ["**Findings by category:** " + " · ".join(f"{key}: {value}" for key, value in sorted(s["category_counts"].items())), ""]
    if not report["findings"]:
        out.append("No findings from the enabled checks.")
    for i, f in enumerate(report["findings"], 1):
        evidence = f["evidence"].replace("`", "\\`")
        out += [f"## {i}. [{f['severity'].upper()}] {f['title']}", "", f"- **Category:** {f['category']}", f"- **Location:** `{f['file']}:{f['line']}`", f"- **Evidence:** `{evidence}`", f"- **Impact:** {f['impact']}", f"- **Recommendation:** {f['recommendation']}", ""]
    out += ["---", "Heuristic static analysis is imperfect. Review findings in context; this report is not a guarantee that the code is secure."]
    return "\n".join(out)


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)
