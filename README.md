# RepoSleuth

RepoSleuth is a lightweight, local-first static codebase auditor. It works across common programming languages and project architectures and exports actionable Markdown or JSON reports. It has no Python package dependencies and does not use AI or online vulnerability services.

## Run the web interface

Requires Python 3.10 or newer.

```powershell
python -m auditor
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765), choose a project folder, and select **Run code audit**. The selected files are uploaded one at a time to the local server, scanned from a temporary directory, and deleted afterward. A folder may be up to 200 GB and 20,000 files. Supported source files up to 1.5 MB and dependency manifests up to 20 MB are uploaded; dependency/build folders are skipped. The server binds to localhost by default.

The report inventories dependency manifests and declared packages. It does not look up vulnerability advisories.

## Run from the command line

```powershell
python -m auditor scan "C:\path\to\project"
python -m auditor scan "C:\path\to\project" --format json
python -m auditor scan . --format markdown --output audit.md
python -m auditor scan .\project.zip
python -m auditor scan https://github.com/owner/public-repository
```

## Checks in this MVP

- Security: likely hardcoded credentials, dynamic SQL patterns, `eval`/`exec`, shell-enabled subprocesses, disabled TLS verification, debug mode, wildcard CORS, unsafe YAML loading, and weak hashes.
- Loose ends and implementation gaps: TODO/FIXME/HACK markers, explicit not-implemented errors, and Python functions containing only `pass`.
- Code quality: repeated long-line prompts and simple language-specific checks.
- Dependency manifests: inventories declared packages from common ecosystems.
- Reports include severity, category, source location, evidence, likely impact, and a suggested next step.

The scanner skips common dependency/build directories and source files larger than 1.5 MB; supported dependency manifests can be up to 20 MB. It inspects common source and configuration formats. Findings are heuristics: they can miss vulnerabilities or flag safe code, and scores are only rough prioritization aids. Review results in context; this is not a substitute for language-specific security tools or human review.

## Project layout

- `auditor/scanner.py` — scanning rules and report formatters
- `auditor/web.py` — dependency-free local web UI
- `auditor/__main__.py` — web and CLI entry points
