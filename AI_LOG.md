# AI Usage Log

RepoSleuth is a static-analysis tool. The submitted application does not call an AI model, send source code to an AI service, or require Ollama. The AI review feature was removed from the project.

AI assistance was used during development to help implement and refine the application. Work included the project-folder upload workflow, static scanning rules, report generation, interface improvements, and documentation. The resulting code and behavior should be reviewed by the project author before release.

## Runtime AI use

- AI model or provider used by the application: None
- User project code sent to an AI provider: No
- AI-generated runtime findings: No

## Verification

The scanner uses deterministic heuristics implemented in `auditor/scanner.py`. Findings may be incomplete or require human review, as described in the README.
