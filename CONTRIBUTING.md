# Contributing to Gauntlet

Thanks for your interest! Gauntlet is a contract-driven DAST tool, and contributions are welcome — especially new checks, better reports, and docs.

## Development setup

```bash
git clone https://github.com/gioeleBrancaleoni/gauntlet.git
cd gauntlet
pip install -e ".[dev]"   # or: pipx install --editable .
pytest -q                  # the suite is hermetic — no Docker or network needed
```

Python ≥ 3.12 is required. The test suite mocks Docker, ZAP and the network, so it runs anywhere and fast.

## How the project is shaped

Gauntlet runs on **two engines** (see [`docs/checks.md`](docs/checks.md) for the full catalog):

1. **OWASP ZAP** (in Docker) for classic web vulnerabilities.
2. **A custom, deterministic access-control & auth tester** (a direct HTTP client) — the crown jewel.

Everything is driven by a per-project **contract** (`gauntlet.yaml`); the code never hard-codes a target.

## Bar for a new check

A new check in the custom engine must:

- **Have a deterministic oracle.** A high-value finding is *confirmed*, never inferred: a bare status code is never enough. Confidence `1.0` means "proven by a load-bearing oracle, zero false positives by construction"; anything observational stays below `1.0` and is worded cautiously.
- **Be non-destructive by default.** Anything that writes or can disrupt the target runs **only** under `--aggressive`, behind the batch-consent hook (`confirm_destructive`).
- **Respect the fail-closed allowlist.** Every request passes `assert_target_allowed` on the original URL *before* any traffic.
- **Be localized.** User-facing strings go through `gauntlet/i18n.py` with both `it` and `en`.
- **Be documented.** Add an entry to [`docs/checks.md`](docs/checks.md): oracle, severity, confidence, trustworthiness.
- **Be tested.** Follow TDD; tests are hermetic (`pytest-httpserver` / mocked ZAP client), assert real behavior, and keep output pristine.

`gauntlet/cors_checks.py` and `gauntlet/open_redirect_checks.py` are good, compact templates to copy.

## House rules

- **No private or third-party data in the repo.** Never commit real client/app names, personal file paths, secrets, or internal URLs. Use generic hosts (`localhost`, `host.docker.internal`, `*.example`) and keep account passwords in environment variables (`password_env`), never in YAML.
- Keep commits focused; run the full suite before opening a PR.
- CI (GitHub Actions) runs the suite on Python 3.12 and 3.13 — it must be green.

## Reporting security issues

Gauntlet is a tool for testing **your own** applications with authorization. If you find a vulnerability **in Gauntlet itself**, please open an issue describing the class of problem (avoid posting a working exploit).

## License

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE).
