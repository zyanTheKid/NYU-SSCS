# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (latest on `main`) | ✅ |
| < 0.1   | ❌ |

Only the latest release on `main` receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security problems.**

Report privately through GitHub: go to the **Security** tab → **Report a vulnerability**, or email **<app7633@nyu.edu>**.

Please include:
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version / commit.

## Response Process

- **Acknowledgement:** within 3 business days.
- **Assessment:** we confirm the issue and assess severity within 7 days.
- **Fix:** critical issues are patched within 30 days; you will be kept updated.
- **Disclosure:** once a fix is released, we publish a GitHub Security Advisory and credit the reporter (unless they prefer to stay anonymous).

## Security Updates

Fixes are released as a new patch version on `main` and announced in the repository's Security Advisories. Dependencies are pinned in `poetry.lock` and updated when vulnerabilities are disclosed.