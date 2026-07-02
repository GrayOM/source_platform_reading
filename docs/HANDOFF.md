# SSS v1.4.1 Handoff

## Current State

- Branch: `main`
- Latest commit: `867ab85 docs: clarify local demo deployment model`
- Previous release-hardening commit: `2c725a8 fix: harden evidence bundle export`
- Working tree was clean before this handoff file was created.
- GitHub Actions for commit `2c725a8` completed successfully.
- The latest README update documents the local demo deployment model and links existing screenshots.

## Completed Work

- v1 release documentation was prepared.
- Release guardrails were added.
- Evidence bundle export was hardened.
- Evidence bundle screenshot paths are restricted to the scan output screenshots directory.
- Screenshot paths outside the scan output root are ignored.
- Evidence bundle report/ZIP generation is offloaded to a threadpool.
- JSON report filenames now include the requested report type.
- CI and Makefile guardrail scripts use `bash ./scripts/...`.
- README now explains that SSS is primarily a local demo or controlled internal tool.
- README now includes Docker Compose start/stop/reset commands.
- README now clarifies that GitHub Releases record versions and do not host running services.
- README now includes screenshots from `docs/screenshots/`.

## Last Known Verification

- `docker compose config`: passed
- Backend/worker/worker-browser Docker build: passed
- Frontend Docker build: passed
- E2E profile startup: passed
- Backend pytest: `87 passed`
- Frontend build: passed
- WeasyPrint PDF smoke: passed
- `bash ./scripts/check_secret_like.sh`: passed
- `bash ./scripts/check_line_endings.sh`: passed
- `git diff --check`: passed
- GitHub Actions jobs for `2c725a8`: all success
  - Repository Guardrails
  - Backend
  - Frontend
  - Docker Compose Config
  - Docker Compose Build

## Release Candidate

- Tag: `v1.4.1-bundle-hardening`
- Tag message: `SSS v1.4.1 evidence bundle hardening`
- Release title: `SSS v1.4.1 - Evidence Bundle Hardening`

## Release Notes Draft

```markdown
## Summary

- Scan Policy/Safety Guardrails
- Outside-scope blocking
- Redirect outside-scope blocking
- Evidence Artifact
- Evidence bundle export
- Screenshot path hardening for evidence bundles
- Report/ZIP generation stability via threadpool offload
- KISA/Full/Markdown/JSON/PDF report generation
- Report Metadata Builder
- CI guardrails
- Secret-like literal check
- Line ending check

## Verification

- GitHub Actions CI completed successfully
- Repository Guardrails passed
- Backend tests passed
- Frontend build passed
- Docker Compose config passed
- Docker Compose build passed
- Secret-like literal check passed
- Line ending check passed
- WeasyPrint PDF smoke passed

## Security / Safety Notes

- Evidence bundle ZIP now only includes screenshot files under the scan output screenshots directory.
- Screenshot paths outside the scan output root are ignored.
- Evidence bundle generation is offloaded to a threadpool to avoid blocking the API event loop.
- Release guardrails prevent secret-like test literals and CRLF line ending drift.
```

## Next Steps After Restart

1. Check the current state:

```bash
git status --short
git log --oneline -5
```

2. If this handoff file is the only pending change, commit it:

```bash
git add docs/HANDOFF.md
git commit -m "docs: add release handoff"
```

3. Push `main`:

```bash
git push origin main
```

4. Create and push the release tag:

```bash
git tag -a v1.4.1-bundle-hardening -m "SSS v1.4.1 evidence bundle hardening"
git push origin v1.4.1-bundle-hardening
```

5. Create the GitHub Release with the title and notes above.

## Important Constraints

- Do not add new scanner features before this release.
- Do not change crawler, report, evidence, backend, or frontend logic unless CI fails.
- Do not add deployment automation, GHCR publish workflows, or public SaaS hosting defaults.
- Do not hardcode secret-like literals in docs, tests, or source.
- Keep SSS positioned as a local demo or controlled internal tool by default.
