# Releasing

Releases are driven by **git tags** and **Conventional Commits**. The version is derived
from the tag (via `hatch-vcs`) — never edited by hand — and the release notes are generated
from commit messages (via `git-cliff`, grouped into Features / Bug Fixes / Documentation / …).

## Choosing the version (SemVer)

- `fix:` / `perf:` only → **patch** (`0.1.0` → `0.1.1`)
- any `feat:` → **minor** (`0.1.0` → `0.2.0`)
- a breaking change (`feat!:` or a `BREAKING CHANGE:` footer) → **major** (pre-1.0: bump minor)

Preview what the next release will contain:

```bash
uv run git-cliff --unreleased          # unreleased commits, categorized
```

## Cutting a release

1. Make sure `main` is green (CI: lint, types, tests).
2. Update the changelog for the new version and commit it:
   ```bash
   uv run git-cliff --tag vX.Y.Z -o CHANGELOG.md
   git add CHANGELOG.md && git commit -m "docs: changelog for vX.Y.Z"
   ```
3. Tag and push:
   ```bash
   git tag vX.Y.Z
   git push origin main
   git push origin vX.Y.Z
   ```

## What the tag push does

The `Release` workflow (`.github/workflows/release.yml`) runs on `v*` tags and:

1. **build** — `uv build` produces the sdist + wheel (version comes from the tag).
2. **publish** — uploads to PyPI via **Trusted Publishing** (OIDC, no tokens) with Sigstore attestations.
3. **github-release** — generates categorized notes for the tag with `git-cliff` and creates a
   **GitHub Release** with those notes and the built artifacts attached.

The commit-message prefixes that drive the notes: `feat:`, `fix:`, `docs:`, `perf:`, `refactor:`,
`build:`, `ci:`. `test:`, `chore:`, and `style:` are omitted from release notes.
