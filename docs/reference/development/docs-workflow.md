---
title: Docs Workflow
package: .github/workflows
---

# Docs Workflow

The `.github/workflows/docs.yml` workflow builds the VitePress documentation site and publishes it to GitHub Pages. A pull request builds the site to prove it still builds; only a push to `main` publishes it.

## Trigger Events

| Event               | Filter                                    | What runs           |
|---------------------|-------------------------------------------|---------------------|
| `push`              | branch `main`, the paths below            | build and deploy    |
| `pull_request`      | the paths below                           | build only          |
| `workflow_dispatch` | —                                         | build and deploy    |

Both path filters carry the same four entries:

```yaml
- 'docs/**'
- 'package.json'
- 'package-lock.json'
- '.github/workflows/docs.yml'
```

`package-lock.json` is in the list because `npm ci` reads it: a dependency bump can break the build without touching a single page.

## Permissions

| Permission      | Value   | Purpose                                  |
|-----------------|---------|------------------------------------------|
| `contents`      | `read`  | Check out the repository                 |
| `pages`         | `write` | Publish to GitHub Pages                  |
| `id-token`      | `write` | OIDC token for the Pages deployment      |

The two write permissions are declared at workflow level and therefore present on a pull-request run as well. What keeps a branch from replacing the live site is the event guard on the publishing steps, not the permission set. `internal/cicheck/docs_workflow_test.go` pins that guard.

## Concurrency

```yaml
group: ${{ github.event_name == 'pull_request' && format('docs-pr-{0}', github.ref) || 'pages' }}
cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

Pushes share the single `pages` group and never cancel each other, so a half-finished publish is always allowed to finish. Each pull request gets its own group and does cancel its own superseded builds, which is the right trade for a check that only reports.

## Jobs

### build

Runs on `ubuntu-latest` with a 10-minute timeout, on every trigger.

| Step                  | Command or action                                | Purpose                                    |
|-----------------------|--------------------------------------------------|--------------------------------------------|
| Checkout              | `actions/checkout` with `fetch-depth: 0`         | Full history, which VitePress reads for page timestamps |
| Setup Node            | `actions/setup-node`, Node 22, `cache: npm`      | Toolchain and dependency cache             |
| Install dependencies  | `npm ci`                                          | Install from the lockfile                  |
| Build docs            | `npm run docs:build`                              | Render the site into `docs/.vitepress/dist` |
| Configure Pages       | `actions/configure-pages`                         | Pages settings — **push only**             |
| Upload artifact       | `actions/upload-pages-artifact`                   | Upload `dist` — **push only**              |

The two Pages steps carry `if: github.event_name != 'pull_request'`, so a pull request stops after the build.

### deploy

Runs on `ubuntu-latest` with a 5-minute timeout, `needs: build`, and the same `if: github.event_name != 'pull_request'`. It publishes the uploaded artifact through `actions/deploy-pages` into the `github-pages` environment and reports the page URL as its output. On a pull request the job is skipped.

## Dead links

`npm run docs:build` fails on a markdown link to a page that does not exist, and `docs/.vitepress/config.mts` sets no `ignoreDeadLinks`. The build step is therefore the dead-link check as well as the build, which is the reason the workflow runs on pull requests at all: before this, a link that pointed nowhere was found only after it had already broken the published page.

A link that must point at something the check cannot resolve — an anchor generated at runtime, a file outside `docs/` — needs an entry in `ignoreDeadLinks` rather than a suppression at the link itself. Adding one turns the check off for that pattern everywhere, so it is worth a sentence in the pull request.

## Building locally

```bash
npm ci
npm run docs:build     # what CI runs, dead-link check included
npm run docs:dev       # live preview on http://localhost:5173
npm run docs:preview   # serve the built site
```

The build takes a few seconds on a warm cache. Run it before pushing a change under `docs/`: it is the same command CI runs and it catches the same dead links.

## Action Versions

All actions are pinned to full SHA hashes for supply-chain hardening, the rule `internal/cicheck` enforces for every workflow in this repository. The `checkout` and `setup-node` pins match those in the other workflows.

| Action                         | Version  | SHA                                          | Purpose                          |
|--------------------------------|----------|----------------------------------------------|----------------------------------|
| `actions/checkout`             | `v4.3.1` | `34e114876b0b11c390a56381ad16ebd13914f8d5`   | Repository checkout              |
| `actions/setup-node`           | `v4.4.0` | `49933ea5288caeca8642d1e84afbd3f7d6820020`   | Node installation and npm cache  |
| `actions/configure-pages`      | `v5.0.0` | `983d7736d9b0ae728b81ab479565c72886d7745b`   | GitHub Pages configuration       |
| `actions/upload-pages-artifact`| `v3.0.1` | `56afc609e74202658d3ffba0e8f6dda462b719fa`   | Upload the rendered site         |
| `actions/deploy-pages`         | `v4.0.5` | `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e`   | Deploy to GitHub Pages           |

## See Also

- [CI Workflow](./ci-workflow.md) — lint, unit tests and integration tests
- [Release Workflow](./release-workflow.md) — cross-compiled binaries and the GitHub Release
- [Getting Started](./getting-started.md) — prerequisites and the project structure
