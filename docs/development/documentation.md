# Documentation workflow

Pistis documentation is maintained with Sphinx and the Read the Docs theme.
Markdown is parsed through MyST, so the canonical planning, governance,
protocol, security, and operator documents remain readable as source while
participating in one versioned documentation tree.

## Local container build

Docker is required. Build the pinned renderer from the repository root:

```sh
docker build \
  --file docs/Dockerfile \
  --tag pistis-docs:1.0.0 \
  .
```

Render into a disposable local directory:

```sh
mkdir -p public
docker run --rm \
  --read-only \
  --tmpfs /tmp:size=256m,mode=1777 \
  --volume "$PWD:/workspace:ro" \
  --volume "$PWD/public:/output" \
  pistis-docs:1.0.0 \
  --fail-on-warning \
  --keep-going \
  --builder html \
  --doctree-dir /tmp/pistis-doctrees \
  docs \
  /output
```

Open `public/index.html` locally and review navigation, code blocks, tables,
links, and narrow-screen behavior. Never commit credentials, private material,
or generated environment details into documentation or rendered pages.

## Manual GitHub Pages publication

Publication uses the `gh-pages` branch as a static artifact branch. No GitHub
Actions, Pages builder, webhook, scheduled task, or other deployment automation
is permitted.

After a reviewed render:

```sh
git fetch origin gh-pages
git worktree add /tmp/pistis-pages origin/gh-pages
rsync --archive --delete public/ /tmp/pistis-pages/
touch /tmp/pistis-pages/.nojekyll
git -C /tmp/pistis-pages add --all
git -C /tmp/pistis-pages commit -m "Publish documentation"
git -C /tmp/pistis-pages push origin HEAD:gh-pages
git worktree remove /tmp/pistis-pages
```

Inspect the staged artifact before committing. The publication commit must
contain pre-rendered HTML and assets only. Source changes remain on the normal
development branch.
