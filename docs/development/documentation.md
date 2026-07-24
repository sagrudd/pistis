# Documentation workflow

Pistis documentation is maintained with Sphinx and the Read the Docs theme.
Markdown is parsed through MyST, so the canonical planning, governance,
protocol, security, and operator documents remain readable as source while
participating in one versioned documentation tree.

## Authoritative Jenkins build

The project-owned Mnemosyne Expedition/Jenkins lane is the authoritative
documentation builder. Its reviewed task:

- installs the exact versions in `docs/requirements.txt`;
- runs Sphinx with warnings treated as errors;
- keeps doctrees outside the publication directory; and
- retains `docs-html.tar.gz` in the Expedition dossier.

Jenkins validates and packages documentation but never publishes it. Obtain the
reviewed artifact from the Base Camp portal or CLI:

```sh
expedition expedition-artifact \
  --expedition-id <uuid> \
  --name docs-html.tar.gz \
  --output docs-html.tar.gz
mkdir -p public
tar --extract --gzip --file docs-html.tar.gz --directory public
```

Inspect the dossier acceptance result and verify the artifact digest before
publication.

## Optional local container preview

The repository Docker image reproduces the Jenkins Sphinx environment for
developer preview. It is not release evidence. Build it from the repository
root:

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

After downloading and reviewing the Jenkins artifact:

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
