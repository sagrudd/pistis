# Documentation workflow

Pistis documentation is maintained with Sphinx and the Read the Docs theme.
Markdown is parsed through MyST, so the canonical planning, governance,
protocol, security, and operator documents remain readable as source while
participating in one versioned documentation tree.

Maintained documentation and user-facing mobile text use British English.
Externally fixed protocol fields, API names, code identifiers, and quoted
third-party terminology retain their defining spelling. Run
`cargo run --locked -p xtask -- language` before review; the deterministic
guard ignores fenced and inline code while checking maintained prose and
mobile display strings.

## Authoritative Jenkins build

The project-owned Mnemosyne Expedition/Jenkins lane is the authoritative
documentation builder. Its reviewed task:

- installs the exact versions in `docs/requirements.txt`;
- runs Sphinx with warnings treated as errors;
- keeps doctrees outside the publication directory; and
- retains `docs-html.tar.gz` in the Expedition dossier.

Jenkins packages the reviewed artefact in the Base Camp dossier:

```sh
expedition expedition-artifact \
  --expedition-id <uuid> \
  --name docs-html.tar.gz \
  --output docs-html.tar.gz
mkdir -p public
tar --extract --gzip --file docs-html.tar.gz --directory public
```

Use this retrieval flow for inspection, audit, or recovery.

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
links, and narrow-screen behaviour. Never commit credentials, private material,
or generated environment details into documentation or rendered pages.

## Jenkins GitHub Pages publication

After every successful CI run, the centrally reviewed Jenkins adapter compares
the tested revision with the current `refs/heads/main`. Pull-request, stale, and
failed builds stop without publishing. A matching build validates
`docs-html.tar.gz`, removes links from the extracted tree, adds `.nojekyll`, and
updates the `gh-pages` artefact branch with the pre-rendered site.

The publisher uses the Jenkins secret-text credential
`pistis-pages-publisher`. It must contain a least-privileged GitHub token with
Contents write access to this repository. The credential is available only to
the fixed publisher container after the project-controlled CI command has
finished; Sphinx and repository code cannot read it.

GitHub Pages serves `gh-pages` as static content. Do not add GitHub Actions or
another Pages build or deployment workflow.
