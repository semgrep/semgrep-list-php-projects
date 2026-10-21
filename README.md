# semgrep-list-php-projects

Lists the Semgrep projects that contain PHP, from the terminal.

```bash
semgrep login                                    # or: export SEMGREP_APP_TOKEN=...
uvx semgrep-list-php-projects > php-projects.txt
uvx semgrep-list-php-projects --format json
```

```
acme/cms
acme/legacy-portal
acme/web
```

The text output is one name per line, so it feeds straight into anything that
takes a list of projects, such as `semgrep-sbom export --projects-file`.

## Install: pick one

**uv** (recommended; pure Python, no dependencies, Python 3.11 or newer):

```bash
uvx semgrep-list-php-projects --help          # needs https://docs.astral.sh/uv/
pipx run semgrep-list-php-projects --help     # or pipx
```

**Docker** (needs nothing but Docker; `linux/amd64` and `linux/arm64`):

```bash
docker run --rm -e SEMGREP_APP_TOKEN ghcr.io/semgrep/semgrep-list-php-projects:0.1.0 --help
```

Or use the wrapper script, which also finds the token `semgrep login` stored
and runs the container as your own user with a read-only filesystem, no
capabilities and no other mounts:

```bash
curl -fsSLO https://raw.githubusercontent.com/semgrep/semgrep-list-php-projects/v0.1.0/semgrep-list-php-projects.sh
less semgrep-list-php-projects.sh && chmod +x semgrep-list-php-projects.sh
./semgrep-list-php-projects.sh > php-projects.txt
```

**Straight from git** (no release needed):

```bash
uvx --from git+https://github.com/semgrep/semgrep-list-php-projects semgrep-list-php-projects
```

**Verify what you got.** Every release is built by
[the release workflow](.github/workflows/release.yml) in this repository:

```bash
gh attestation verify oci://ghcr.io/semgrep/semgrep-list-php-projects:0.1.0 --owner semgrep
```

The PyPI release carries PEP 740 attestations, shown on each file at
[pypi.org](https://pypi.org/project/semgrep-list-php-projects/).

## The token

The tool looks for a Semgrep API token in this order and uses the first it
finds:

1. **`~/.semgrep/settings.yml`**, which `semgrep login` writes. Set
   `SEMGREP_SETTINGS_FILE` to use another path, as with the semgrep CLI.
2. **`SEMGREP_APP_TOKEN`** in the environment.
3. **A prompt**, with input hidden, when run from a terminal. Without a
   terminal (CI, a pipe) there is nothing to prompt, so that is an error.

The token is never accepted as a command-line argument, so it stays out of
shell history and `ps`. It is never logged or written to disk. The token decides
the deployment, so you never pass one.

The token needs the **Web API** scope, because every endpoint used is a public
v1 endpoint. The token `semgrep login` creates has it. A CI-only token (the
`agent_cli` scope) gets HTTP 401 here, and the error says so.

In Docker, the wrapper script mounts the settings file read-only and forwards
`SEMGREP_APP_TOKEN` by name. Without the wrapper, pass one of:

```bash
docker run --rm -v ~/.semgrep/settings.yml:/run/semgrep/settings.yml:ro \
  -e SEMGREP_SETTINGS_FILE=/run/semgrep/settings.yml ghcr.io/semgrep/semgrep-list-php-projects:0.1.0
docker run --rm -e SEMGREP_APP_TOKEN ghcr.io/semgrep/semgrep-list-php-projects:0.1.0
```

## How PHP is detected

The Semgrep API has no "languages" field on a project. PHP is detected from
three signals instead, run in this order. Each one narrows what the next has to
cover:

| Signal | Source | Decides | Misses |
|---|---|---|---|
| `scans` | Latest full, completed Code scan: did Semgrep parse PHP files? | Yes **or no**, for every project with such a scan in the last 30 days | Projects with no full scan in 30 days |
| `composer` | Supply Chain: Composer dependencies | Yes, in one fast call | PHP with no `composer.lock`; every project when the deployment has no Supply Chain |
| `findings` | Code findings in `.php`, `.phtml`, `.php3`–`.php7` or `.phps` files, or from `php.*` rules | Yes, for projects the other two left undecided | PHP projects with no Code findings |

Each project in the `json` and `csv` output says which signal found it.

**How `scans` reads a scan** (checked against the live API on 2026-10-21): a
scan's `stats.parse_rate` lists every language Semgrep parsed, with file counts.
A project is PHP when `php` is listed with at least one file. The scan search
only works per project, so this signal costs two small requests per project. If
a scan ever comes back without `parse_rate`, the tool prints a warning naming
the fields it did see, and `findings` decides that project instead.

**Not every customer has Supply Chain.** If a signal's endpoint refuses with
HTTP 403 or 404, the tool prints a warning, records it under `signalsSkipped`
and answers from the others. Any other failure stops the run with exit `2`. A
list built from half a findings walk would look complete when it is not.

**A project no signal finds is not reported**, even if it contains PHP. If you
need certainty for a project that is not on the list, check its repository.

## Large organisations

Built for orgs with 10,000+ projects, while keeping load on the API low:

- **The findings walk is a fallback, not a sweep.** It runs only for projects
  that `scans` and `composer` left undecided, filtered to their ids in batches
  of 100. No query pages deep through the deployment's whole findings list.
  `projectsWalkedForFindings` in the JSON output says how many projects needed it.
- **Concurrency is capped.** The two scan requests per project run at most 4
  at a time (`--concurrency`, 1 to 8). A 10,000-project org is about 20,000
  small requests. The findings walk is always sequential.
- **Transient failures are retried.** Rate limits (429, honouring
  `Retry-After`), 5xx, timeouts and dropped connections are retried with
  backoff, up to 6 attempts per request.
- **Progress goes to stderr.**

## Options

| Option | Default | |
|---|---|---|
| `--signals scans,composer,findings` | all three | Which signals to run |
| `--concurrency N` | `4` | Parallel scan lookups, 1 to 8 |
| `--format text\|json\|csv` | `text` | `json` and `csv` add the project id, signals and counts |
| `--base-url URL` | `https://semgrep.dev` | |

## What leaves the API

Each Code finding is read only for its project name, file extension and rule
name. From each scan, only the per-language file counts are read. Snippets,
messages and file paths are never printed or stored. The output holds only
project names, ids and counts.

## Exit codes

| | |
|---|---|
| `0` | The lookup ran, even if nothing matched or a signal's product is not enabled |
| `2` | It did not finish: bad arguments, no token, or an API failure that survived retries |

## Development

```bash
uv sync --extra dev
uv run pytest
uv run semgrep-list-php-projects --help
```

The tests never reach the network: a fixture fails any test that tries.

To build and run the image locally:

```bash
docker build -t semgrep-list-php-projects:dev .
SEMGREP_LIST_PHP_PROJECTS_IMAGE=semgrep-list-php-projects:dev ./semgrep-list-php-projects.sh --help
```

## Releasing

1. Bump the version in `pyproject.toml`, `semgrep_list_php_projects/__init__.py`,
   the `Dockerfile` label, the wrapper script's default image and this README,
   then `uv lock`. Open a pull request; CI runs the tests and builds the image.
2. Tag the merged commit: `git tag v0.2.0 && git push origin v0.2.0`.

[The release workflow](.github/workflows/release.yml) refuses a tag whose
version does not match every one of those files, runs CI again, then publishes
the multi-arch image to GHCR with a build provenance attestation, the package to
PyPI through trusted publishing (no token stored anywhere), and a GitHub release
carrying the wheel and sdist.

Dependencies are updated by Dependabot with a one-week cooldown, and every
GitHub Action and base image is pinned to a commit SHA or digest.
