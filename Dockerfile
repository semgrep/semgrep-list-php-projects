# semgrep-list-php-projects: list the Semgrep projects that contain PHP.
#
# Base images are pinned by digest: a tag is mutable, and this image runs with a
# Semgrep API token in its environment.
#
# Deliberately NOT in this image: any token or key. At run time the semgrep
# settings file is mounted read-only, or SEMGREP_APP_TOKEN is forwarded by name
# (`-e SEMGREP_APP_TOKEN`, no value, so it never appears in `ps`). See the
# wrapper script, semgrep-list-php-projects.sh.

FROM python:3.12-slim@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17 AS build

COPY --from=ghcr.io/astral-sh/uv:0.11.17@sha256:03bdc89bb9798628846e60c3a9ad19006c8c3c724ccd2985a33145c039a0577b /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY semgrep_list_php_projects ./semgrep_list_php_projects

# --frozen installs exactly what uv.lock pins, and fails rather than re-resolving.
# The lock was resolved under `exclude-newer = "1 week"` (pyproject.toml), the
# org's package-manager cooldown; do not remove it to "fix" a resolution failure.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
RUN uv sync --frozen --no-dev --no-editable --no-cache

FROM python:3.12-slim@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17

LABEL org.opencontainers.image.title="semgrep-list-php-projects" \
      org.opencontainers.image.description="List the Semgrep projects that contain PHP" \
      org.opencontainers.image.vendor="Semgrep, Inc." \
      org.opencontainers.image.version="0.1.0"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /opt/venv /opt/venv

# Non-root. Nothing is written inside the container: results go to stdout.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin semgrep-list-php-projects
USER semgrep-list-php-projects

RUN semgrep-list-php-projects --version >/dev/null

ENTRYPOINT ["semgrep-list-php-projects"]
