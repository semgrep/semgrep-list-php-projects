#!/bin/sh
# Run semgrep-list-php-projects in Docker.
#
#   ./semgrep-list-php-projects.sh > php-projects.txt
#   ./semgrep-list-php-projects.sh --format json
#
# The token comes from the first of these that has one:
#   1. $SEMGREP_APP_TOKEN, forwarded by name so it never appears on a command
#      line where `ps` would show it,
#   2. ~/.semgrep/settings.yml, written by `semgrep login` (mounted read-only;
#      SEMGREP_SETTINGS_FILE overrides the path),
#   3. a hidden prompt, when run from a terminal.
#
# The container needs no other filesystem access: results go to stdout.
# SEMGREP_LIST_PHP_PROJECTS_IMAGE overrides the image, e.g. one built locally.
set -eu

IMAGE="${SEMGREP_LIST_PHP_PROJECTS_IMAGE:-ghcr.io/semgrep/semgrep-list-php-projects:0.1.0}"
SETTINGS="${SEMGREP_SETTINGS_FILE:-$HOME/.semgrep/settings.yml}"
MOUNTED=/run/semgrep/settings.yml

# The image goes before the user's arguments; docker options go before the image.
set -- "$IMAGE" "$@"

if [ -n "${SEMGREP_APP_TOKEN:-}" ]; then
  : # forwarded by name below; the settings file is not mounted
elif [ -f "$SETTINGS" ] && grep -Eq '^[[:space:]]*api_token[[:space:]]*:[[:space:]]*[^[:space:]#]' "$SETTINGS"; then
  set -- -v "$SETTINGS:$MOUNTED:ro" -e "SEMGREP_SETTINGS_FILE=$MOUNTED" "$@"
else
  if [ ! -t 0 ]; then
    echo "semgrep-list-php-projects: no API token: SEMGREP_APP_TOKEN is not set and" \
         "$SETTINGS has no api_token. Export a token with the Web API scope, or" \
         "run 'semgrep login'." >&2
    exit 2
  fi
  # The container's stdin is a pipe, so the prompt happens here. The token goes
  # into the environment and is forwarded by name, never onto a command line.
  printf 'Semgrep API token (Web API scope; hidden): ' >&2
  stty -echo
  trap 'stty echo' EXIT INT TERM
  read -r SEMGREP_APP_TOKEN
  stty echo
  trap - EXIT INT TERM
  echo >&2
  if [ -z "$SEMGREP_APP_TOKEN" ]; then
    echo "semgrep-list-php-projects: no token entered" >&2
    exit 2
  fi
  export SEMGREP_APP_TOKEN
fi

exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e SEMGREP_APP_TOKEN \
  "$@"
