"""Semgrep API v2: which projects contain PHP.

Written against the v2 OpenAPI spec (semgrep.dev/api/v2/openapi.yaml) and
checked against the live API on 2026-10-21. Nothing in v2 says what languages a
project contains: not the project (`protos.projects.v2.Project`), not the
branch, and not the scan (`protos.scan.v2.Scan` carries findings counts and
enabled products, but no per-language parse statistics). So PHP is detected
from three signals, most direct first. The first still needs two v1 endpoints,
because only the v1 scan object carries per-language statistics:

    scans      POST /api/v1/deployments/{id}/scans/search  (full, Code, completed)
               GET  /api/v1/deployments/{id}/scan/{scanId}
               -> per-language parse statistics from each project's latest full
               Code scan: did Semgrep parse PHP files in this repository? A full
               scan, because a diff scan only sees the files a change touched.
               `stats.parse_rate` maps language ids (`php`, `python`, ...) to
               {num_targets, targets_parsed, num_bytes, bytes_parsed}. The
               search takes one repository_id (the v2 project id works) and
               returns newest first, so this is two small requests per project.
               Covers only projects with a full scan in the last 30 days, the
               search endpoint's window. This is the one signal that can say
               "no PHP" with confidence, which spares the findings walk.

    composer   POST /api/sca/deployments/{id}/repositories
               with dependencyFilter.ecosystem = ["composer"]
               -> projects whose Supply Chain scan found Composer packages.
               One cheap, paginated call. Misses PHP with no composer.lock, and
               projects that are not scanned with Supply Chain.

    findings   POST /api/agent/deployments/{id}/issues
               with issueTypes = ["ISSUE_TYPE_SAST"]
               -> projects with at least one Code finding in a PHP file, or
               from a `php.*` rule. Cursor-paginated over large pages, so it
               is the expensive one: it runs only for the projects the other
               signals left undecided, filtered to their ids in batches so no
               query pages deep into the whole deployment's findings. The
               endpoint insists on a branch filter; `onPrimaryBranch` keeps it
               to each project's default branch. Every status is included
               (open, fixed, ignored, removed): a finding that was once in a
               PHP file is still evidence the project contains PHP.

               The filter's `filePaths` field is not used. It is a fuzzy
               text search with typo tolerance, and measured on 2026-10-21 it
               is silently ignored whenever a `status` filter is also set: a
               nonsense term then returned every finding in the deployment.
               The file extension is checked here instead.

Not every customer has Supply Chain, so the CLI treats a signal whose product is
not enabled as a warning and answers from the others.

Every endpoint takes the Web API token (`SemgrepWebToken` in the spec). The
token `semgrep login` stores has that scope; a CI-only (`agent_cli`) token gets
401. The token comes from SEMGREP_APP_TOKEN, then the semgrep settings file,
then a hidden prompt: see `resolve_token`.

Uses stdlib urllib rather than a HTTP client library, and a line scan rather
than a YAML parser for the settings file: this runs with an API token, so every
dependency it carries is one more thing to vet. The token is never logged,
never included in an exception message, and never written to disk.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Callable, Iterable

DEFAULT_BASE_URL = "https://semgrep.dev"
TOKEN_ENV = "SEMGREP_APP_TOKEN"
# Where `semgrep login` stores its token. SEMGREP_SETTINGS_FILE overrides the
# path, as it does for the semgrep CLI itself.
SETTINGS_FILE_ENV = "SEMGREP_SETTINGS_FILE"
DEFAULT_SETTINGS_FILE = "~/.semgrep/settings.yml"
# `api_token: value`, optionally quoted, optionally followed by a comment. The
# file is flat YAML, so a line scan is enough and keeps the dependency list empty.
_SETTINGS_TOKEN_LINE = re.compile(r"""^\s*api_token\s*:\s*['"]?([^'"#\s]+)['"]?\s*(?:#.*)?$""")

# `.php` alone misses templates and the older extensions that are still served
# as PHP by default Apache and nginx configs. `.inc` is deliberately absent: C,
# Pascal and assembly use it too, and a false positive here is a wrong answer.
PHP_EXTENSIONS = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps")
COMPOSER = "composer"

ISSUE_TYPE_CODE = "ISSUE_TYPE_SAST"
# Every scan-controlled status the API defines. The default is narrower.
ISSUE_STATUSES = ("ISSUE_STATUS_UNRESOLVED", "ISSUE_STATUS_FIXED",
                  "ISSUE_STATUS_MUTED", "ISSUE_STATUS_REMOVED")
ISSUES_PAGE_SIZE = 3000  # the documented maximum
# Project ids per issues query. Bounds how deep any one query's pagination goes.
ISSUES_REPOSITORY_BATCH = 100
REPOSITORIES_PAGE_SIZE = 100  # the API maximum
PROJECTS_PAGE_SIZE = 3000  # the API maximum
# A runaway pagination loop (an API that keeps returning the same page) would
# otherwise spin forever with a token in the environment.
MAX_PAGES = 10_000


class SemgrepError(RuntimeError):
    """The lookup could not be completed. Never carries the token.

    `status` is the HTTP status when the API answered with an error, so callers
    can tell "this product is not enabled" from "the request broke".
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# A large org's findings walk is hundreds of multi-megabyte requests; one
# transient failure must not end it. Only failures that a retry can fix are
# retried. Every request here is a read, so retrying a POST is safe too.
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 6
RETRY_BASE_DELAY = 2.0
RETRY_MAX_DELAY = 60.0


def settings_token(path: str | os.PathLike[str]) -> str | None:
    """The `api_token` in a semgrep settings file, or None when there is none."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as handle:
            for line in handle:
                match = _SETTINGS_TOKEN_LINE.match(line)
                if match:
                    return match.group(1)
    except OSError:
        return None
    return None


def settings_file_path(env: dict[str, str] | None = None) -> str:
    env = env if env is not None else os.environ
    return env.get(SETTINGS_FILE_ENV) or DEFAULT_SETTINGS_FILE


# Where the token came from. The CLI reports it, because which org a run
# queries depends on it, and because a `semgrep login` token is not granted
# Web API access on every deployment (measured 2026-10-21: the same login token
# gets 200 on one deployment's v1 endpoints and 404 on another's, where a
# token created with the Web API scope gets 200).
SOURCE_SETTINGS = "settings"
SOURCE_ENV = "environment"
SOURCE_PROMPT = "prompt"


def resolve_token(
    env: dict[str, str] | None = None,
    settings_file: str | os.PathLike[str] | None = None,
    prompt: Callable[[str], str] | None = None,
    interactive: bool | None = None,
) -> tuple[str, str]:
    """(token, source), from the first of these that has one:

    1. the SEMGREP_APP_TOKEN environment variable;
    2. the semgrep CLI's settings file, `~/.semgrep/settings.yml`, which
       `semgrep login` writes (SEMGREP_SETTINGS_FILE overrides the path);
    3. a prompt on the terminal, with input hidden.

    The environment wins, as is usual, so a token exported for one run
    overrides a login without touching the settings file.

    Without a terminal there is nothing to prompt, so that is an error. The
    token is never accepted as a command-line argument: it would land in shell
    history and `ps`.

    `settings_file`, `prompt` and `interactive` exist for tests.
    """
    env = env if env is not None else os.environ
    token = (env.get(TOKEN_ENV) or "").strip()
    if token:
        return token, SOURCE_ENV
    if settings_file is None:
        settings_file = settings_file_path(env)
    token = settings_token(settings_file)
    if token:
        return token, SOURCE_SETTINGS
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        raise SemgrepError(
            f"no API token found: {TOKEN_ENV} is not set and {settings_file} has "
            "no api_token. Export a token with the Web API scope, or run "
            "`semgrep login`. It is never accepted as a command-line argument."
        )
    # getpass reads from the terminal, not stdin, and hides the input, so this
    # works even when stdout is redirected to a file.
    token = (prompt or getpass.getpass)("Semgrep API token (Web API scope; hidden): ").strip()
    if not token:
        raise SemgrepError("no token entered")
    return token, SOURCE_PROMPT


def get_token(
    env: dict[str, str] | None = None,
    settings_file: str | os.PathLike[str] | None = None,
    prompt: Callable[[str], str] | None = None,
    interactive: bool | None = None,
) -> str:
    """The token alone; see `resolve_token`."""
    return resolve_token(env, settings_file, prompt, interactive)[0]


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), RETRY_MAX_DELAY)
        except ValueError:
            pass  # an HTTP date; fall back to backoff
    return min(RETRY_BASE_DELAY * 2 ** attempt, RETRY_MAX_DELAY)


def _request(
    url: str,
    token: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 180.0,
    sleep=time.sleep,
) -> dict[str, Any]:
    """One API call, retried on rate limits, 5xx, timeouts and dropped connections.

    `sleep` is injectable so tests exercise the backoff without waiting.
    """
    if params:
        url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    for attempt in range(MAX_ATTEMPTS):
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        last = attempt == MAX_ATTEMPTS - 1

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read().decode("utf-8")
            break
        except urllib.error.HTTPError as exc:
            if exc.code in RETRY_STATUSES and not last:
                sleep(_retry_delay(attempt, exc.headers.get("Retry-After") if exc.headers else None))
                continue
            # Read the body for context, but keep it short -- it may echo request
            # detail, and this string can end up in CI logs.
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:  # noqa: BLE001 - best effort only
                detail = ""
            hint = ""
            if exc.code == 401:
                hint = (" (the token was not accepted: it needs the Web API scope, "
                        "which a CI-only token does not have)")
            elif exc.code == 403:
                hint = (" (the token is not permitted to use this endpoint: it needs "
                        "the Web API scope on this deployment)")
            tries = f" after {attempt + 1} attempts" if attempt else ""
            raise SemgrepError(
                f"{method} {url} failed{tries}: HTTP {exc.code}{hint} {detail}",
                status=exc.code,
            ) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            if not last:
                sleep(_retry_delay(attempt, None))
                continue
            reason = getattr(exc, "reason", exc)
            raise SemgrepError(
                f"{method} {url} failed after {attempt + 1} attempts: {reason}") from exc

    if not payload.strip():
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"{method} {url} returned unparseable JSON: {exc}") from exc


def current_deployment(token: str, base_url: str = DEFAULT_BASE_URL) -> dict[str, Any]:
    """The deployment this token acts on: its numeric `id` and `name`.

    GET /api/v2/deployments. A token belongs to exactly one deployment, so the
    deployment is never a flag.
    """
    response = _request(f"{base_url}/api/v2/deployments", token)
    deployments = response.get("deployments") or []
    if len(deployments) != 1 or not deployments[0].get("id") or not deployments[0].get("name"):
        raise SemgrepError(
            f"expected exactly one deployment for this token, got {len(deployments)}; "
            f"check that the token is valid"
        )
    deployment = deployments[0]
    return {"id": int(deployment["id"]), "name": str(deployment["name"])}


def list_projects(
    deployment_id: int, token: str, base_url: str = DEFAULT_BASE_URL
) -> list[dict[str, Any]]:
    """Every non-archived project in the deployment, each with `id` and `name`.

    POST /api/v2/deployments/{id}/projects/list, following `pageToken` until
    it comes back empty. Ids are strings on the wire (int64) and ints here.
    """
    url = f"{base_url}/api/v2/deployments/{deployment_id}/projects/list"
    projects: list[dict[str, Any]] = []
    page_token = ""
    for _ in range(MAX_PAGES):
        body: dict[str, Any] = {"pageSize": PROJECTS_PAGE_SIZE}
        if page_token:
            body["pageToken"] = page_token
        response = _request(url, token, method="POST", body=body)
        for project in response.get("projects") or []:
            if project.get("isSemgrepArchived") or project.get("id") in (None, ""):
                continue
            projects.append({"id": int(project["id"]), "name": str(project.get("name") or "")})
        next_token = str(response.get("pageToken") or "")
        if not next_token or next_token == page_token:
            return projects
        page_token = next_token
    raise SemgrepError(f"project listing did not end after {MAX_PAGES} pages")


def composer_repositories(
    deployment_id: int, token: str, base_url: str = DEFAULT_BASE_URL
) -> dict[str, int]:
    """Project name -> number of Composer dependencies, for every project that has any."""
    url = f"{base_url}/api/sca/deployments/{deployment_id}/repositories"
    found: dict[str, int] = {}
    cursor: int | None = None
    for _ in range(MAX_PAGES):
        body: dict[str, Any] = {
            "deploymentId": str(deployment_id),
            "pageSize": REPOSITORIES_PAGE_SIZE,
            "dependencyFilter": {"ecosystem": [COMPOSER]},
        }
        if cursor is not None:
            body["cursor"] = cursor
        response = _request(url, token, method="POST", body=body)
        for summary in response.get("repositorySummaries") or []:
            name = str(summary.get("name") or "").strip()
            # The filter narrows the dependency count, not only the repository
            # list -- a summary with zero matching dependencies is not PHP.
            count = int(summary.get("numDependencies") or 0)
            if name and count:
                found[name] = count
        next_cursor = response.get("cursor")
        if not response.get("hasMore") or next_cursor in (None, cursor):
            return found
        cursor = int(next_cursor)
    raise SemgrepError(f"dependency repository listing did not end after {MAX_PAGES} pages")


def is_php_issue(issue: dict[str, Any]) -> bool:
    """True when a Code issue is in a PHP file, or comes from a PHP rule.

    The rule check covers PHP embedded in files with other extensions; registry
    rule paths start with their language (`php.lang.security...`).
    """
    path = str(issue.get("filePath") or "").lower()
    if path.endswith(PHP_EXTENSIONS):
        return True
    rule = str(issue.get("rulePath") or issue.get("ruleId") or "")
    return rule.startswith("php.")


def php_issues(
    deployment_id: int,
    token: str,
    base_url: str = DEFAULT_BASE_URL,
    repository_ids: Iterable[int] | None = None,
    progress=None,
) -> Counter[str]:
    """Project name -> number of Code issues in PHP, for every project with any.

    `repository_ids=None` walks the whole deployment; a list restricts the walk
    to those projects, queried in batches of ISSUES_REPOSITORY_BATCH. An empty
    list makes no request at all.

    Only the project name is kept from each issue. Code snippets, messages and
    file paths are customer data and never leave this function.
    """
    url = f"{base_url}/api/agent/deployments/{deployment_id}/issues"
    base_filter: dict[str, Any] = {"onPrimaryBranch": True, "status": list(ISSUE_STATUSES)}
    if repository_ids is None:
        filters: list[dict[str, Any]] = [base_filter]
    else:
        ids = list(dict.fromkeys(str(int(i)) for i in repository_ids))
        filters = [{**base_filter, "repositoryIds": ids[i:i + ISSUES_REPOSITORY_BATCH]}
                   for i in range(0, len(ids), ISSUES_REPOSITORY_BATCH)]

    counts: Counter[str] = Counter()
    seen = 0
    for batch_filter in filters:
        cursor = ""
        for _ in range(MAX_PAGES):
            body: dict[str, Any] = {
                "deploymentId": str(deployment_id),
                "issueTypes": [ISSUE_TYPE_CODE],
                "limit": ISSUES_PAGE_SIZE,
                "filter": batch_filter,
            }
            if cursor:
                body["cursor"] = cursor
            response = _request(url, token, method="POST", body=body)
            page = response.get("issues") or []
            for summary in page:
                issue = summary.get("issue") or summary
                if is_php_issue(issue):
                    name = str((issue.get("repository") or {}).get("name") or "").strip()
                    if name:
                        counts[name] += 1
            seen += len(page)
            if progress:
                progress(seen)
            next_cursor = str(response.get("cursor") or "")
            if not page or not next_cursor or next_cursor == cursor:
                break
            cursor = next_cursor
        else:
            raise SemgrepError(f"issue listing did not end after {MAX_PAGES} pages")
    return counts


# scans: the v1 endpoints, kept because v2 has no per-language statistics.

def latest_full_scan(
    deployment_id: int,
    repository_id: int,
    token: str,
    base_url: str = DEFAULT_BASE_URL,
) -> dict[str, Any] | None:
    """A project's most recent completed, full, Code scan in the last 30 days.

    Partial scans are excluded: a Supply Chain incident scan covers the whole
    repository but runs only that incident's rules, so its statistics describe
    a fraction of the code.

    Measured on the live API, 2026-10-21: the search takes exactly one integer
    `repository_id` -- no list, no deployment-wide search -- and returns scans
    newest first, so `limit: 1` is the newest scan and one request suffices.
    """
    response = _request(
        f"{base_url}/api/v1/deployments/{deployment_id}/scans/search", token,
        method="POST",
        body={
            "deploymentId": str(deployment_id),
            "repository_id": int(repository_id),
            # The spec types this as an integer; the live API rejects 1 with
            # "Expected true or false". It is a boolean.
            "is_full_scan": True,
            "is_partial_scan": False,
            "statuses": ["SCAN_STATUS_COMPLETED"],
            "products": ["PRODUCT_SAST"],
            "limit": 1,
        },
    )
    scans = [s for s in response.get("scans") or [] if s.get("id") not in (None, "")]
    return scans[0] if scans else None


def scan_stats(
    deployment_id: int, scan_id: int | str, token: str, base_url: str = DEFAULT_BASE_URL
) -> dict[str, Any]:
    """The `stats` object of one scan; empty when the scan has none."""
    response = _request(f"{base_url}/api/v1/deployments/{deployment_id}/scan/{scan_id}", token)
    stats = response.get("stats")
    return stats if isinstance(stats, dict) else {}


# Where `semgrep ci` reports per-language parsing, and the per-language counts
# it uses. The live API uses the snake_case names (2026-10-21); the camelCase
# ones are kept so a protobuf JSON re-encoding degrades rather than breaks.
_PARSE_RATE_KEYS = ("parse_rate", "parseRate")
_TARGET_COUNT_KEYS = ("num_targets", "numTargets", "targets_parsed", "targetsParsed")


def scan_languages(stats: dict[str, Any]) -> dict[str, int] | None:
    """Language -> number of files of that language the scan targeted.

    None when the stats carry no per-language data at all, which is different
    from "no PHP": the scan says nothing either way, so the project stays
    undecided and falls through to the other signals.
    """
    for key in _PARSE_RATE_KEYS:
        rates = stats.get(key)
        if isinstance(rates, dict):
            break
    else:
        return None
    languages: dict[str, int] = {}
    for language, rate in rates.items():
        count = None
        if isinstance(rate, dict):
            for count_key in _TARGET_COUNT_KEYS:
                if isinstance(rate.get(count_key), (int, float)):
                    count = int(rate[count_key])
                    break
        # A language listed with no recognisable count was still targeted.
        languages[str(language).lower()] = count if count is not None else 1
    return languages


def php_files(languages: dict[str, int]) -> int:
    return languages.get("php", 0)
