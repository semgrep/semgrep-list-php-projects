"""Command line: list the Semgrep projects that contain PHP.

argparse rather than a CLI framework: one command does not need one, and every
dependency is one more thing for the people running this to vet.

Results go to stdout and progress to stderr, so the output can be piped.

Exit codes: 0 the lookup ran (whether or not anything matched, and even if a
signal was skipped because its product is not enabled), 2 it could not run or
did not finish -- bad arguments, no token, or an API failure that survived
retries.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable, TypeVar

from . import __version__, api

EXIT_OK = 0
EXIT_USAGE = 2

SIGNALS = ("scans", "composer", "findings")
OUTPUT_FORMATS = ("text", "json", "csv")
# What an endpoint answers when the deployment does not have that product. Not
# yet measured against a deployment without Supply Chain; widen it if the live
# API turns out to use another status.
UNAVAILABLE_STATUSES = {403, 404}
# Requests in flight at once for the per-project scan lookups: a search and a
# scan read per project, so two requests each. Each is cheap, but for a large org
# tens of thousands arrive together; the cap keeps that from becoming a load
# spike. The findings walk is never parallel.
DEFAULT_CONCURRENCY = 4
MAX_CONCURRENCY = 8

T = TypeVar("T")
R = TypeVar("R")


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _signals(value: str) -> tuple[str, ...]:
    chosen = tuple(dict.fromkeys(v.strip().lower() for v in value.split(",") if v.strip()))
    unknown = [v for v in chosen if v not in SIGNALS]
    if not chosen or unknown:
        raise argparse.ArgumentTypeError(
            f"expected a comma-separated list of {', '.join(SIGNALS)}; got {value!r}"
        )
    return chosen


def _concurrency(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        number = 0
    if not 1 <= number <= MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(f"expected 1 to {MAX_CONCURRENCY}; got {value!r}")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="semgrep-list-php-projects",
        description="List the Semgrep projects that contain PHP.",
        epilog=f"The API token comes from ${api.TOKEN_ENV}, then "
               f"{api.DEFAULT_SETTINGS_FILE} (written by `semgrep login`), then a "
               "hidden prompt. It needs the Web API scope and is never accepted as "
               "an argument.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--signals", default=",".join(SIGNALS), type=_signals,
                        help="comma-separated: scans (PHP parsed in the latest full "
                             "Code scan), composer (Composer dependencies), findings "
                             "(Code findings in PHP files; only for projects the "
                             "others leave undecided) (default: scans,composer,findings)")
    parser.add_argument("--concurrency", type=_concurrency, default=DEFAULT_CONCURRENCY,
                        metavar="N",
                        help=f"parallel scan lookups, 1-{MAX_CONCURRENCY} "
                             f"(default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--format", dest="output", choices=OUTPUT_FORMATS, default="text",
                        help="text: one project name per line; json and csv add the "
                             "evidence per project (default: text)")
    parser.add_argument("--base-url", default=api.DEFAULT_BASE_URL,
                        help=f"Semgrep URL (default: {api.DEFAULT_BASE_URL})")
    return parser


def _parallel(
    fn: Callable[[T], R], items: Iterable[T], workers: int, label: str
) -> list[R]:
    """`fn` over `items` with at most `workers` in flight, results in input order.

    The first failure stops the run: a partial answer would look complete.
    """
    items = list(items)
    results: list[Any] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, item): index for index, item in enumerate(items)}
        for done, future in enumerate(as_completed(futures), start=1):
            results[futures[future]] = future.result()
            if done % 500 == 0 or done == len(items):
                _log(f"{label}: {done}/{len(items)}")
    return results


def scan_signal(
    deployment_id: int,
    token: str,
    projects: list[dict[str, Any]],
    args: argparse.Namespace,
) -> tuple[dict[str, int], set[str]]:
    """(PHP project -> PHP files parsed, every project the scans decided).

    A project is decided when its latest full scan reports per-language data:
    the answer is then yes or no, and the findings walk can skip it.
    """
    names = {int(p["id"]): str(p.get("name")) for p in projects if p.get("id") is not None}
    # One search per project: the API takes a single repository_id, and
    # refuses lists and deployment-wide searches (2026-10-21).
    found = _parallel(
        lambda repository_id: api.latest_full_scan(
            deployment_id, repository_id, token, base_url=args.base_url),
        names, args.concurrency, "scans: searched",
    )
    latest = {repo: scan for repo, scan in zip(names, found) if scan}
    _log(f"scans: {len(latest)} of {len(projects)} project(s) have a full Code scan "
         "in the last 30 days")

    repos = list(latest)
    all_stats = _parallel(
        lambda repo: api.scan_stats(deployment_id, latest[repo]["id"], token,
                                    base_url=args.base_url),
        repos, args.concurrency, "scans: stats read",
    )
    hits: dict[str, int] = {}
    decided: set[str] = set()
    fields: set[str] = set()
    for repo, stats in zip(repos, all_stats):
        languages = api.scan_languages(stats)
        if languages is None:
            fields.update(stats)
            continue
        decided.add(names[repo])
        if api.php_files(languages):
            hits[names[repo]] = api.php_files(languages)
    if repos and not decided:
        # Field names only -- they are Semgrep's schema, not customer data.
        _log("scans: warning: no scan reported per-language statistics, so this "
             "signal decided nothing; stats fields seen: "
             + (", ".join(sorted(fields)) or "none"))
    return hits, decided


def detect(
    projects: list[dict[str, Any]],
    results: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Merge the signals into one row per PHP project, sorted by name.

    A project is PHP when any signal says so. A project a signal reports but the
    listing does not (archived, or deleted since) is still included, with no id:
    dropping it would hide evidence.
    """
    ids = {str(p.get("name")): p.get("id") for p in projects}
    names = set().union(*results.values()) if results else set()
    rows = []
    for name in sorted(names):
        rows.append({
            "project": name,
            "id": ids.get(name),
            "signals": [s for s in SIGNALS if name in results.get(s, {})],
            "phpFilesParsed": results.get("scans", {}).get(name, 0),
            "composerDependencies": results.get("composer", {}).get(name, 0),
            "phpFindings": results.get("findings", {}).get(name, 0),
        })
    return rows


def _write(rows: list[dict[str, Any]], output: str, meta: dict[str, Any]) -> None:
    if output == "text":
        for row in rows:
            print(row["project"])
    elif output == "json":
        json.dump({**meta, "projects": rows}, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        writer = csv.writer(sys.stdout)
        writer.writerow(["project", "id", "signals", "php_files_parsed",
                         "composer_dependencies", "php_findings"])
        for row in rows:
            writer.writerow([row["project"], row["id"] if row["id"] is not None else "",
                             "+".join(row["signals"]), row["phpFilesParsed"],
                             row["composerDependencies"], row["phpFindings"]])


def run(args: argparse.Namespace) -> int:
    token = api.get_token()
    deployment = api.current_deployment(token, base_url=args.base_url)
    deployment_id, name = int(deployment["id"]), str(deployment["name"])

    projects = api.list_projects(deployment_id, token, base_url=args.base_url)
    _log(f"deployment {name}: {len(projects)} project(s)")

    results: dict[str, dict[str, int]] = {}
    skipped: dict[str, str] = {}
    # Projects whose answer is settled before the findings walk: a full scan
    # said yes or no, or Composer already said yes.
    decided: set[str] = set()
    walked = 0

    def run_signal(signal: str) -> None:
        nonlocal walked
        if signal == "scans":
            hits, by_scan = scan_signal(deployment_id, token, projects, args)
            decided.update(by_scan)
            results[signal] = hits
        elif signal == "composer":
            results[signal] = api.composer_repositories(
                deployment_id, token, base_url=args.base_url)
            decided.update(results[signal])
        else:
            undecided = [int(p["id"]) for p in projects
                         if p.get("id") is not None and str(p.get("name")) not in decided]
            walked = len(undecided)
            _log(f"findings: walking {walked} undecided project(s)")
            results[signal] = dict(api.php_issues(
                deployment_id, token, base_url=args.base_url, repository_ids=undecided,
                progress=lambda seen: _log(f"findings: {seen} read")))

    # Order matters: each signal narrows what the findings walk has to cover.
    for signal in [s for s in SIGNALS if s in args.signals]:
        # Not every deployment has every product: without Supply Chain the
        # dependency endpoint refuses. One missing product must not discard the
        # other signals' answers, so that is a warning. Anything else -- a walk
        # that died on page 250 after its retries -- would make the list look
        # complete when it is not, so it stops the run.
        try:
            run_signal(signal)
        except api.SemgrepError as exc:
            if exc.status not in UNAVAILABLE_STATUSES:
                raise
            skipped[signal] = str(exc)
            _log(f"{signal}: skipped, {exc}")
            continue
        _log(f"{signal}: {len(results[signal])} project(s) with PHP")
    if not results:
        raise api.SemgrepError("no signal could run; see the messages above")

    rows = detect(projects, results)
    _log(f"{len(rows)} of {len(projects)} project(s) contain PHP"
         + (f" (signals skipped: {', '.join(skipped)})" if skipped else ""))
    _write(rows, args.output, {
        "tool": f"semgrep-list-php-projects {__version__}",
        "deployment": name,
        "signals": list(results),
        "signalsSkipped": skipped,
        "projectsVisible": len(projects),
        "projectsWalkedForFindings": walked,
    })
    return EXIT_OK


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        code = run(args)
    except api.SemgrepError as exc:
        _log(f"error: {exc}")
        code = EXIT_USAGE
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)
