"""Semgrep API tests.

No network: `_request` is patched, and each fake records what it was asked for.
"""

import pytest

from semgrep_list_php_projects import api as sg


def _pages(monkeypatch, pages):
    """Serve `pages` in order and record every call's keyword arguments."""
    it = iter(pages)
    calls = []

    def fake(url, token, method="GET", body=None, params=None, timeout=120.0):
        calls.append({"url": url, "method": method, "body": body, "params": params})
        return next(it)

    monkeypatch.setattr(sg, "_request", fake)
    return calls


def _finding(repo, path, rule="generic.rule"):
    return {"repository": {"name": repo}, "location": {"file_path": path},
            "rule": {"name": rule}}


class TestToken:
    """Order: settings file, then SEMGREP_APP_TOKEN, then a prompt."""

    def test_reads_the_settings_file_first(self, tmp_path):
        settings = tmp_path / "settings.yml"
        settings.write_text("anonymous_user_id: abc\napi_token: from_file\n")
        env = {"SEMGREP_APP_TOKEN": "from_env"}
        assert sg.get_token(env, settings_file=settings, interactive=False) == "from_file"

    def test_settings_file_path_comes_from_the_environment(self, tmp_path):
        settings = tmp_path / "elsewhere.yml"
        settings.write_text("api_token: from_file\n")
        env = {"SEMGREP_SETTINGS_FILE": str(settings)}
        assert sg.get_token(env, interactive=False) == "from_file"

    @pytest.mark.parametrize("line", [
        "api_token: 'quoted'", 'api_token: "quoted"', "  api_token:   quoted   ",
        "api_token: quoted  # a comment",
    ])
    def test_settings_file_value_is_unquoted_and_stripped(self, tmp_path, line):
        settings = tmp_path / "settings.yml"
        settings.write_text(f"other: x\n{line}\n")
        assert sg.settings_token(settings) == "quoted"

    @pytest.mark.parametrize("content", ["", "api_token:\n", "api_token: ''\n",
                                         "not_the_token: x\n", "def foo(): 5 == 5\n"])
    def test_settings_file_without_a_token(self, tmp_path, content):
        settings = tmp_path / "settings.yml"
        settings.write_text(content)
        assert sg.settings_token(settings) is None

    def test_falls_back_to_the_environment(self, tmp_path):
        missing = tmp_path / "absent.yml"
        env = {"SEMGREP_APP_TOKEN": " tok "}
        assert sg.get_token(env, settings_file=missing, interactive=False) == "tok"

    def test_prompts_on_a_terminal(self, tmp_path):
        prompts = []

        def fake_prompt(message):
            prompts.append(message)
            return " typed \n"

        token = sg.get_token({}, settings_file=tmp_path / "absent.yml",
                             prompt=fake_prompt, interactive=True)
        assert token == "typed"
        assert prompts and "hidden" in prompts[0]

    def test_blank_prompt_is_an_error(self, tmp_path):
        with pytest.raises(sg.SemgrepError, match="no token entered"):
            sg.get_token({}, settings_file=tmp_path / "absent.yml",
                         prompt=lambda _: "", interactive=True)

    def test_without_a_terminal_the_error_names_every_source(self, tmp_path):
        with pytest.raises(sg.SemgrepError) as excinfo:
            sg.get_token({}, settings_file=tmp_path / "absent.yml", interactive=False)
        message = str(excinfo.value)
        assert "absent.yml" in message
        assert "SEMGREP_APP_TOKEN" in message
        assert "semgrep login" in message
        assert "never accepted as a command-line argument" in message


class TestTokenNeverLeaks:
    def test_http_error_message_excludes_the_token(self, monkeypatch):
        import urllib.error

        secret = "sg_supersecrettoken"

        def boom(*args, **kwargs):
            raise urllib.error.HTTPError("https://semgrep.dev/x", 401, "Unauthorized", {}, None)

        monkeypatch.setattr("urllib.request.urlopen", boom)
        with pytest.raises(sg.SemgrepError) as excinfo:
            sg._request("https://semgrep.dev/x", secret)
        assert secret not in str(excinfo.value)
        # A CI token is the usual cause; the message should point at the scope.
        assert "Web API scope" in str(excinfo.value)


class TestDeployment:
    def test_returns_the_single_deployment(self, monkeypatch):
        _pages(monkeypatch, [{"deployments": [{"id": 1234, "slug": "acme", "name": "Acme"}]}])
        assert sg.current_deployment("tok")["slug"] == "acme"

    @pytest.mark.parametrize("response", [
        {}, {"deployments": []}, {"deployments": [{"id": 1}]},
        {"deployments": [{"id": 1, "slug": "a"}, {"id": 2, "slug": "b"}]},
    ])
    def test_anything_but_one_complete_deployment_is_an_error(self, monkeypatch, response):
        _pages(monkeypatch, [response])
        with pytest.raises(sg.SemgrepError, match="exactly one deployment"):
            sg.current_deployment("tok")


class TestListProjects:
    def test_pages_until_a_short_page(self, monkeypatch):
        full = [{"id": i, "name": f"acme/r{i}"} for i in range(sg.PROJECTS_PAGE_SIZE)]
        calls = _pages(monkeypatch, [{"projects": full}, {"projects": [{"id": 999, "name": "x"}]}])
        assert len(sg.list_projects("acme", "tok")) == sg.PROJECTS_PAGE_SIZE + 1
        assert [c["params"]["page"] for c in calls] == [0, 1]

    def test_slug_is_url_quoted(self, monkeypatch):
        calls = _pages(monkeypatch, [{"projects": []}])
        sg.list_projects("a/b", "tok")
        assert "/deployments/a%2Fb/projects" in calls[0]["url"]


class TestComposer:
    def test_filters_on_the_composer_ecosystem(self, monkeypatch):
        calls = _pages(monkeypatch, [{"repositorySummaries": [], "hasMore": False}])
        sg.composer_repositories(1234, "tok")
        assert calls[0]["method"] == "POST"
        assert calls[0]["url"].endswith("/api/v1/deployments/1234/dependencies/repositories")
        assert calls[0]["body"]["dependencyFilter"] == {"ecosystem": ["composer"]}
        assert "cursor" not in calls[0]["body"]

    def test_follows_the_cursor(self, monkeypatch):
        calls = _pages(monkeypatch, [
            {"repositorySummaries": [{"name": "acme/a", "numDependencies": 3}],
             "hasMore": True, "cursor": 7},
            {"repositorySummaries": [{"name": "acme/b", "numDependencies": 1}],
             "hasMore": False},
        ])
        assert sg.composer_repositories(1, "tok") == {"acme/a": 3, "acme/b": 1}
        assert calls[1]["body"]["cursor"] == 7

    def test_a_repeated_cursor_stops_instead_of_looping(self, monkeypatch):
        page = {"repositorySummaries": [], "hasMore": True, "cursor": 7}
        _pages(monkeypatch, [page, page, AssertionError("looped")])
        assert sg.composer_repositories(1, "tok") == {}

    def test_zero_matching_dependencies_is_not_php(self, monkeypatch):
        _pages(monkeypatch, [{"repositorySummaries": [
            {"name": "acme/php", "numDependencies": 4},
            {"name": "acme/empty", "numDependencies": 0},
        ], "hasMore": False}])
        assert sg.composer_repositories(1, "tok") == {"acme/php": 4}


class TestIsPhpFinding:
    @pytest.mark.parametrize("path", [
        "src/index.php", "views/page.PHTML", "legacy/old.php5", "a/b.phps",
    ])
    def test_php_extensions(self, path):
        assert sg.is_php_finding(_finding("r", path))

    @pytest.mark.parametrize("path", [
        "src/app.py", "include/config.inc", "php/readme.md", "notphp", "",
    ])
    def test_other_files_are_not_php(self, path):
        assert not sg.is_php_finding(_finding("r", path))

    def test_a_php_rule_counts_whatever_the_extension(self):
        assert sg.is_php_finding(_finding("r", "templates/x.tpl",
                                          "php.lang.security.eval-use.eval-use"))

    def test_missing_location_and_rule_are_tolerated(self):
        assert not sg.is_php_finding({})


class TestPhpFindings:
    def test_counts_php_findings_per_project(self, monkeypatch):
        _pages(monkeypatch, [{"findings": [
            _finding("acme/web", "index.php"),
            _finding("acme/web", "lib/db.php"),
            _finding("acme/api", "main.go"),
            _finding("acme/cms", "x.tpl", "php.lang.security.injection.tainted-sql"),
        ]}])
        assert sg.php_findings("acme", "tok") == {"acme/web": 2, "acme/cms": 1}

    def test_requests_deduplicated_code_findings_at_the_maximum_page_size(self, monkeypatch):
        calls = _pages(monkeypatch, [{"findings": []}])
        sg.php_findings("acme", "tok")
        params = calls[0]["params"]
        assert params["issue_type"] == "sast"
        assert params["dedup"] == "true"
        assert params["page_size"] == 3000

    def test_pages_until_a_short_page(self, monkeypatch):
        full = [_finding("acme/web", "a.py")] * sg.FINDINGS_PAGE_SIZE
        calls = _pages(monkeypatch, [{"findings": full},
                                     {"findings": [_finding("acme/web", "a.php")]}])
        seen = []
        assert sg.php_findings("acme", "tok", progress=seen.append) == {"acme/web": 1}
        assert [c["params"]["page"] for c in calls] == [0, 1]
        assert seen == [sg.FINDINGS_PAGE_SIZE, sg.FINDINGS_PAGE_SIZE + 1]

    def test_accepts_the_nested_shape_from_the_spec(self, monkeypatch):
        _pages(monkeypatch, [{"sastFindings": {"findings": [_finding("acme/web", "a.php")]}}])
        assert sg.php_findings("acme", "tok") == {"acme/web": 1}


class TestRetries:
    """A large org's findings walk is hundreds of requests; one blip must not end it."""

    def _urlopen(self, monkeypatch, outcomes):
        import contextlib
        import io
        import urllib.error

        it = iter(outcomes)
        calls = []

        @contextlib.contextmanager
        def fake_urlopen(request, timeout=None):
            calls.append(request)
            outcome = next(it)
            if isinstance(outcome, int):
                headers = {"Retry-After": "7"} if outcome == 429 else {}
                raise urllib.error.HTTPError(request.full_url, outcome, "err", headers, None)
            if isinstance(outcome, BaseException):
                raise outcome
            yield io.BytesIO(outcome)

        monkeypatch.setattr(sg.urllib.request, "urlopen", fake_urlopen)
        return calls

    def test_retries_rate_limits_and_server_errors(self, monkeypatch):
        import urllib.error
        calls = self._urlopen(monkeypatch, [
            502, 429, urllib.error.URLError("reset"), TimeoutError(), b'{"ok": 1}'])
        slept = []
        assert sg._request("https://x/y", "tok", sleep=slept.append) == {"ok": 1}
        assert len(calls) == 5
        assert slept[1] == 7.0, "Retry-After is honoured"
        assert all(d <= sg.RETRY_MAX_DELAY for d in slept)

    def test_gives_up_after_max_attempts_with_the_status(self, monkeypatch):
        self._urlopen(monkeypatch, [503] * sg.MAX_ATTEMPTS)
        with pytest.raises(sg.SemgrepError, match="after 6 attempts: HTTP 503") as excinfo:
            sg._request("https://x/y", "tok", sleep=lambda _: None)
        assert excinfo.value.status == 503

    @pytest.mark.parametrize("status", [400, 401, 403, 404])
    def test_client_errors_are_not_retried(self, monkeypatch, status):
        calls = self._urlopen(monkeypatch, [status])
        with pytest.raises(sg.SemgrepError) as excinfo:
            sg._request("https://x/y", "tok", sleep=lambda _: None)
        assert len(calls) == 1
        assert excinfo.value.status == status

    def test_the_token_survives_retries_unlogged(self, monkeypatch):
        self._urlopen(monkeypatch, [500] * sg.MAX_ATTEMPTS)
        with pytest.raises(sg.SemgrepError) as excinfo:
            sg._request("https://x/y", "sg_secret", sleep=lambda _: None)
        assert "sg_secret" not in str(excinfo.value)


class TestFindingsBatching:
    def test_an_empty_id_list_makes_no_request(self, monkeypatch):
        calls = _pages(monkeypatch, [])
        assert sg.php_findings("acme", "tok", repository_ids=[]) == {}
        assert calls == []

    def test_ids_are_queried_in_batches(self, monkeypatch):
        ids = list(range(sg.FINDINGS_REPOSITORY_BATCH * 2 + 1))
        calls = _pages(monkeypatch, [{"findings": []}] * 3)
        sg.php_findings("acme", "tok", repository_ids=ids)
        assert [len(c["params"]["repository_ids"]) for c in calls] == [
            sg.FINDINGS_REPOSITORY_BATCH, sg.FINDINGS_REPOSITORY_BATCH, 1]
        assert all(c["params"]["page"] == 0 for c in calls)

    def test_each_batch_pages_independently(self, monkeypatch):
        full = [_finding("acme/a", "a.php")] * sg.FINDINGS_PAGE_SIZE
        ids = list(range(sg.FINDINGS_REPOSITORY_BATCH + 1))
        calls = _pages(monkeypatch, [{"findings": full}, {"findings": []},
                                     {"findings": [_finding("acme/b", "b.php")]}])
        counts = sg.php_findings("acme", "tok", repository_ids=ids)
        assert [c["params"]["page"] for c in calls] == [0, 1, 0]
        assert counts == {"acme/a": sg.FINDINGS_PAGE_SIZE, "acme/b": 1}


class TestLatestFullScan:
    def test_asks_for_one_completed_full_code_scan_of_one_repository(self, monkeypatch):
        calls = _pages(monkeypatch, [{"scans": []}])
        sg.latest_full_scan(1234, 7, "tok")
        body = calls[0]["body"]
        assert calls[0]["url"].endswith("/api/v1/deployments/1234/scans/search")
        # The live API refuses a list here, and refuses a search without one.
        assert body["repository_id"] == 7
        assert body["is_full_scan"] is True, "the live API rejects the spec's integer"
        assert body["is_partial_scan"] is False
        assert body["statuses"] == ["SCAN_STATUS_COMPLETED"]
        assert body["products"] == ["PRODUCT_SAST"]
        # Results are newest first (measured live), so one is enough.
        assert body["limit"] == 1

    def test_returns_the_scan(self, monkeypatch):
        _pages(monkeypatch, [{"scans": [{"id": "3", "repository_id": "7"}], "cursor": "c"}])
        assert sg.latest_full_scan(1, 7, "tok")["id"] == "3"

    def test_none_without_a_recent_full_scan(self, monkeypatch):
        _pages(monkeypatch, [{"scans": []}])
        assert sg.latest_full_scan(1, 7, "tok") is None

    def test_makes_exactly_one_request_even_with_a_cursor(self, monkeypatch):
        calls = _pages(monkeypatch, [{"scans": [{"id": "3"}], "cursor": "more"}])
        sg.latest_full_scan(1, 7, "tok")
        assert len(calls) == 1


class TestScanLanguages:
    # Shape measured on the live API, 2026-10-21.
    LIVE = {"engine_requested": "PRO", "errors": [], "findings": 3,
            "findings_by_product": {}, "lockfile_scan_info": {}, "total_time": 12.5,
            "unsupported_exts": {},
            "parse_rate": {"html": {"bytes_parsed": 10, "num_bytes": 10,
                                    "num_targets": 2, "targets_parsed": 2},
                           "php": {"bytes_parsed": 900, "num_bytes": 1000,
                                   "num_targets": 31, "targets_parsed": 30}}}

    def test_reads_the_live_shape(self):
        assert sg.php_files(sg.scan_languages(self.LIVE)) == 31

    def test_reads_semgrep_ci_parse_rate(self):
        stats = {"parse_rate": {"PHP": {"num_targets": 12, "targets_parsed": 11},
                                "python": {"num_targets": 3}}}
        languages = sg.scan_languages(stats)
        assert languages == {"php": 12, "python": 3}
        assert sg.php_files(languages) == 12

    def test_camel_case_spelling(self):
        assert sg.scan_languages({"parseRate": {"php": {"numTargets": 4}}}) == {"php": 4}

    def test_a_listed_language_without_a_count_still_counts(self):
        assert sg.php_files(sg.scan_languages({"parse_rate": {"php": 0.98}})) == 1

    def test_zero_php_targets_is_no_php(self):
        assert sg.php_files(sg.scan_languages({"parse_rate": {"php": {"num_targets": 0}}})) == 0

    def test_no_language_data_is_none_not_no_php(self):
        # "Says nothing" must stay distinct from "no PHP": the first leaves the
        # project to the other signals, the second settles it.
        assert sg.scan_languages({"findings": 5, "total_time": 100}) is None
        assert sg.scan_languages({}) is None

    def test_scan_stats_returns_only_the_stats_object(self, monkeypatch):
        calls = _pages(monkeypatch, [{"id": 5, "stats": {"parse_rate": {}}}])
        assert sg.scan_stats(1234, "5", "tok") == {"parse_rate": {}}
        assert calls[0]["url"].endswith("/api/v1/deployments/1234/scan/5")

    def test_scan_stats_tolerates_a_missing_object(self, monkeypatch):
        _pages(monkeypatch, [{"id": 5}])
        assert sg.scan_stats(1, "5", "tok") == {}
