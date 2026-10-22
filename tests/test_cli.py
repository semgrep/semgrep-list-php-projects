"""CLI tests: argument parsing, signal ordering and merging, and output. No network."""

import csv
import io
import json

import pytest

from semgrep_list_php_projects import api, cli

PROJECTS = [{"id": 1, "name": "acme/web"}, {"id": 2, "name": "acme/cms"},
            {"id": 3, "name": "acme/api"}, {"id": 4, "name": "acme/old"}]


def php_stats(files):
    return {"parse_rate": {"php": {"num_targets": files}, "python": {"num_targets": 9}}}


class TestArguments:
    def test_default_is_every_signal(self):
        assert cli.build_parser().parse_args([]).signals == ("scans", "composer", "findings")

    def test_signals_are_deduplicated_and_lowercased(self):
        assert cli._signals("Composer, composer") == ("composer",)

    @pytest.mark.parametrize("value", ["", "npm", "composer,npm"])
    def test_rejects_unknown_signals(self, value):
        with pytest.raises(Exception):
            cli._signals(value)

    def test_concurrency_defaults_to_the_cap(self):
        assert cli.build_parser().parse_args([]).concurrency == cli.DEFAULT_CONCURRENCY

    @pytest.mark.parametrize("value", ["0", "9", "many"])
    def test_concurrency_is_capped(self, value):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["--concurrency", value])

    def test_the_token_is_never_an_argument(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["--token", "x"])


class TestDetect:
    def test_merges_signals_and_records_which_found_each(self):
        rows = cli.detect(PROJECTS, {
            "scans": {"acme/web": 40},
            "composer": {"acme/web": 12, "acme/cms": 3},
            "findings": {"acme/web": 5, "acme/old": 1},
        })
        assert [r["project"] for r in rows] == ["acme/cms", "acme/old", "acme/web"]
        web = rows[2]
        assert web == {"project": "acme/web", "id": 1,
                       "signals": ["scans", "composer", "findings"],
                       "phpFilesParsed": 40, "composerDependencies": 12, "phpFindings": 5}
        assert rows[1]["signals"] == ["findings"]

    def test_a_project_missing_from_the_listing_is_kept_without_an_id(self):
        rows = cli.detect(PROJECTS, {"findings": {"acme/archived": 2}})
        assert rows == [{"project": "acme/archived", "id": None, "signals": ["findings"],
                         "phpFilesParsed": 0, "composerDependencies": 0, "phpFindings": 2}]


@pytest.fixture
def fake_api(monkeypatch):
    """A deployment where:

    acme/web  full scan parsed PHP                 -> decided yes by scans
    acme/api  full scan parsed no PHP              -> decided no by scans
    acme/cms  no recent full scan, Composer deps   -> decided yes by composer
    acme/old  no recent full scan, no Composer     -> undecided: findings walk
    """
    calls = {"walked": None, "stats": []}
    monkeypatch.setattr(api, "get_token", lambda: "tok")
    monkeypatch.setattr(api, "current_deployment",
                        lambda token, base_url: {"id": 1234, "name": "Acme"})
    monkeypatch.setattr(api, "list_projects", lambda deployment_id, token, base_url: PROJECTS)
    scans = {1: {"id": "11"}, 3: {"id": "33"}}

    monkeypatch.setattr(api, "latest_full_scan",
                        lambda deployment_id, repository_id, token, base_url:
                        scans.get(repository_id))

    def stats(deployment_id, scan_id, token, base_url):
        calls["stats"].append(scan_id)
        return {"11": php_stats(40), "33": {"parse_rate": {"go": {"num_targets": 7}}}}[scan_id]

    def issues(deployment_id, token, base_url, repository_ids=None, progress=None):
        calls["walked"] = list(repository_ids)
        return {"acme/old": 2}

    monkeypatch.setattr(api, "scan_stats", stats)
    monkeypatch.setattr(api, "composer_repositories",
                        lambda deployment_id, token, base_url: {"acme/cms": 5})
    monkeypatch.setattr(api, "php_issues", issues)
    return calls


def _run(capsys, argv):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(argv)
    out, err = capsys.readouterr()
    return excinfo.value.code, out, err


class TestMain:
    def test_text_is_one_name_per_line_on_stdout(self, fake_api, capsys):
        code, out, err = _run(capsys, [])
        assert code == 0
        assert out == "acme/cms\nacme/old\nacme/web\n"
        assert "3 of 4 project(s) contain PHP" in err

    def test_findings_walk_covers_only_undecided_projects(self, fake_api, capsys):
        # The point of the ordering: the expensive walk skips everything a full
        # scan or Composer already answered, including scans that said "no PHP".
        _run(capsys, [])
        assert fake_api["walked"] == [4]

    def test_without_scans_the_walk_still_skips_composer_hits(self, fake_api, capsys):
        _run(capsys, ["--signals", "composer,findings"])
        assert fake_api["walked"] == [1, 3, 4]

    def test_findings_alone_walks_every_project(self, fake_api, capsys):
        _run(capsys, ["--signals", "findings"])
        assert fake_api["walked"] == [1, 2, 3, 4]

    def test_composer_alone_never_walks(self, fake_api, capsys):
        code, out, err = _run(capsys, ["--signals", "composer"])
        assert code == 0
        assert fake_api["walked"] is None
        assert out == "acme/cms\n"

    def test_every_latest_scan_has_its_stats_read(self, fake_api, capsys):
        _run(capsys, [])
        assert sorted(fake_api["stats"]) == ["11", "33"]

    def test_json_carries_the_evidence(self, fake_api, capsys):
        code, out, err = _run(capsys, ["--format", "json"])
        data = json.loads(out)
        assert data["deployment"] == "Acme"
        assert data["signals"] == ["scans", "composer", "findings"]
        assert data["signalsSkipped"] == {}
        assert data["projectsVisible"] == 4
        assert data["projectsWalkedForFindings"] == 1
        assert data["tool"].startswith("semgrep-list-php-projects ")
        by_name = {p["project"]: p for p in data["projects"]}
        assert by_name["acme/web"]["signals"] == ["scans"]
        assert by_name["acme/web"]["phpFilesParsed"] == 40
        assert by_name["acme/old"] == {"project": "acme/old", "id": 4, "signals": ["findings"],
                                       "phpFilesParsed": 0, "composerDependencies": 0,
                                       "phpFindings": 2}

    def test_csv(self, fake_api, capsys):
        code, out, err = _run(capsys, ["--format", "csv"])
        rows = list(csv.reader(io.StringIO(out)))
        assert rows[0] == ["project", "id", "signals", "php_files_parsed",
                           "composer_dependencies", "php_findings"]
        assert rows[1] == ["acme/cms", "2", "composer", "0", "5", "0"]
        assert rows[3] == ["acme/web", "1", "scans", "40", "0", "0"]

    def test_stats_without_language_data_decide_nothing_and_say_so(
            self, fake_api, monkeypatch, capsys):
        # If `stats` has no per-language data, every project must fall through
        # to the walk, and the run must say why.
        monkeypatch.setattr(api, "scan_stats", lambda *a, **k: {"findings": 3, "total_time": 9})
        _, out, err = _run(capsys, [])
        assert fake_api["walked"] == [1, 3, 4]
        assert "no scan reported per-language statistics" in err
        assert "findings, total_time" in err

    def test_scans_are_searched_once_per_project(self, fake_api, monkeypatch, capsys):
        asked = []

        def search(deployment_id, repository_id, token, base_url):
            asked.append(repository_id)
            return {"id": "11"} if repository_id == 1 else None

        monkeypatch.setattr(api, "latest_full_scan", search)
        _, out, _ = _run(capsys, [])
        assert sorted(asked) == [1, 2, 3, 4]
        assert "acme/web" in out

    def test_an_empty_parse_rate_decides_no_php(self, fake_api, monkeypatch, capsys):
        # Seen live: a scan that parsed nothing reports `parse_rate: {}`. The
        # scan covered the repository and found no PHP, so it is settled.
        monkeypatch.setattr(api, "scan_stats", lambda *a, **k: {"parse_rate": {}})
        _run(capsys, [])
        assert fake_api["walked"] == [4]

    def test_without_supply_chain_the_other_signals_still_answer(
            self, fake_api, monkeypatch, capsys):
        def no_sca(*args, **kwargs):
            raise api.SemgrepError("POST .../repositories failed: HTTP 403", status=403)
        monkeypatch.setattr(api, "composer_repositories", no_sca)
        code, out, err = _run(capsys, ["--format", "json"])
        assert code == 0
        data = json.loads(out)
        assert data["signals"] == ["scans", "findings"]
        assert list(data["signalsSkipped"]) == ["composer"]
        assert "composer: skipped" in err
        assert "signals skipped: composer" in err
        # Composer decided nothing, so its project is walked too.
        assert fake_api["walked"] == [2, 4]

    def test_every_signal_unavailable_is_an_error(self, fake_api, monkeypatch, capsys):
        def gone(*args, **kwargs):
            raise api.SemgrepError("HTTP 404", status=404)
        monkeypatch.setattr(api, "latest_full_scan", gone)
        monkeypatch.setattr(api, "composer_repositories", gone)
        monkeypatch.setattr(api, "php_issues", gone)
        code, out, err = _run(capsys, [])
        assert code == 2 and out == ""
        assert "no signal could run" in err

    def test_a_walk_that_breaks_partway_stops_the_run(self, fake_api, monkeypatch, capsys):
        def broken(*args, **kwargs):
            raise api.SemgrepError("POST .../issues failed after 6 attempts: HTTP 503",
                                   status=503)
        monkeypatch.setattr(api, "php_issues", broken)
        code, out, err = _run(capsys, [])
        assert code == 2 and out == ""
        assert "after 6 attempts" in err

    def test_a_failed_scan_lookup_stops_the_run(self, fake_api, monkeypatch, capsys):
        def broken(*args, **kwargs):
            raise api.SemgrepError("GET .../scan/33 failed after 6 attempts", status=503)
        monkeypatch.setattr(api, "scan_stats", broken)
        code, out, err = _run(capsys, [])
        assert code == 2 and out == ""

    def test_api_errors_exit_2_without_a_traceback(self, monkeypatch, capsys):
        def no_token():
            raise api.SemgrepError("no API token found")
        monkeypatch.setattr(api, "get_token", no_token)
        code, out, err = _run(capsys, [])
        assert code == 2 and out == ""
        assert "error: no API token found" in err
