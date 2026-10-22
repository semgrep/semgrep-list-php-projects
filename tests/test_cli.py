"""CLI tests: argument parsing, signal ordering and merging, and output. No network."""

import csv
import io
import json

import pytest

from semgrep_list_php_projects import api, cli

PROJECTS = [{"id": 1, "name": "acme/web"}, {"id": 2, "name": "acme/cms"},
            {"id": 3, "name": "acme/api"}, {"id": 4, "name": "acme/old"}]


class TestArguments:
    def test_default_is_every_signal(self):
        assert cli.build_parser().parse_args([]).signals == ("composer", "findings")

    def test_signals_are_deduplicated_and_lowercased(self):
        assert cli._signals("Composer, composer") == ("composer",)

    @pytest.mark.parametrize("value", ["", "npm", "composer,npm", "scans"])
    def test_rejects_unknown_signals(self, value):
        with pytest.raises(Exception):
            cli._signals(value)

    def test_the_token_is_never_an_argument(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["--token", "x"])


class TestDetect:
    def test_merges_signals_and_records_which_found_each(self):
        rows = cli.detect(PROJECTS, {
            "composer": {"acme/web": 12, "acme/cms": 3},
            "findings": {"acme/web": 5, "acme/old": 1},
        })
        assert [r["project"] for r in rows] == ["acme/cms", "acme/old", "acme/web"]
        web = rows[2]
        assert web == {"project": "acme/web", "id": 1, "signals": ["composer", "findings"],
                       "composerDependencies": 12, "phpFindings": 5}
        assert rows[1]["signals"] == ["findings"]

    def test_a_project_missing_from_the_listing_is_kept_without_an_id(self):
        rows = cli.detect(PROJECTS, {"findings": {"acme/archived": 2}})
        assert rows == [{"project": "acme/archived", "id": None, "signals": ["findings"],
                         "composerDependencies": 0, "phpFindings": 2}]


@pytest.fixture
def fake_api(monkeypatch):
    """A deployment where:

    acme/web  Composer deps and PHP findings      -> decided yes by composer
    acme/cms  Composer deps                        -> decided yes by composer
    acme/api  no Composer, Go findings             -> undecided: walked, no PHP
    acme/old  no Composer, PHP findings            -> undecided: walked, yes
    """
    calls = {"walked": None}
    monkeypatch.setattr(api, "get_token", lambda: "tok")
    monkeypatch.setattr(api, "current_deployment",
                        lambda token, base_url: {"id": 1234, "name": "Acme"})
    monkeypatch.setattr(api, "list_projects", lambda deployment_id, token, base_url: PROJECTS)

    def issues(deployment_id, token, base_url, repository_ids=None, progress=None):
        calls["walked"] = list(repository_ids)
        return {"acme/old": 2}

    monkeypatch.setattr(api, "composer_repositories",
                        lambda deployment_id, token, base_url: {"acme/cms": 5, "acme/web": 12})
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
        # The point of the ordering: the expensive walk skips everything
        # Composer already answered.
        _run(capsys, [])
        assert fake_api["walked"] == [3, 4]

    def test_findings_alone_walks_every_project(self, fake_api, capsys):
        _run(capsys, ["--signals", "findings"])
        assert fake_api["walked"] == [1, 2, 3, 4]

    def test_composer_alone_never_walks(self, fake_api, capsys):
        code, out, err = _run(capsys, ["--signals", "composer"])
        assert code == 0
        assert fake_api["walked"] is None
        assert out == "acme/cms\nacme/web\n"

    def test_json_carries_the_evidence(self, fake_api, capsys):
        code, out, err = _run(capsys, ["--format", "json"])
        data = json.loads(out)
        assert data["deployment"] == "Acme"
        assert data["signals"] == ["composer", "findings"]
        assert data["signalsSkipped"] == {}
        assert data["projectsVisible"] == 4
        assert data["projectsWalkedForFindings"] == 2
        assert data["tool"].startswith("semgrep-list-php-projects ")
        by_name = {p["project"]: p for p in data["projects"]}
        assert by_name["acme/web"]["signals"] == ["composer"]
        assert by_name["acme/web"]["composerDependencies"] == 12
        assert by_name["acme/old"] == {"project": "acme/old", "id": 4, "signals": ["findings"],
                                       "composerDependencies": 0, "phpFindings": 2}

    def test_csv(self, fake_api, capsys):
        code, out, err = _run(capsys, ["--format", "csv"])
        rows = list(csv.reader(io.StringIO(out)))
        assert rows[0] == ["project", "id", "signals", "composer_dependencies", "php_findings"]
        assert rows[1] == ["acme/cms", "2", "composer", "5", "0"]
        assert rows[2] == ["acme/old", "4", "findings", "0", "2"]

    def test_without_supply_chain_the_findings_still_answer(
            self, fake_api, monkeypatch, capsys):
        def no_sca(*args, **kwargs):
            raise api.SemgrepError("POST .../repositories failed: HTTP 403", status=403)
        monkeypatch.setattr(api, "composer_repositories", no_sca)
        code, out, err = _run(capsys, ["--format", "json"])
        assert code == 0
        data = json.loads(out)
        assert data["signals"] == ["findings"]
        assert list(data["signalsSkipped"]) == ["composer"]
        assert "composer: skipped" in err
        assert "signals skipped: composer" in err
        # With nothing decided, every project is walked.
        assert fake_api["walked"] == [1, 2, 3, 4]

    def test_every_signal_unavailable_is_an_error(self, fake_api, monkeypatch, capsys):
        def gone(*args, **kwargs):
            raise api.SemgrepError("HTTP 404", status=404)
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

    def test_api_errors_exit_2_without_a_traceback(self, monkeypatch, capsys):
        def no_token():
            raise api.SemgrepError("no API token found")
        monkeypatch.setattr(api, "get_token", no_token)
        code, out, err = _run(capsys, [])
        assert code == 2 and out == ""
        assert "error: no API token found" in err
