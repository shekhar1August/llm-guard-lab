import json

from llm_guard_lab.cli import main
from llm_guard_lab.store import Store


def test_cli_compliance_against_mock(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    rc = main(["compliance", "--target", "mock", "--db", db,
               "--report", str(tmp_path / "r.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("[OK]") == 8

    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["run"]["mode"] == "compliance"
    assert report["run"]["summary"]["passed"] == 8

    store = Store(db)
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert len(store.get_results(runs[0]["id"])) == 8
    store.close()


def test_cli_campaign_against_mock(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    rc = main(["campaign", "--target", "mock", "--categories", "direct_injection",
               "--db", db, "--report", str(tmp_path / "r.html")])
    assert rc == 0
    assert (tmp_path / "r.html").read_text(encoding="utf-8").startswith("<!doctype html>")

    store = Store(db)
    run = store.list_runs()[0]
    assert run["mode"] == "campaign"
    assert run["summary"]["total"] == 8
    store.close()


def test_cli_fail_below_threshold(tmp_path, capsys):
    rc = main(["campaign", "--target", "mock", "--categories", "direct_injection",
               "--db", str(tmp_path / "cli.db"), "--fail-below", "101"])
    assert rc == 1


def test_cli_runs_list_and_show(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    main(["compliance", "--target", "mock", "--db", db])
    capsys.readouterr()
    assert main(["runs", "list", "--db", db]) == 0
    out = capsys.readouterr().out
    assert "compliance" in out and "completed" in out

    assert main(["runs", "show", "1", "--db", db]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["run"]["id"] == 1


def test_cli_report_export(tmp_path):
    db = str(tmp_path / "cli.db")
    main(["compliance", "--target", "mock", "--db", db])
    pdf_path = tmp_path / "out.pdf"
    rc = main(["report", "1", "--format", "pdf", "-o", str(pdf_path), "--db", db])
    assert rc == 0
    assert pdf_path.read_bytes()[:5] == b"%PDF-"


def test_cli_unknown_target_fails_fast(tmp_path):
    try:
        main(["compliance", "--target", '{"type": "bogus"}',
              "--db", str(tmp_path / "x.db")])
        raise AssertionError("expected SystemExit")
    except SystemExit as e:
        assert "unknown target type" in str(e)
