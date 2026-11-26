"""Tests for the --strict option of report_uploader.py."""
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report_uploader  # noqa: E402

VALID_TEST_RESULT_FILE = os.path.join(os.path.dirname(__file__), "files", "sample_archive", "test_1.xml")


@pytest.fixture
def fake_kusto(monkeypatch):
    """Replace KustoConnector with a fake that records upload_report calls."""
    class FakeKustoConnector:
        uploads = []
        upload_error = None

        def __init__(self, db_name, auth_method):
            pass

        def upload_report(self, report_json, *args):
            FakeKustoConnector.uploads.append(report_json)
            if FakeKustoConnector.upload_error:
                raise FakeKustoConnector.upload_error

    monkeypatch.setattr(report_uploader, "KustoConnector", FakeKustoConnector)
    return FakeKustoConnector


def _run(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["report_uploader.py", "-c", "test_result", *args, "TestDB"])
    report_uploader._run_script()


def test_strict_folder_with_valid_xml(fake_kusto, monkeypatch, tmp_path):
    shutil.copy(VALID_TEST_RESULT_FILE, tmp_path / "test_1.xml")

    _run(monkeypatch, "--strict", str(tmp_path))

    assert len(fake_kusto.uploads) == 1
    assert fake_kusto.uploads[0]["test_cases"]


def test_strict_folder_with_skipped_xml_exits_3(fake_kusto, monkeypatch, tmp_path, capsys):
    shutil.copy(VALID_TEST_RESULT_FILE, tmp_path / "test_1.xml")
    (tmp_path / "broken.xml").write_text("<testsuite")

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, "--strict", str(tmp_path))

    assert excinfo.value.code == 3
    assert len(fake_kusto.uploads) == 1
    assert "WARNING: skipped 1 of 2 XML file(s)" in capsys.readouterr().out


def test_strict_folder_with_xml_named_directory(fake_kusto, monkeypatch, tmp_path):
    (tmp_path / "results.xml").mkdir()
    shutil.copy(VALID_TEST_RESULT_FILE, tmp_path / "results.xml" / "test_1.xml")

    _run(monkeypatch, "--strict", str(tmp_path))

    assert len(fake_kusto.uploads) == 1


def test_strict_upload_error_exits_1(fake_kusto, monkeypatch, tmp_path):
    shutil.copy(VALID_TEST_RESULT_FILE, tmp_path / "test_1.xml")
    fake_kusto.upload_error = RuntimeError("queueing failed")

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, "--strict", str(tmp_path))

    assert excinfo.value.code == 1


@pytest.mark.parametrize("create_folder", [True, False], ids=["empty", "nonexistent"])
def test_strict_folder_without_results_exits_1(fake_kusto, monkeypatch, tmp_path, create_folder):
    folder = tmp_path / "results"
    if create_folder:
        folder.mkdir()

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, "--strict", str(folder))

    assert excinfo.value.code == 1
    assert fake_kusto.uploads == []


def test_without_strict_empty_folder_uploads_empty_report(fake_kusto, monkeypatch, tmp_path):
    _run(monkeypatch, str(tmp_path))

    assert fake_kusto.uploads == [None]


def test_warn_skipped_xml_files_finds_upper_case_extension(tmp_path, capsys):
    shutil.copy(VALID_TEST_RESULT_FILE, tmp_path / "R.XML")

    assert report_uploader._warn_skipped_xml_files(str(tmp_path), []) is True
    out = capsys.readouterr().out
    assert out.startswith("WARNING: skipped 1 of 1 XML file(s)")
    assert out.rstrip().endswith(": R.XML")
