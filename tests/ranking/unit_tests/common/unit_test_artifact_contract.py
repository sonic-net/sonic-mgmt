def test_artifact_contract_owns_shared_file_names_and_log_markers():
    from tests.ranking.common import artifact_contract

    assert artifact_contract.OUTCOME_FILE == 'outcome.json'
    assert artifact_contract.RUN_LOG_FILE == 'run.log'
    text = (
        artifact_contract.CONSOLE_HEADER + 'OK\n' +
        artifact_contract.INTERNAL_HEADER + 'private\n')
    assert artifact_contract.extract_console(text) == 'OK\n'


def test_run_uses_shared_artifact_contract_and_report_does_not_parse_logs():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    runner = (root / 'run/ptf_runner.py').read_text(encoding='utf-8')
    report = (root / 'report/generate.py').read_text(encoding='utf-8')
    assert 'CONSOLE_HEADER =' not in runner
    assert 'INTERNAL_HEADER =' not in runner
    assert 'tests.ranking.common.artifact_contract' in runner
    assert 'tests.ranking.common.artifact_contract' not in report
    assert 'extract_console' not in report
