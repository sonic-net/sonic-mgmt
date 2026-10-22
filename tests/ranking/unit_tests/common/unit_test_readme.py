from pathlib import Path


README = Path(__file__).resolve().parents[2] / 'README.md'


def test_readme_documents_current_three_phase_contract_only():
    text = README.read_text(encoding='utf-8')

    for current in (
            'environments/sonic_sonic',
            'examples/my-lab/environment.yml',
            'prepare/test_prepare.py',
            'run/test_ranking.py',
            'python3 -m tests.ranking.report.generate',
            'cases/<module>/results/<Class>.json',
            'v1.10-pdx-capability',
            '--ranking-environment',
            '--ranking-prepare-steps',
            '--ranking-force-sync'):
        assert current in text

    for obsolete in (
            'prepare_inputs',
            'lifecycle.py',
            'ansible/roles/ranking',
            'tests.ranking.report_runner',
            'report_runner.py',
            '--ranking-inputs',
            '--ranking-skip-setup',
            '--ranking-keep-env'):
        assert obsolete not in text
    assert '--ranking-adopt-existing' not in text


def test_readme_keeps_run_independent_and_credentials_out_of_artifacts():
    text = README.read_text(encoding='utf-8')

    assert 'Prepare writes no durable deployment state' in text
    assert 'manually prepared environment' in text
    assert 'never written to artifacts' in text
    assert '--ranking-live-log' in text


def test_readme_separates_generic_ready_from_sonic_environment_state():
    text = README.read_text(encoding='utf-8')

    assert 'Generic Run Ready contract' in text
    assert 'does not require SONiC `swss`' in text
    assert 'SDK-only DUT' in text
    assert 'SONiC-to-SONiC/Broadcom environment only' in text


def test_controller_container_uses_one_checkout_mount_and_ignored_output():
    text = README.read_text(encoding='utf-8')

    assert text.count('--mount type=bind') == 1
    assert 'source="$PWD",target=/work/sonic-mgmt' in text
    assert '`--rm` removes only the controller container' in text
    assert text.count(
        '--ranking-output tests/ranking/output/route-batch-001') >= 3
    assert '/work/ranking-output' not in text
    assert 'RANKING_OUTPUT_HOST' not in text
    assert '--ranking-artifacts' not in text
    assert '--artifact-root' not in text


def test_readme_documents_fixed_sonic_sonic_ptf_contract():
    text = README.read_text(encoding='utf-8')

    assert '| `type` | Required, must be `sonic_sonic` |' in text
    assert '| `dut.rpc_port` | Required, exactly `9092` |' in text
    assert '| `ptf.arguments` | Required, exactly `[--relax]` |' in text
    assert 'configurable' not in text
    assert 'Literal common PTF arguments' not in text


def test_readme_documents_environment_package_and_device_dependencies():
    text = README.read_text(encoding='utf-8')

    for required in (
            'dut/config_db.json',
            'dut/port_config.ini',
            'ptf/port_config.ini',
            'ptf/mirror_port.py',
            '/usr/bin/saiserverv2.sh',
            '/SAI-TEST/test/ptf/ptf',
            'docker exec syncd bcmcmd -c ps',
            'SAI 1.10.2',
            'topo_ptf32.yml',
            'topo_ptf64.yml',
            'environments/sonic_sonic/README.md'):
        assert required in text


def test_readme_copies_the_tracked_template_to_an_ignored_local_lab():
    text = README.read_text(encoding='utf-8')

    assert ('cp -a tests/ranking/environments/sonic_sonic '
            'tests/ranking/examples/my-lab') in text
    assert 'tests/ranking/examples/` is ignored by Git' in text
    assert 'examples/physical' not in text


def test_readme_filters_exported_config_db_to_the_wired_dut_ports():
    text = README.read_text(encoding='utf-8')

    assert '> /tmp/config_db.full.json' in text
    assert 'environment.yml:ports` exactly' in text
    assert "missing DUT PORT entries" in text
    assert "tests/ranking/examples/my-lab/dut/config_db.json" in text


def test_readme_documents_cli_reference_and_case_discovery():
    text = README.read_text(encoding='utf-8')

    for required in (
            'Prepare command reference',
            'Run command reference',
            'Report command reference',
            'cases/manifest.json',
            '--ranking-environment',
            '--ranking-cases',
            '--ranking-output',
            '--ranking-prepare-steps',
            '--ranking-force-sync',
            '--ranking-config',
            '--ranking-select',
            '--ranking-live-log'):
        assert required in text
    assert '--expected-case' not in text


def test_prepare_documentation_does_not_require_ranking_output():
    text = README.read_text(encoding='utf-8')
    prepare_section = text.split(
        '## 5. Prepare the SONiC-to-SONiC environment', 1)[1].split(
            '## 6. Select and run cases', 1)[0]

    assert '--ranking-output' not in prepare_section


def test_readme_closes_report_viewing_and_restore_loop():
    text = README.read_text(encoding='utf-8')

    assert 'python3 -m http.server' in text
    assert 'result.html' in text
    assert 'capability.html' in text
    assert 'spec.html' in text
    assert '`NOT TESTED`' in text
    assert 'cases/manifest.json' in text
    assert 'report_status.json' not in text
    assert 'capability.json' not in text
    assert 'report-input/' not in text
    assert 'Environment restoration' in text
