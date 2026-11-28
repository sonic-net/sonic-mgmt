from pathlib import Path


RANKING_ROOT = Path(__file__).resolve().parents[2]
README = (RANKING_ROOT / 'README.md').read_text(encoding='utf-8')
ENVIRONMENT_ROOT = RANKING_ROOT / 'environments' / 'sonic_sonic'
TEMPLATE_README = (ENVIRONMENT_ROOT / 'README.md').read_text(encoding='utf-8')
EXAMPLE_PACKAGE = 'tests/ranking/environments/sonic_sonic'
EXAMPLE_OUTPUT = 'tests/ranking/output/route-batch-001'


def _section(start, end):
    return README.split(start, 1)[1].split(end, 1)[0]


def test_readme_documents_current_three_phase_contract_only():
    for current in (
            'prepare/test_prepare.py',
            'run/test_ranking.py',
            'python3 -m tests.ranking.report.generate',
            'cases/<module>/results/<Class>.json'):
        assert current in README

    for obsolete in (
            'prepare_inputs',
            'lifecycle.py',
            'ansible/roles/ranking',
            'report_runner.py',
            '--ranking-inputs',
            '--ranking-skip-setup',
            '--ranking-keep-env',
            '--ranking-adopt-existing',
            '--expected-case'):
        assert obsolete not in README


def test_readme_keeps_run_independent_and_credentials_local():
    workflow = _section('## Test Workflow\n', '### Environment and Prerequisites\n')
    run = _section('### Run\n', '### Report\n')

    assert '| Optional. Skip it if the lab and deployed cases are ready. |' in workflow
    assert 'If you prepared the lab manually' in run
    assert 'local, untracked copy' in TEMPLATE_README
    assert 'auth.password' in TEMPLATE_README


def test_readme_leaves_sonic_service_changes_in_the_environment_template():
    assert 'the selected environment\'s setup logic' in README
    assert 'template README](environments/sonic_sonic/README.md)' in README
    assert '## Prepare service changes' in TEMPLATE_README
    assert 'DUT `swss`' in TEMPLATE_README
    assert 'PTF `swss` may also restart its `syncd` container' in TEMPLATE_README


def test_controller_container_mounts_checkout_and_keeps_output_readable():
    controller = _section('### Environment and Prerequisites\n', '### Prepare (optional)\n')
    run = _section('### Run\n', '### Report\n')
    report = _section('### Report\n', '### Verify and Wrap Up the Run\n')

    assert controller.count('--mount ') == 1
    assert 'source=$PWD,target=/work/sonic-mgmt' in controller
    assert '--workdir /work/sonic-mgmt' in controller
    assert '--user "$(id -u):$(id -g)"' in controller
    assert '--env ANSIBLE_CONFIG=/work/sonic-mgmt/ansible/ansible.cfg' in controller
    assert '--ranking-output ' + EXAMPLE_OUTPUT in run
    assert '--ranking-output ' + EXAMPLE_OUTPUT in report
    for obsolete in ('/work/ranking-output', 'RANKING_OUTPUT_HOST',
                     '--ranking-artifacts', '--artifact-root'):
        assert obsolete not in README


def test_environment_template_documents_the_fixed_sonic_sonic_ptf_contract():
    for required in (
            '| `type` | Keep `sonic_sonic`',
            '| `dut.rpc_port` | Keep `9092`.',
            '| `ptf.arguments` | Keep `[--relax]`.',
            '| `ptf.collector_dir` | Keep `/tmp/sai_test_results`'):
        assert required in TEMPLATE_README


def test_readme_documents_environment_package_and_run_dependencies():
    for required in (
            'dut/config_db.json',
            'dut/port_config.ini',
            'ptf/port_config.ini',
            'ptf/mirror_port.py',
            'environments/sonic_sonic/README.md'):
        assert required in README
        if required != 'environments/sonic_sonic/README.md':
            assert (ENVIRONMENT_ROOT / required).is_file()

    run = _section('### Run\n', '### Report\n')
    for required in ('PTF launcher', '`sai_thrift`', 'route from PTF to the DUT', 'TCP 9092'):
        assert required in run


def test_prepare_and_run_examples_point_to_the_environment_template():
    prepare = _section('### Prepare (optional)\n', '### Run\n')
    run = _section('### Run\n', '### Report\n')

    assert '--ranking-environment ' + EXAMPLE_PACKAGE in prepare
    assert '--ranking-config ' + EXAMPLE_PACKAGE + '/environment.yml' in run
    for required in ('environment.yml', 'environment.py', 'prepare.py'):
        assert (ENVIRONMENT_ROOT / required).is_file()


def test_readme_explains_where_to_install_resources_for_manually_prepared_labs():
    run = _section('### Run\n', '### Report\n')

    for required in ('`cases/ptf/`', '`ptf.case_dir`', '`config_db.json`',
                     '`port_config.ini`', '`resources/`'):
        assert required in run


def test_readme_documents_options_for_each_phase():
    prepare = _section('### Prepare (optional)\n', '### Run\n')
    run = _section('### Run\n', '### Report\n')
    report = _section('### Report\n', '### Verify and Wrap Up the Run\n')

    for option in ('--ranking-environment', '--ranking-cases',
                   '--ranking-prepare-steps', '--ranking-force-sync'):
        assert option in prepare
    for option in ('--ranking-config', '--ranking-output', '--ranking-select',
                   '--ranking-live-log', '--collect-only'):
        assert option in run
    for option in ('--ranking-config', '--ranking-output'):
        assert option in report
    assert 'cases/manifest.json' in README


def test_prepare_documentation_does_not_require_ranking_output():
    prepare = _section('### Prepare (optional)\n', '### Run\n')

    assert '--ranking-output' not in prepare


def test_readme_closes_report_viewing_and_restore_loop():
    report = _section('### Report\n', '### Verify and Wrap Up the Run\n')
    wrap_up = README.split('### Verify and Wrap Up the Run\n', 1)[1]

    assert 'report/report.html' in report
    assert 'python3 -m http.server' in report
    assert 'http://127.0.0.1:8000/report/report.html' in report
    assert 'Test Results, Capability, and Performance & Scale' in report
    assert '`NOT TESTED`' in wrap_up
    assert 'restores the DUT and PTF according to lab policy' in wrap_up
    for obsolete in ('result.html', 'capability.html', 'spec.html',
                     'report_status.json', 'capability.json', 'report-input/'):
        assert obsolete not in README


def test_readme_documents_optional_report_environment_disclosure():
    report = _section('### Report\n', '### Verify and Wrap Up the Run\n')
    example = report.split('```bash\n', 1)[1].split('```', 1)[0]

    assert 'python3 -m tests.ranking.report.generate' in example
    assert '--ranking-config' not in example
    assert '| `--ranking-config YAML` | Optional.' in report
    for field in ('DUT ASIC', 'ASIC vendor', 'DUT IP', 'PTF IP'):
        assert field in report


def test_readme_keeps_report_metadata_regeneration_optional():
    report, maintenance = _section('### Report\n', '### Verify and Wrap Up the Run\n').split(
        '#### Optional maintenance for report metadata\n')
    generator = 'python3 -m tests.ranking.report.tools.generate_metadata'

    for required in ('enum_values.json', 'skeleton.json', 'spec_registry.json'):
        assert required in report
    assert generator not in report
    assert maintenance.count(generator) == 1
