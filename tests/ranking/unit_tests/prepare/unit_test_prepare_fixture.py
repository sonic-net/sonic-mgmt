from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest


ENVIRONMENT_API = (
    'def load_environment(path):\n'
    '    return {"type": "custom"}\n'
    'def controller_spec(value):\n'
    '    return {}\n'
    'def compile_runtime(value, path):\n'
    '    return {}\n'
)


def test_prepare_registers_the_case_root_option():
    from tests.ranking.prepare import conftest

    registered = {}

    class Group:
        def addoption(self, name, **kwargs):
            registered[name] = kwargs

    class Parser:
        def getgroup(self, name):
            assert name == 'ranking prepare'
            return Group()

    conftest.pytest_addoption(Parser())

    assert registered['--ranking-cases']['metavar'] == 'DIR'
    assert '--ranking-output' not in registered


def test_prepare_steps_default_to_all_actions_in_canonical_order():
    from tests.ranking.prepare.conftest import normalize_prepare_steps

    assert normalize_prepare_steps(None) == (
        'configure_env', 'check_env', 'sync_cases')


def test_prepare_steps_are_normalized_to_canonical_order():
    from tests.ranking.prepare.conftest import normalize_prepare_steps

    assert normalize_prepare_steps('sync_cases,configure_env') == (
        'configure_env', 'sync_cases')


@pytest.mark.parametrize('value', [
    '', 'configure_env,', 'unknown', 'check_env,check_env',
])
def test_prepare_steps_reject_invalid_input(value):
    from tests.ranking.prepare.conftest import normalize_prepare_steps

    with pytest.raises(pytest.UsageError, match='prepare steps'):
        normalize_prepare_steps(value)


def test_driver_is_loaded_from_the_selected_environment_directory(tmp_path):
    from tests.ranking.prepare.conftest import load_environment_driver

    environment = tmp_path / 'custom-environment'
    environment.mkdir()
    (environment / 'environment.yml').write_text('type: custom\n')
    (environment / 'environment.py').write_text(ENVIRONMENT_API)
    (environment / 'prepare.py').write_text(
        'def describe(context):\n'
        '    return {"type": "custom"}\n'
        'def configure_env(context, description):\n'
        '    return None\n'
        'def check_env(context, description):\n'
        '    return None\n')

    root, environment_file, environment_api, driver = load_environment_driver(environment)

    assert root == environment.resolve()
    assert environment_file == (environment / 'environment.yml').resolve()
    assert environment_api.load_environment(environment_file) == {'type': 'custom'}
    assert driver.describe(None) == {'type': 'custom'}


def test_driver_requires_all_environment_hooks(tmp_path):
    from tests.ranking.prepare.conftest import load_environment_driver

    environment = tmp_path / 'incomplete'
    environment.mkdir()
    (environment / 'environment.yml').write_text('type: custom\n')
    (environment / 'environment.py').write_text(ENVIRONMENT_API)
    (environment / 'prepare.py').write_text(
        'def describe(context):\n'
        '    return {}\n'
        'def configure_env(context, description):\n'
        '    return None\n')

    with pytest.raises(pytest.UsageError, match='check_env'):
        load_environment_driver(environment)


def test_driver_description_error_becomes_usage_error(tmp_path, monkeypatch):
    from tests.ranking.prepare import conftest

    environment = tmp_path / 'environment'
    environment.mkdir()
    environment_file = environment / 'environment.yml'
    environment_file.write_text('type: custom\n')
    cases = tmp_path / 'cases'
    (cases / 'ptf').mkdir(parents=True)
    driver = SimpleNamespace(
        describe=lambda context: (_ for _ in ()).throw(RuntimeError('bad package')),
        configure_env=lambda *args: None,
        check_env=lambda *args: None,
    )
    environment_api = SimpleNamespace()
    monkeypatch.setattr(
        conftest, 'load_environment_driver',
        lambda path: (environment, environment_file, environment_api, driver))
    monkeypatch.setattr(conftest, 'explicit_standard_options', lambda config: [])

    config = SimpleNamespace(
        option=SimpleNamespace(),
        getoption=lambda name: {
            '--ranking-environment': str(environment),
            '--ranking-prepare-steps': None,
            '--ranking-force-sync': False,
            '--ranking-cases': str(cases),
        }.get(name),
    )
    with pytest.raises(pytest.UsageError, match='bad package'):
        conftest.pytest_configure(config)


def test_prepare_disables_inapplicable_memory_monitoring(tmp_path, monkeypatch):
    from tests.ranking.prepare import conftest

    environment = tmp_path / 'environment'
    environment.mkdir()
    environment_file = environment / 'environment.yml'
    environment_file.write_text('type: custom\n')
    adapter = SimpleNamespace(
        inventory=tmp_path / 'inventory.yml',
        testbed='ranking-test',
        testbed_file=tmp_path / 'testbed.yml',
        host_pattern='all',
    )
    driver = SimpleNamespace(describe=lambda context: {'controller_spec': {}})
    monkeypatch.setattr(
        conftest, 'load_environment_driver',
        lambda path: (environment, environment_file, object(), driver))
    monkeypatch.setattr(conftest, 'create_controller_adapter', lambda spec: adapter)
    monkeypatch.setattr(conftest, 'explicit_standard_options', lambda config: [])

    values = {
        '--ranking-environment': str(environment),
        '--ranking-prepare-steps': 'check_env',
        '--ranking-force-sync': False,
        '--ranking-cases': None,
    }
    config = SimpleNamespace(
        option=SimpleNamespace(disable_memory_utilization=False),
        getoption=lambda name: values.get(name),
    )

    conftest.pytest_configure(config)

    assert config.option.disable_memory_utilization is True


def test_prepare_unconfigure_cleans_the_private_controller_adapter(
        tmp_path, monkeypatch):
    from tests.ranking.prepare import conftest

    environment = tmp_path / 'environment'
    environment.mkdir()
    environment_file = environment / 'environment.yml'
    environment_file.write_text('type: custom\n')
    cleaned = []
    adapter = SimpleNamespace(
        inventory=tmp_path / 'inventory.yml',
        testbed='ranking-test',
        testbed_file=tmp_path / 'testbed.yml',
        host_pattern='all',
        root=tmp_path / 'private-adapter',
        cleanup=lambda: cleaned.append(True),
    )
    driver = SimpleNamespace(describe=lambda context: {'controller_spec': {}})
    monkeypatch.setattr(
        conftest, 'load_environment_driver',
        lambda path: (environment, environment_file, object(), driver))
    monkeypatch.setattr(conftest, 'create_controller_adapter', lambda spec: adapter)
    monkeypatch.setattr(conftest, 'explicit_standard_options', lambda config: [])

    values = {
        '--ranking-environment': str(environment),
        '--ranking-prepare-steps': 'check_env',
        '--ranking-force-sync': False,
        '--ranking-cases': None,
    }
    config = SimpleNamespace(
        option=SimpleNamespace(),
        getoption=lambda name: values.get(name),
    )

    conftest.pytest_configure(config)
    conftest.pytest_unconfigure(config)

    assert cleaned == [True]
    assert not hasattr(config, '_ranking_controller_adapter')


def test_invalid_steps_fail_before_loading_environment_or_hosts(tmp_path, monkeypatch):
    from tests.ranking.prepare import conftest

    loaded = []
    monkeypatch.setattr(
        conftest, 'load_environment_driver',
        lambda path: loaded.append(path))
    config = SimpleNamespace(
        getoption=lambda name: {
            '--ranking-environment': str(tmp_path),
            '--ranking-prepare-steps': 'check_env',
            '--ranking-force-sync': True,
            '--ranking-cases': None,
        }.get(name),
    )

    with pytest.raises(pytest.UsageError, match='force-sync.*sync_cases'):
        conftest.pytest_configure(config)

    assert loaded == []


def test_prepare_context_is_immutable(tmp_path):
    from tests.ranking.prepare.conftest import PrepareContext

    context = PrepareContext(
        environment_root=tmp_path,
        environment_file=tmp_path / 'environment.yml',
        case_root=None,
        steps=('check_env',),
        force_sync=False,
        duthost=object(),
        ptfhost=object(),
        tbinfo={},
        environment_api=object(),
        driver=object(),
    )

    with pytest.raises(FrozenInstanceError):
        context.force_sync = True


def test_force_sync_requires_sync_cases_step():
    from tests.ranking.prepare.conftest import validate_prepare_options

    with pytest.raises(pytest.UsageError, match='force-sync.*sync_cases'):
        validate_prepare_options(('check_env',), force_sync=True, case_root=None)


def test_sync_cases_requires_case_root():
    from tests.ranking.prepare.conftest import validate_prepare_options

    with pytest.raises(pytest.UsageError, match='ranking-cases'):
        validate_prepare_options(('sync_cases',), force_sync=False, case_root=None)


def test_case_root_is_not_required_when_sync_is_not_selected():
    from tests.ranking.prepare.conftest import validate_prepare_options

    assert validate_prepare_options(
        ('configure_env', 'check_env'), force_sync=False, case_root=None) is None


def test_workflow_runs_only_selected_actions_in_canonical_order(monkeypatch):
    from tests.ranking.prepare import test_prepare

    events = []
    description = {'type': 'custom'}
    driver = SimpleNamespace(
        describe=lambda context: events.append('describe') or description,
        configure_env=lambda context, value: events.append(('configure_env', value)),
        check_env=lambda context, value: events.append(('check_env', value)),
    )
    context = SimpleNamespace(
        driver=driver,
        steps=('configure_env', 'sync_cases'),
    )
    monkeypatch.setattr(
        test_prepare, 'sync_cases',
        lambda current, value: events.append(('sync_cases', value)))

    test_prepare.test_prepare_workflow(context)

    assert events == [
        'describe',
        ('configure_env', description),
        ('sync_cases', description),
    ]


def test_workflow_check_only_has_no_configuration_or_sync(monkeypatch):
    from tests.ranking.prepare import test_prepare

    events = []
    driver = SimpleNamespace(
        describe=lambda context: events.append('describe') or {},
        configure_env=lambda *args: events.append('configure_env'),
        check_env=lambda *args: events.append('check_env'),
    )
    monkeypatch.setattr(
        test_prepare, 'sync_cases', lambda *args: events.append('sync_cases'))

    test_prepare.test_prepare_workflow(SimpleNamespace(
        driver=driver, steps=('check_env',)))

    assert events == ['describe', 'check_env']
