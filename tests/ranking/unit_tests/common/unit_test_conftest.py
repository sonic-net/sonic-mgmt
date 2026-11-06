import hashlib
from pathlib import Path

import pytest


RANKING_ROOT = Path(__file__).resolve().parents[2]
pytest_plugins = ('pytester',)


def test_common_modules_are_importable_from_canonical_package():
    from tests.ranking.common import (
        case_selection, sonic_mgmt_adapter, artifact_store,
    )

    assert callable(case_selection.select_ranking_cases)
    assert callable(sonic_mgmt_adapter.create_controller_adapter)
    assert callable(artifact_store.exclusive)


def test_common_sources_do_not_own_environment_profile_behavior():
    forbidden = (
        'environments/sonic_sonic', "'sonic_sonic'", '"sonic_sonic"')
    for source in (RANKING_ROOT / 'common').glob('*.py'):
        text = source.read_text(encoding='utf-8')
        assert not any(token in text for token in forbidden), source


def test_root_conftest_is_phase_neutral():
    source = (RANKING_ROOT / 'conftest.py').read_text(encoding='utf-8')

    assert 'tests.ranking.run' not in source
    assert 'tests.ranking.prepare' not in source
    assert '--ranking-config' not in source
    assert '--ranking-environment' not in source


def test_run_collection_exposes_one_unified_case_selector():
    source = (RANKING_ROOT / 'run' / 'conftest.py').read_text(encoding='utf-8')

    assert "'--ranking-select'" in source
    for legacy in (
            '--ranking-case', '--ranking-cases',
            '--ranking-modules', '--ranking-priority'):
        assert legacy not in source


def test_output_option_is_owned_only_by_run():
    root_source = (RANKING_ROOT / 'conftest.py').read_text(encoding='utf-8')
    run_source = (RANKING_ROOT / 'run' / 'conftest.py').read_text(
        encoding='utf-8')

    assert '--ranking-output' not in root_source
    assert '--ranking-output' in run_source
    assert '--ranking-config' not in root_source
    assert '--ranking-environment' not in root_source


def test_run_registers_the_output_option():
    from tests.ranking.run import conftest

    registered = {}

    class Group:
        def addoption(self, name, **kwargs):
            registered[name] = kwargs

    class Parser:
        def getgroup(self, name):
            assert name == 'ranking'
            return Group()

    conftest.pytest_addoption(Parser())

    assert registered['--ranking-output']['metavar'] == 'DIR'


class _Options:
    def __init__(self, values):
        self.values = values

    def getoption(self, name):
        if name not in self.values:
            raise ValueError(name)
        return self.values[name]


class _RankingOptions:
    def __init__(self, config_path, output_root):
        self.values = {
            '--ranking-config': str(config_path),
            '--ranking-output': str(output_root),
            '--ranking-select': None,
        }

    def getoption(self, name):
        return self.values[name]


@pytest.mark.parametrize('source_name', (
    'manifest',
    'source_identity_file',
    'runner_path',
    'ranking_config',
))
@pytest.mark.parametrize('output_position', ('same', 'inside-source', 'contains-source'))
def test_settings_rejects_output_and_source_overlap_in_both_directions(
        source_name, output_position):
    from tests.ranking.run import conftest
    from tests.ranking.environments.sonic_sonic import environment
    from tests.ranking.run.run_assets import load_run_assets

    config_path = RANKING_ROOT / 'environments' / 'sonic_sonic' / 'environment.yml'
    runtime = load_run_assets(RANKING_ROOT)
    runtime.update(environment.load_config(config_path))
    source = (config_path if source_name == 'ranking_config'
              else Path(runtime[source_name])).resolve()
    if output_position == 'same':
        output_root = source
    elif output_position == 'inside-source':
        output_root = source / 'ranking-output'
    else:
        output_root = source.parent

    with pytest.raises(pytest.UsageError, match='must not overlap'):
        conftest._settings(_RankingOptions(config_path, output_root))


def test_settings_rejects_ranking_root_without_touching_cases_or_report():
    from tests.ranking.run import conftest

    config_path = RANKING_ROOT / 'environments' / 'sonic_sonic' / 'environment.yml'
    watched = (RANKING_ROOT / 'cases', RANKING_ROOT / 'report')
    before = {
        path: tuple(sorted(
            (entry.relative_to(path), hashlib.sha256(entry.read_bytes()).hexdigest())
            for entry in path.rglob('*') if entry.is_file()))
        for path in watched
    }

    with pytest.raises(pytest.UsageError, match='must not overlap'):
        conftest._settings(_RankingOptions(config_path, RANKING_ROOT))

    after = {
        path: tuple(sorted(
            (entry.relative_to(path), hashlib.sha256(entry.read_bytes()).hexdigest())
            for entry in path.rglob('*') if entry.is_file()))
        for path in watched
    }
    assert after == before


def test_settings_accepts_external_output_root(tmp_path):
    from tests.ranking.run import conftest

    config_path = RANKING_ROOT / 'environments' / 'sonic_sonic' / 'environment.yml'
    output_root = tmp_path / 'ranking-output'
    options = _RankingOptions(config_path, output_root)

    conftest._settings(options)

    assert options._ranking_output == output_root.resolve()


def _isolate_nested_pytest(pytester, monkeypatch):
    monkeypatch.chdir(pytester.path)
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')


def _isolated_sonic_sonic_config(pytester):
    destination = pytester.path / 'sonic_sonic'
    destination.mkdir()
    source = RANKING_ROOT / 'environments' / 'sonic_sonic'
    (destination / 'environment.yml').write_text(
        (source / 'environment.yml').read_text(encoding='utf-8'),
        encoding='utf-8')
    (destination / 'environment.py').write_text("""
import importlib.util

spec = importlib.util.spec_from_file_location(
    'ranking_real_sonic_sonic_environment', %r)
loaded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loaded)
globals().update({
    name: getattr(loaded, name)
    for name in dir(loaded) if not name.startswith('__')
})
""" % str(source / 'environment.py'), encoding='utf-8')
    return destination / 'environment.yml'


def test_configure_injects_adapter_options_and_unconfigure_removes_files():
    from tests.ranking.run import conftest

    class Option:
        ranking_config = str(RANKING_ROOT / 'environments' / 'sonic_sonic' / 'environment.yml')
        ansible_inventory = None
        testbed = None
        testbed_file = None
        ansible_host_pattern = None
        skip_sanity = False
        ignore_conditional_mark = False
        disable_memory_utilization = False

    class Invocation:
        args = ('tests/ranking/run/test_ranking.py',)

    class Config:
        option = Option()
        invocation_params = Invocation()

        def getoption(self, name):
            return getattr(self.option, name.lstrip('-').replace('-', '_'))

    config = Config()
    conftest.pytest_configure(config)
    adapter = config._ranking_controller_adapter
    assert Path(config.option.ansible_inventory).is_file()
    assert config.option.testbed == 'ranking'
    assert config.option.testbed_file == str(adapter.testbed_file)
    assert config.option.ansible_host_pattern == 'all'
    assert config.option.skip_sanity is True
    assert config.option.ignore_conditional_mark is True
    assert config.option.disable_memory_utilization is True
    conftest.pytest_unconfigure(config)
    assert not adapter.root.exists()


def test_non_ranking_configure_creates_no_adapter():
    from tests.ranking.run import conftest

    class Option:
        ranking_config = None

    class Config:
        option = Option()

        def getoption(self, name):
            return None

    config = Config()
    conftest.pytest_configure(config)
    assert not hasattr(config, '_ranking_controller_adapter')


def test_explicit_standard_options_are_rejected_as_a_second_source():
    from tests.ranking.run import conftest

    class Option:
        ranking_config = str(RANKING_ROOT / 'environments' / 'sonic_sonic' / 'environment.yml')

    class Invocation:
        args = ('--ranking-config', Option.ranking_config, '--inventory', 'other.yml')

    class Config:
        option = Option()
        invocation_params = Invocation()

        def getoption(self, name):
            return getattr(self.option, name.lstrip('-').replace('-', '_'), None)

    with pytest.raises(pytest.UsageError, match='owns standard controller options'):
        conftest.pytest_configure(Config())


def test_ideal_collect_command_injects_adapter_before_standard_consumers(
        pytester, tmp_path, monkeypatch):
    _isolate_nested_pytest(pytester, monkeypatch)
    config = _isolated_sonic_sonic_config(pytester)
    testbed_module = RANKING_ROOT.parent / 'common' / 'testbed.py'
    pytester.makeconftest("""
import importlib.util
import ipaddress
import sys
import types

from tests.ranking.run import conftest as ranking


def pytest_addoption(parser):
    for name in (
            '--ranking-config', '--ranking-output', '--ranking-select'):
        parser.addoption(name, default=None)
    parser.addoption('--inventory', dest='ansible_inventory', default=None)
    parser.addoption('--testbed', dest='testbed', default=None)
    parser.addoption('--testbed_file', dest='testbed_file', default=None)
    parser.addoption('--ansible-host-pattern', dest='ansible_host_pattern', default=None)
    parser.addoption('--skip_sanity', action='store_true', default=False)
    parser.addoption('--ignore-conditional-mark', dest='ignore_conditional_mark',
                     action='store_true', default=False)


def pytest_configure(config):
    ranking.pytest_configure(config)


def pytest_unconfigure(config):
    ranking.pytest_unconfigure(config)


def pytest_generate_tests(metafunc):
    ranking.pytest_generate_tests(metafunc)


def _real_testbed_info(path):
    module = types.ModuleType('ipaddr')
    class IPNetwork:
        def __init__(self, value):
            interface = ipaddress.ip_interface(value)
            self.ip = interface.ip
            self.netmask = interface.network.netmask
    module.IPNetwork = IPNetwork
    sys.modules['ipaddr'] = module
    spec = importlib.util.spec_from_file_location(
        'ranking_real_testbed_parser', %r)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded.TestbedInfo(path)


def pytest_collection_modifyitems(config, items):
    assert config.option.ansible_inventory
    assert config.option.testbed == 'ranking'
    assert config.option.testbed_file
    assert config.option.ansible_host_pattern == 'all'
    assert config.option.skip_sanity is True
    assert config.option.ignore_conditional_mark is True
    parsed = _real_testbed_info(config.option.testbed_file)
    selected = parsed.testbed_topo['ranking']
    assert selected['duts'] == ['sonic-dut']
    assert selected['ptf'] == 'sonic-ptf'
    assert selected['topo']['name'] == 'ptf32'
""" % str(testbed_module))
    test_file = pytester.makepyfile("""
def test_ranking_case(ranking_case):
    pass
""")
    result = pytester.runpytest(
        '-q', '--rootdir', str(pytester.path),
        '--confcutdir', str(pytester.path), str(test_file),
        '--ranking-config', str(config),
        '--ranking-output', str(tmp_path / 'artifacts'),
        '--ranking-select', 'case:sairoute.multipleRoutesTest',
        '--collect-only')

    assert result.ret == 0
    output = result.stdout.str()
    assert '::test_ranking_case[sairoute.multipleRoutesTest]' in output
    assert '1 test collected' in output
