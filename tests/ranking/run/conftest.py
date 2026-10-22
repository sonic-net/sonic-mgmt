import hashlib
import importlib.util
from pathlib import Path
import warnings

import pytest

from tests.ranking.common.case_selection import select_ranking_cases
from tests.ranking.common import artifact_store
from tests.ranking.common.sonic_mgmt_adapter import (
    create_controller_adapter, explicit_standard_options,
)
from tests.ranking.run import ptf_container
from tests.ranking.run.run_assets import load_run_assets


SOURCE_PATH_FIELDS = (
    'runner_path', 'manifest', 'source_identity_file',
)
ENVIRONMENT_HOOKS = (
    'load_environment', 'controller_spec', 'compile_runtime',
)


def _load_environment_api(path):
    environment_file = Path(path).expanduser().resolve()
    implementation = environment_file.parent / 'environment.py'
    if implementation.is_symlink() or not implementation.is_file():
        raise ValueError(
            'Ranking environment requires sibling environment.py: {}'.format(
                implementation))
    digest = hashlib.sha256(
        str(implementation).encode('utf-8')).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(
        '_ranking_runtime_environment_{}'.format(digest), str(implementation))
    if spec is None or spec.loader is None:
        raise ValueError(
            'cannot load Ranking environment API: {}'.format(implementation))
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise ValueError(
            'cannot load Ranking environment API: {}'.format(
                implementation)) from error
    for hook in ENVIRONMENT_HOOKS:
        if not callable(getattr(module, hook, None)):
            raise ValueError(
                'Ranking environment.py requires callable {}'.format(hook))
    return module


def pytest_addoption(parser):
    group = parser.getgroup('ranking')
    group.addoption('--ranking-config', default=None, metavar='YAML',
                    help='environment YAML with a sibling environment.py')
    group.addoption(
        '--ranking-output', default=None, metavar='DIR',
        help='controller output directory for final case results')
    group.addoption(
        '--ranking-live-log', choices=('compact', 'full', 'off'),
        default='compact',
        help='PTF console display: compact summary, full console, or off')
    group.addoption(
        '--ranking-select', default=None, metavar='TYPE:VALUE',
        help='case, module, or priority selector; defaults to priority:P0')


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    path = _option(config, '--ranking-config')
    if not path:
        return
    explicit = explicit_standard_options(config)
    if explicit:
        raise pytest.UsageError(
            'Ranking environment owns standard controller options: {}'.format(
                ', '.join(explicit)))
    try:
        environment_api = _load_environment_api(path)
        environment = environment_api.load_environment(path)
        adapter = create_controller_adapter(
            environment_api.controller_spec(environment))
    except (OSError, TypeError, ValueError) as error:
        raise pytest.UsageError(str(error)) from error
    try:
        config.option.ansible_inventory = str(adapter.inventory)
        config.option.testbed = adapter.testbed
        config.option.testbed_file = str(adapter.testbed_file)
        config.option.ansible_host_pattern = adapter.host_pattern
        config.option.skip_sanity = True
        config.option.ignore_conditional_mark = True
        # Ranking owns the DUT service lifecycle.  Generic sonic-mgmt memory
        # monitoring is not meaningful after swss has deliberately been
        # stopped for SAIserver testing, and can turn a valid case result into
        # an unrelated teardown error.
        config.option.disable_memory_utilization = True
        config._ranking_environment = environment
        config._ranking_environment_api = environment_api
        config._ranking_controller_adapter = adapter
    except BaseException:
        adapter.cleanup()
        raise


def pytest_unconfigure(config):
    adapter = getattr(config, '_ranking_controller_adapter', None)
    if adapter is None:
        return
    try:
        adapter.cleanup()
    except OSError as error:
        warnings.warn(pytest.PytestWarning(
            'Ranking controller adapter cleanup failed at {}: {}'.format(
                adapter.root, type(error).__name__)))
    finally:
        del config._ranking_controller_adapter


def _settings(config):
    cached = getattr(config, '_ranking_runtime', None)
    if cached is not None:
        return cached
    path = config.getoption('--ranking-config')
    output = config.getoption('--ranking-output')
    if not path or not output:
        raise pytest.UsageError(
            'Ranking requires --ranking-config and --ranking-output')
    try:
        environment = getattr(config, '_ranking_environment', None)
        environment_api = getattr(config, '_ranking_environment_api', None)
        if environment_api is None:
            environment_api = _load_environment_api(path)
            config._ranking_environment_api = environment_api
        if environment is None:
            environment = environment_api.load_environment(path)
            config._ranking_environment = environment
        profile_runtime = environment_api.compile_runtime(environment, path)
        package_runtime = load_run_assets()
        overlap = sorted(set(profile_runtime).intersection(package_runtime))
        if overlap:
            raise ValueError(
                'environment runtime overrides framework fields: {}'.format(
                    ', '.join(overlap)))
        runtime = dict(package_runtime, **profile_runtime)
        selector = config.getoption('--ranking-select') or 'priority:P0'
        selected = select_ranking_cases(runtime['manifest_data'], selector)
        output_root = Path(output).expanduser().resolve()
        sources = {name: Path(runtime[name]).resolve()
                   for name in SOURCE_PATH_FIELDS}
        sources['ranking_config'] = Path(path).expanduser().resolve()
        for name, source in sources.items():
            if (output_root == source or output_root in source.parents or
                    source in output_root.parents):
                raise ValueError(
                    'output must not overlap source {}: {} and {}'.format(
                        name, output_root, source))
    except (OSError, TypeError, ValueError) as error:
        raise pytest.UsageError(str(error)) from error
    config._ranking_runtime = runtime
    config._ranking_selected_cases = selected
    config._ranking_output = output_root
    return runtime


def pytest_generate_tests(metafunc):
    if 'ranking_case' not in metafunc.fixturenames:
        return
    config = metafunc.config
    if all(config.getoption(option) is None for option in (
            '--ranking-config', '--ranking-output', '--ranking-select')):
        metafunc.parametrize('ranking_case', [pytest.param(
            None, id='not-configured', marks=pytest.mark.skip(
                reason='Ranking requires --ranking-config '
                       'and --ranking-output'))])
        return
    _settings(config)
    metafunc.parametrize('ranking_case', config._ranking_selected_cases,
                         ids=config._ranking_selected_cases)


def _option(config, name):
    try:
        return config.getoption(name)
    except (AttributeError, ValueError):
        return None


@pytest.fixture(scope='session')
def ranking_session(request, ptfhost):
    """Validate Ready state and own only this process's temporary session."""
    config = request.config
    runtime = dict(_settings(config))
    root = Path(config._ranking_output)
    root.mkdir(parents=True, exist_ok=True)
    with artifact_store.exclusive(root):
        active = ptf_container.open_session(ptfhost, runtime)
        try:
            yield {
                'config': runtime,
                'ptf': ptfhost,
                'session': active,
                'output_root': root,
            }
        finally:
            ptf_container.close_session(ptfhost, active)
