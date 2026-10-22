"""Translate Prepare CLI input into one immutable workflow context."""

from dataclasses import dataclass
import hashlib
import importlib.util
from pathlib import Path
import warnings

import pytest

from tests.ranking.common.sonic_mgmt_adapter import (
    create_controller_adapter, explicit_standard_options,
)


PREPARE_STEPS = ('configure_env', 'check_env', 'sync_cases')
DRIVER_HOOKS = ('describe', 'configure_env', 'check_env')
ENVIRONMENT_HOOKS = (
    'load_environment', 'controller_spec', 'compile_runtime',
)


@dataclass(frozen=True)
class PrepareContext:
    """All inputs and standard hosts owned by one Prepare invocation."""

    environment_root: Path
    environment_file: Path
    case_root: object
    steps: tuple
    force_sync: bool
    duthost: object
    ptfhost: object
    tbinfo: object
    environment_api: object
    driver: object


def normalize_prepare_steps(value):
    """Validate a comma-separated selector and return canonical execution order."""
    if value is None:
        return PREPARE_STEPS
    if not isinstance(value, str) or not value:
        raise pytest.UsageError('ranking prepare steps must be a non-empty list')
    requested = value.split(',')
    if (any(not item for item in requested) or len(requested) != len(set(requested))
            or any(item not in PREPARE_STEPS for item in requested)):
        raise pytest.UsageError(
            'ranking prepare steps must be unique values from: {}'.format(
                ', '.join(PREPARE_STEPS)))
    return tuple(step for step in PREPARE_STEPS if step in requested)


def validate_prepare_options(steps, force_sync, case_root):
    """Validate relationships between the three independent Prepare actions."""
    if force_sync and 'sync_cases' not in steps:
        raise pytest.UsageError(
            '--ranking-force-sync requires sync_cases in --ranking-prepare-steps')
    if 'sync_cases' in steps and case_root is None:
        raise pytest.UsageError(
            '--ranking-cases must name the case root when sync_cases is selected')


def _real_directory(path, description):
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise pytest.UsageError('{} must not be a symlink: {}'.format(
            description, candidate))
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise pytest.UsageError('{} must be an existing directory: {}'.format(
            description, resolved))
    return resolved


def _real_file(path, description):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise pytest.UsageError('{} must be a regular file: {}'.format(
            description, candidate))
    return candidate.resolve()


def load_environment_driver(path):
    """Load the fixed Prepare interface from an arbitrary environment directory."""
    root = _real_directory(path, 'Ranking environment root')
    environment_file = _real_file(
        root / 'environment.yml', 'Ranking environment.yml')
    environment_implementation = _real_file(
        root / 'environment.py', 'Ranking environment environment.py')
    implementation = _real_file(
        root / 'prepare.py', 'Ranking environment prepare.py')

    def load_module(source, prefix, hooks):
        digest = hashlib.sha256(str(source).encode('utf-8')).hexdigest()[:16]
        spec = importlib.util.spec_from_file_location(
            '{}_{}'.format(prefix, digest), str(source))
        if spec is None or spec.loader is None:
            raise pytest.UsageError(
                'cannot load Ranking environment module: {}'.format(source))
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as error:
            raise pytest.UsageError(
                'cannot load Ranking environment module: {}'.format(source)) from error
        for hook in hooks:
            if not callable(getattr(module, hook, None)):
                raise pytest.UsageError(
                    '{} requires callable {}'.format(source.name, hook))
        return module

    environment_api = load_module(
        environment_implementation, '_ranking_environment_api', ENVIRONMENT_HOOKS)
    driver = load_module(implementation, '_ranking_prepare_driver', DRIVER_HOOKS)
    return root, environment_file, environment_api, driver


def _option(config, name):
    try:
        return config.getoption(name)
    except (AttributeError, ValueError):
        return None


def pytest_addoption(parser):
    group = parser.getgroup('ranking prepare')
    group.addoption(
        '--ranking-environment', default=None, metavar='DIR',
        help=(
            'environment package containing environment.yml, environment.py, '
            'and prepare.py'))
    group.addoption(
        '--ranking-cases', default=None, metavar='DIR',
        help='Ranking case root containing the ptf directory to synchronize')
    group.addoption(
        '--ranking-prepare-steps', default=None,
        help='comma-separated subset of configure_env,check_env,sync_cases')
    group.addoption(
        '--ranking-force-sync', action='store_true', default=False,
        help='replace an existing PTF case directory when sync_cases is selected')


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    """Wire the selected package into standard sonic-mgmt host fixtures."""
    selected = _option(config, '--ranking-environment')
    if selected is None:
        return
    steps = normalize_prepare_steps(_option(config, '--ranking-prepare-steps'))
    force_sync = bool(_option(config, '--ranking-force-sync'))
    selected_cases = _option(config, '--ranking-cases')
    validate_prepare_options(steps, force_sync, selected_cases)
    case_root = None
    if selected_cases is not None:
        case_root = _real_directory(selected_cases, 'Ranking case root')
        _real_directory(case_root / 'ptf', 'Ranking PTF case root')
    explicit = explicit_standard_options(config)
    if explicit:
        raise pytest.UsageError(
            'Ranking environment owns standard controller options: {}'.format(
                ', '.join(explicit)))
    root, environment_file, environment_api, driver = load_environment_driver(selected)
    preview = PrepareContext(
        environment_root=root,
        environment_file=environment_file,
        case_root=None,
        steps=(),
        force_sync=False,
        duthost=None,
        ptfhost=None,
        tbinfo=None,
        environment_api=environment_api,
        driver=driver,
    )
    try:
        description = driver.describe(preview)
        adapter = create_controller_adapter(description['controller_spec'])
    except Exception as error:
        raise pytest.UsageError(str(error)) from error
    try:
        config.option.ansible_inventory = str(adapter.inventory)
        config.option.testbed = adapter.testbed
        config.option.testbed_file = str(adapter.testbed_file)
        config.option.ansible_host_pattern = adapter.host_pattern
        config.option.skip_sanity = True
        config.option.ignore_conditional_mark = True
        config.option.disable_memory_utilization = True
        config._ranking_controller_adapter = adapter
        config._ranking_prepare_driver = driver
        config._ranking_prepare_environment_api = environment_api
        config._ranking_prepare_environment_root = root
        config._ranking_prepare_environment_file = environment_file
        config._ranking_prepare_case_root = case_root
        config._ranking_prepare_steps = steps
        config._ranking_prepare_force_sync = force_sync
    except BaseException:
        adapter.cleanup()
        raise


def pytest_unconfigure(config):
    """Remove private sonic-mgmt adapter files created by Prepare."""
    adapter = getattr(config, '_ranking_controller_adapter', None)
    if adapter is None:
        return
    try:
        adapter.cleanup()
    except OSError as error:
        warnings.warn(pytest.PytestWarning(
            'Ranking Prepare controller adapter cleanup failed at {}: {}'.format(
                adapter.root, type(error).__name__)))
    finally:
        del config._ranking_controller_adapter


def pytest_collection_modifyitems(config, items):
    """Skip the explicit entry when no Prepare environment was selected."""
    if _option(config, '--ranking-environment') is not None:
        return
    marker = pytest.mark.skip(reason='Ranking Prepare requires --ranking-environment')
    for item in items:
        if (Path(str(item.fspath)).name == 'test_prepare.py'
                and getattr(item, 'originalname', None) == 'test_prepare_workflow'):
            item.add_marker(marker)


@pytest.fixture(scope='session')
def ranking_prepare_context(request, duthost, ptfhost, tbinfo):
    """Build context only; all business actions remain visible in the test entry."""
    config = request.config
    driver = getattr(config, '_ranking_prepare_driver', None)
    if driver is None:
        raise pytest.UsageError('Ranking Prepare requires --ranking-environment')
    return PrepareContext(
        environment_root=config._ranking_prepare_environment_root,
        environment_file=config._ranking_prepare_environment_file,
        case_root=config._ranking_prepare_case_root,
        steps=config._ranking_prepare_steps,
        force_sync=config._ranking_prepare_force_sync,
        duthost=duthost,
        ptfhost=ptfhost,
        tbinfo=tbinfo,
        environment_api=config._ranking_prepare_environment_api,
        driver=driver,
    )
