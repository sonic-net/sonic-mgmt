"""
Nexthop AI platform test for the `nh_module` kernel module reload command.

Exercises `nh_module` (backed by `nexthop.module_reload_lib`) against real
hardware: `reload` of every declared custom kernel module, which for a
PDDF-declared module runs the full PDDF teardown and reinstall, the
declared-module guard for arbitrary module names, `reload-all`, that no `unload`
subcommand is exposed, and a post-reload health check of the PDDF stack and
platform daemons.
"""

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import check_critical_processes_for_service
from tests.platform_tests.pddf.pddf_helpers import check_pddf_device_json_exists, read_pddf_device_json

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
]


def _normalize(module_name):
    """Kernel module names in lsmod/pddf-device.json may use hyphens or underscores
    interchangeably; lsmod output always uses underscores."""
    return module_name.replace('-', '_')


def _get_loaded_modules(duthost):
    """Return {module_name: [dependent module names]} parsed from lsmod on duthost."""
    lsmod_output = duthost.command("lsmod")
    modules = {}
    for line in lsmod_output['stdout_lines'][1:]:
        if not line.strip():
            continue
        fields = line.split()
        name = fields[0]
        # lsmod joins multiple dependents with commas and no spaces, so the
        # whole list arrives as a single field.
        used_by = fields[3].split(',') if len(fields) > 3 and fields[3] != '-' else []
        modules[name] = [m for m in (dep.strip() for dep in used_by) if m]
    return modules


def _get_custom_kos(duthost):
    check_pddf_device_json_exists(duthost, skip_if_missing=True)
    pddf_device_data = read_pddf_device_json(duthost)
    custom_kos = pddf_device_data.get('PLATFORM', {}).get('custom_kos', [])
    if not custom_kos:
        pytest.skip("No 'custom_kos' declared in pddf-device.json, skipping test")
    return custom_kos


def _assert_declared_modules_loaded(duthost, pddf_device_data):
    platform = pddf_device_data.get('PLATFORM', {})
    declared = platform.get('pddf_kos', []) + platform.get('custom_kos', [])
    loaded_modules = _get_loaded_modules(duthost)
    missing = [mod for mod in declared if _normalize(mod) not in loaded_modules]
    pytest_assert(not missing, "Declared kernel modules missing after module reload: {}".format(missing))


def test_module_reload_restores_declared_custom_modules(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    For every custom kernel module declared in pddf-device.json that is currently
    loaded, reload it via `nh_module reload` and verify it (and any modules that
    depended on it) come back, and the overall PDDF stack stays healthy.

    A declared module takes the full teardown/reinstall path, so every other
    declared module has to come back too, not just the target and its dependents.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_pddf_device_json_exists(duthost, skip_if_missing=True)
    pddf_device_data = read_pddf_device_json(duthost)
    custom_kos = _get_custom_kos(duthost)

    loaded_modules = _get_loaded_modules(duthost)
    modules_to_test = [mod for mod in custom_kos if _normalize(mod) in loaded_modules]
    if not modules_to_test:
        pytest.skip("None of the declared custom_kos are currently loaded, skipping test")

    for module in modules_to_test:
        # Recompute on every iteration: reloading one module can change the live
        # dependency graph (or loaded state) of a module tested later in the loop.
        loaded_modules = _get_loaded_modules(duthost)
        dependents_before = loaded_modules.get(_normalize(module), [])
        logger.info("Reloading %s (dependents: %s)", module, dependents_before or "none")

        result = duthost.command("nh_module reload {}".format(module), module_ignore_errors=True)
        pytest_assert(
            result['rc'] == 0,
            "nh_module reload {} failed (rc={}): {}".format(module, result['rc'], result['stdout'])
        )

        loaded_modules_after = _get_loaded_modules(duthost)
        pytest_assert(
            _normalize(module) in loaded_modules_after, "{} is not loaded after reload".format(module)
        )
        missing_dependents = [dep for dep in dependents_before if dep not in loaded_modules_after]
        pytest_assert(
            not missing_dependents,
            "Dependents of {} did not come back after reload: {}".format(module, missing_dependents)
        )

        _assert_declared_modules_loaded(duthost, pddf_device_data)

    check_critical_processes_for_service(duthost, "pmon")


def test_module_commands_block_undeclared_module_by_default(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module reload` must refuse an arbitrary module name that isn't declared
    as a PDDF/custom module for this platform, without --any.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_pddf_device_json_exists(duthost, skip_if_missing=True)

    undeclared_module = "not_a_declared_module_xyz"

    reload_result = duthost.command(
        "nh_module reload {}".format(undeclared_module), module_ignore_errors=True
    )
    pytest_assert(
        reload_result['rc'] != 0,
        "nh_module reload should refuse an undeclared module by default"
    )


def test_reload_all_restores_declared_modules(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module reload-all` runs `pddf_util.py --force clean`, unloads whatever
    that leaves behind in dependency order, then `pddf_util.py install`; verify it
    succeeds and leaves every declared PDDF/custom module loaded and the platform
    healthy.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_pddf_device_json_exists(duthost, skip_if_missing=True)
    pddf_device_data = read_pddf_device_json(duthost)

    result = duthost.command("nh_module reload-all", module_ignore_errors=True)
    pytest_assert(
        result['rc'] == 0,
        "nh_module reload-all failed (rc={}): {}".format(result['rc'], result['stdout'])
    )

    _assert_declared_modules_loaded(duthost, pddf_device_data)
    check_critical_processes_for_service(duthost, "pmon")


def test_unload_subcommand_is_not_exposed(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module` must not offer an `unload` subcommand. A module left unloaded
    strands the platform with its PDDF devices deleted, so the switch can
    forward traffic with its sensors and telemetry gone.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command("nh_module unload any_module", module_ignore_errors=True)
    # click quotes the command name differently across 7.x/8.x, so match only the
    # stable part of its unknown-subcommand error.
    output = result['stdout'] + result['stderr']
    pytest_assert(
        result['rc'] != 0 and 'No such command' in output,
        "nh_module did not reject an unload subcommand (rc={}): {}".format(result['rc'], output)
    )
