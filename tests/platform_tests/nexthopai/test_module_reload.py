"""
Nexthop AI platform test for the `nh_module` kernel module reload command.

Exercises `nh_module` (backed by `nexthop.module_reload_lib`) against real
hardware: dependency-aware unload/reload of every declared custom kernel
module, the --no-recursive guard rail when a module is in use, the
declared-module guard for arbitrary module names, reload from an
already-unloaded state, `reload-all`, and a post-reload health check of the
PDDF stack and platform daemons.
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
        used_by = fields[3:] if len(fields) > 3 else []
        modules[name] = [m.rstrip(',') for m in used_by if m.rstrip(',')]
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


def test_module_reload_from_unloaded_state(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module reload` must also work when the module was already unloaded
    beforehand (e.g. to swap its .ko file), not just when reloading a
    currently-loaded module.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_pddf_device_json_exists(duthost, skip_if_missing=True)
    pddf_device_data = read_pddf_device_json(duthost)
    custom_kos = _get_custom_kos(duthost)

    loaded_modules = _get_loaded_modules(duthost)
    # Pick a module with no current dependents so unloading it doesn't cascade
    # into other modules and complicate verifying this specific scenario.
    module = next(
        (mod for mod in custom_kos if not loaded_modules.get(_normalize(mod))),
        None,
    )
    if module is None:
        pytest.skip("No declared custom_kos module without dependents is currently loaded, skipping test")

    unload_result = duthost.command(
        "nh_module unload {} --no-recursive".format(module), module_ignore_errors=True
    )
    pytest_assert(
        unload_result['rc'] == 0,
        "Failed to unload {} to set up the already-unloaded reload test (rc={}): {}".format(
            module, unload_result['rc'], unload_result['stdout']
        )
    )

    reload_result = duthost.command("nh_module reload {}".format(module), module_ignore_errors=True)
    pytest_assert(
        reload_result['rc'] == 0,
        "nh_module reload {} from an already-unloaded state failed (rc={}): {}".format(
            module, reload_result['rc'], reload_result['stdout']
        )
    )

    loaded_modules_after = _get_loaded_modules(duthost)
    pytest_assert(
        _normalize(module) in loaded_modules_after,
        "{} is not loaded after reloading from an already-unloaded state".format(module)
    )

    _assert_declared_modules_loaded(duthost, pddf_device_data)
    check_critical_processes_for_service(duthost, "pmon")


def test_module_unload_no_recursive_fails_when_in_use(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module unload --no-recursive` must refuse to unload a module that other
    loaded modules currently depend on, and must leave it untouched. Recovers by
    reloading the module (which also restores any auto-loaded dependents) so the
    DUT is left as it was found.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_pddf_device_json_exists(duthost, skip_if_missing=True)
    pddf_device_data = read_pddf_device_json(duthost)
    custom_kos = _get_custom_kos(duthost)

    loaded_modules = _get_loaded_modules(duthost)
    module_in_use = next(
        (mod for mod in custom_kos if loaded_modules.get(_normalize(mod))),
        None,
    )
    if module_in_use is None:
        pytest.skip("No declared custom_kos module currently has dependents, skipping test")

    unload_result = duthost.command(
        "nh_module unload {} --no-recursive".format(module_in_use), module_ignore_errors=True
    )
    pytest_assert(
        unload_result['rc'] != 0,
        "nh_module unload --no-recursive should have failed for {}".format(module_in_use)
    )
    pytest_assert(
        "is in use by" in unload_result['stdout'],
        "Expected a 'is in use by' refusal reason in nh_module unload --no-recursive output for {}, got: {}"
        .format(module_in_use, unload_result['stdout'])
    )

    loaded_modules_after = _get_loaded_modules(duthost)
    pytest_assert(
        _normalize(module_in_use) in loaded_modules_after,
        "{} should still be loaded after a failed --no-recursive unload".format(module_in_use)
    )

    # Restore state in case the module (or its dependents) were disturbed.
    reload_result = duthost.command("nh_module reload {}".format(module_in_use), module_ignore_errors=True)
    pytest_assert(
        reload_result['rc'] == 0,
        "Failed to restore {} after --no-recursive test (rc={}): {}".format(
            module_in_use, reload_result['rc'], reload_result['stdout']
        )
    )

    _assert_declared_modules_loaded(duthost, pddf_device_data)
    check_critical_processes_for_service(duthost, "pmon")


def test_module_commands_block_undeclared_module_by_default(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module unload`/`reload` must refuse an arbitrary module name that isn't
    declared as a PDDF/custom module for this platform, without --any.
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

    unload_result = duthost.command(
        "nh_module unload {}".format(undeclared_module), module_ignore_errors=True
    )
    pytest_assert(
        unload_result['rc'] != 0,
        "nh_module unload should refuse an undeclared module by default"
    )


def test_reload_all_restores_declared_modules(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    `nh_module reload-all` runs the full `pddf_util.py clean && install` cycle;
    verify it succeeds and leaves every declared PDDF/custom module loaded and
    the platform healthy.
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
