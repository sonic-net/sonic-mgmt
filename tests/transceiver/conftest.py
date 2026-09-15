import os
import pytest
import logging
import warnings
from pathlib import Path

from tests.common.platform.interface_utils import (
    get_physical_port_indices,
    get_lport_to_first_subport_mapping,
)

# Import attribute parser components
from tests.transceiver.attribute_parser.dut_info_loader import DutInfoLoader
from tests.transceiver.attribute_parser.attribute_manager import AttributeManager
from tests.transceiver.attribute_parser.template_validator import STATUS_FULLY, STATUS_PARTIAL, TemplateValidator
from tests.transceiver.attribute_parser.exceptions import DutInfoError, AttributeMergeError, TemplateValidationError
from tests.transceiver.attribute_parser.utils import format_kv_block
from tests.transceiver.attribute_parser.paths import (
    REL_ATTR_DIR,
    REL_DEPLOYMENT_TEMPLATES_FILE,
    get_repo_root,
)

# Shared prerequisite + health-check primitives (also called from reportable test cases).
from tests.transceiver.common.prerequisites import (
    check_gold_firmware,
    check_links_up,
    check_presence_show_cli,
)
from tests.transceiver.common.health_checks import (
    POST_TEST_ACTIONS,
    PRE_TEST_ACTIONS,
    capture_baseline,
    run_post_check,
    run_pre_check,
    verify_health,
)

logger = logging.getLogger(__name__)

REPO_ROOT = get_repo_root()

# Session-wide health-check event log, consumed by pytest_terminal_summary.
# Category conftest files import this list and pass it to
# run_pre_check / run_post_check so all events accumulate in one place.
health_check_events = []

# Cached at module import to avoid a per-item filesystem resolve in
# pytest_collection_modifyitems.
_TRANSCEIVER_ROOT = Path(__file__).resolve().parent
_TRANSCEIVER_ROOT_PREFIX = os.path.join(str(_TRANSCEIVER_ROOT), "")


def _is_under_transceiver_root(item_path):
    """Return True iff *item_path* is inside this conftest's directory."""
    return str(item_path).startswith(_TRANSCEIVER_ROOT_PREFIX)


def pytest_addoption(parser):
    """Add transceiver infra specific CLI options."""
    parser.addoption(
        "--skip_transceiver_template_validation", action="store_true", default=False,
        help="Skip template validation even if deployment templates file exists"
    )
    parser.addoption(
        "--xcvr_pre_test_failure_action",
        action="store", default=PRE_TEST_ACTIONS[0], choices=list(PRE_TEST_ACTIONS),
        help=("Action when the per-test pre-check fails. "
              "'skip' (default) skips the test; 'warn' logs and lets the test run. "
              "Override per test with @pytest.mark.xcvr_pre_test_failure_action(<action>).")
    )
    parser.addoption(
        "--xcvr_post_test_failure_action",
        action="store", default=POST_TEST_ACTIONS[0], choices=list(POST_TEST_ACTIONS),
        help=("Action when the per-test post-check fails. "
              "'exit' (default) aborts the session; 'warn' logs and lets the run continue. "
              "Override per test with @pytest.mark.xcvr_post_test_failure_action(<action>).")
    )


def pytest_configure(config):
    """Register transceiver-specific markers."""
    # Re-register here because pytest discovers pyproject.toml at the repo
    # root as its configfile, which shadows tests/pytest.ini where this
    # marker is otherwise defined.
    config.addinivalue_line(
        "markers",
        "skip_check_dut_health: skip default execution of check_dut_health_status fixture",
    )
    config.addinivalue_line(
        "markers",
        "xcvr_pre_test_failure_action(action): override action on pre-test health check "
        "failure for this test. Valid values: " + ", ".join(PRE_TEST_ACTIONS) + ".",
    )
    config.addinivalue_line(
        "markers",
        "xcvr_post_test_failure_action(action): override action on post-test health check "
        "failure for this test. Valid values: " + ", ".join(POST_TEST_ACTIONS) + ".",
    )


def pytest_collection_modifyitems(config, items):
    """Tag every transceiver test with shared markers.

    Adds two markers to every collected item under ``tests/transceiver/``
    (and to its parent ``Module``):

    * ``topology("ptp")`` – the transceiver suite only runs on PTP testbeds;
      applying it here saves every test module from declaring ``pytestmark``.
    * ``skip_check_dut_health`` – the suite has its own per-test health check
      fixture (``_per_test_health_check``) that monitors core dumps and PIDs
      at finer granularity, so the global module-scoped
      ``core_dump_and_config_check`` fixture in ``tests/conftest.py`` is
      redundant.

    ``pytest_collection_modifyitems`` receives ALL items in the session, not
    just those under this conftest, so we filter by path. The parent
    ``Module`` is tagged in addition to each item because
    ``core_dump_and_config_check`` is module-scoped and inspects markers via
    ``request.node`` (the Module), which does not see item-level markers.
    """
    skip_marker = pytest.mark.skip_check_dut_health
    topology_marker = pytest.mark.topology("ptp")
    tagged_modules = set()
    for item in items:
        if not _is_under_transceiver_root(item.fspath):
            continue
        item.add_marker(skip_marker)
        item.add_marker(topology_marker)
        module = item.getparent(pytest.Module)
        if module is not None and module.nodeid not in tagged_modules:
            module.add_marker(skip_marker)
            module.add_marker(topology_marker)
            tagged_modules.add(module.nodeid)


def _load_platform_hwsku(duthost):
    """Derive (platform, hwsku) from a single duthost fixture.

    Returns (platform, hwsku) or (None, None) if unavailable.
    """
    try:
        if duthost:
            platform = duthost.facts.get('platform')
            hwsku = duthost.facts.get('hwsku')
            if platform and hwsku:
                return platform, hwsku
    except Exception as e:
        logger.error("Failed to derive platform/hwsku from duthost: %s", e)
    return None, None


def _validate_port_attribute_templates(
    request,
    ansible_root,
    dut_name,
    merged,
):
    """Return a template-validation error for *merged*, or ``None``."""
    templates_path = os.path.join(ansible_root, REL_DEPLOYMENT_TEMPLATES_FILE)
    skip_validation = request.config.getoption(
        '--skip_transceiver_template_validation'
    )
    if skip_validation or not os.path.isfile(templates_path):
        return None

    logger.info(
        "Validating transceiver attributes for DUT %s against templates in %s",
        dut_name,
        templates_path,
    )
    validator = TemplateValidator(ansible_root)
    try:
        compliance_dict = validator.validate(merged)
    except TemplateValidationError as error:
        return "template validation failed: {}".format(error)

    results = compliance_dict.get('results', [])
    fail_messages = []
    full_count = 0
    partial_count = 0
    fail_count = 0
    for result in results:
        status = result.get('status')
        port = result.get('port')
        deployment = result.get('deployment')
        if status == STATUS_FULLY:
            full_count += 1
            logger.info("PASS: %s (%s) - %s", port, deployment, status)
        elif status == STATUS_PARTIAL:
            partial_count += 1
            missing_optional = ', '.join(result.get('missing_optional', []))
            warnings.warn(
                "PARTIAL: {} missing optional: {}".format(
                    port,
                    missing_optional,
                )
            )
        else:
            fail_count += 1
            missing_required = ', '.join(result.get('missing_required', []))
            fail_messages.append(
                "{} missing required: {}".format(port, missing_required)
            )

    total_ports = compliance_dict.get('total_ports', len(results))
    logger.info(
        "Template validation summary for DUT %s: "
        "total=%d full=%d partial=%d fail=%d",
        dut_name,
        total_ports,
        full_count,
        partial_count,
        fail_count,
    )
    if fail_messages:
        return "template validation failures:\n{}".format(
            "\n".join(fail_messages)
        )
    return None


def _load_port_attributes(request, ansible_root, duthost):
    """Return ``(attributes, error, skippable)`` for one DUT.

    The selected-DUT and peer-DUT fixtures intentionally share this complete
    load, merge, and validation sequence. Their only difference is how the
    returned error is surfaced to the caller.
    """
    dut_name = duthost.hostname
    if not dut_name:
        return (
            None,
            "no DUT name available for transceiver attribute initialization",
            True,
        )

    platform, hwsku = _load_platform_hwsku(duthost)
    logger.info(
        "Transceiver infra context resolved: dut_name=%s platform=%s hwsku=%s",
        dut_name,
        platform,
        hwsku,
    )
    if not platform or not hwsku:
        logger.warning(
            "Platform/HWSKU not determined for DUT %s; "
            "platform/hwsku specific overrides may not apply",
            dut_name,
        )

    logger.info(
        "Building transceiver base port attributes for DUT '%s'",
        dut_name,
    )
    try:
        base_dict = DutInfoLoader(ansible_root).build_base_port_attributes(
            dut_name,
        )
    except DutInfoError as error:
        return (
            None,
            "failed loading base port attributes: {}".format(error),
            False,
        )

    if not base_dict:
        return (
            None,
            "no ports found for DUT '{}' in dut_info.json".format(dut_name),
            True,
        )

    attr_dir = os.path.join(ansible_root, REL_ATTR_DIR)
    if not os.path.isdir(attr_dir):
        return None, "attributes directory {} is absent".format(attr_dir), True

    logger.info(
        "Merging category attributes for DUT %s from %s",
        dut_name,
        attr_dir,
    )
    try:
        merged = AttributeManager(
            ansible_root,
            base_dict,
        ).build_port_attributes(
            dut_name, platform or '', hwsku or ''
        )
    except AttributeMergeError as error:
        return (
            None,
            "category attribute merging failed: {}".format(error),
            False,
        )

    if not merged:
        return (
            None,
            "no merged attributes found for DUT '{}'".format(dut_name),
            True,
        )

    validation_error = _validate_port_attribute_templates(
        request,
        ansible_root,
        dut_name,
        merged,
    )
    if validation_error:
        return None, validation_error, False
    return merged, None, False


@pytest.fixture(scope='session')
def port_attributes_dict(request, ansible_root, duthost):
    """Session-scoped merged port attributes (BASE + category).

    Loads base and category data through the shared canonical loader. It then
    applies optional template validation and selected-DUT fail/skip behavior.
    """
    attributes, error, skippable = _load_port_attributes(
        request,
        ansible_root,
        duthost,
    )
    if error:
        if skippable:
            pytest.skip(error)
        pytest.fail(error)
    return attributes


def _build_port_attributes_loader(
    request,
    ansible_root,
    duthost,
    duthosts,
    port_attributes_dict,
):
    """Build the cached per-DUT attribute loader used by the fixture."""
    attributes_by_dut = {duthost.hostname: port_attributes_dict}
    hosts_by_name = {host.hostname: host for host in duthosts}
    hosts_by_name[duthost.hostname] = duthost

    def _load(hostname):
        if hostname in attributes_by_dut:
            return attributes_by_dut[hostname], None
        host = hosts_by_name.get(hostname)
        if host is None:
            return None, "DUT host is unavailable"
        attributes, error, _skippable = _load_port_attributes(
            request,
            ansible_root,
            host,
        )
        if error:
            return None, error
        attributes_by_dut[host.hostname] = attributes
        logger.info(
            "Loaded transceiver attributes for peer DUT %s: %d port(s)",
            host.hostname,
            len(attributes),
        )
        return attributes, None

    return _load


@pytest.fixture(scope='session')
def port_attributes_for_dut(
    request,
    ansible_root,
    duthost,
    duthosts,
    port_attributes_dict,
):
    """Return a cached loader for the selected DUT and an actually used peer.

    Peer-aware tests resolve the connection graph before calling this loader.
    That keeps missing inventory on an unrelated DUT from failing the entire
    transceiver session, while preserving a clear error for a peer that is
    actually needed by the test.
    """
    return _build_port_attributes_loader(
        request,
        ansible_root,
        duthost,
        duthosts,
        port_attributes_dict,
    )


# Ensure infra initialized before any test in this package
@pytest.fixture(autouse=True, scope='session')
def _ensure_transceiver_infra_initialized(port_attributes_dict):
    logger.info("Transceiver infrastructure initialized: %d ports", len(port_attributes_dict))
    for port, categories in port_attributes_dict.items():
        for category, attrs in categories.items():
            logger.info(format_kv_block(f"{port} {category}", attrs))
    return


# ──────────────────────────────────────────────────────────────────────
# Session-wide guard: skip the entire transceiver suite on virtual switch
# testbeds. VS DUTs lack physical optics, ``xcvrd`` does not run, and the
# per-test health check would otherwise mass-skip every test with a
# misleading message about a missing process.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True, scope="session")
def _skip_transceiver_suite_on_vs(duthost):
    """Skip every transceiver test when the DUT is a virtual switch."""
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Transceiver tests are not supported on virtual switch testbed")


@pytest.fixture(scope="session")
def lport_to_first_subport_mapping(duthost):
    """Map each logical port to its breakout group's first sub-port.

    Resolved once per session (it hits the DUT via ansible facts / sonic-db-cli)
    and shared by every test that needs first-sub-port filtering, so the mapping
    is not re-queried per test.  Pair with
    ``interface_utils.is_first_subport``.
    """
    return get_lport_to_first_subport_mapping(duthost)


def _build_lport_mapping_loader(
    duthost,
    duthosts,
    lport_to_first_subport_mapping,
):
    """Build the cached per-DUT logical-to-primary-subport loader."""
    mappings_by_dut = {duthost.hostname: lport_to_first_subport_mapping}
    hosts_by_name = {host.hostname: host for host in duthosts}
    hosts_by_name[duthost.hostname] = duthost

    def _load(hostname):
        if hostname in mappings_by_dut:
            return mappings_by_dut[hostname], None
        host = hosts_by_name.get(hostname)
        if host is None:
            return None, "DUT host is unavailable"
        try:
            mapping = get_lport_to_first_subport_mapping(host)
        except Exception as error:
            return None, "failed loading logical-port mapping: {}".format(error)
        if mapping is None:
            return None, "logical-port mapping is unavailable"
        mappings_by_dut[hostname] = mapping
        logger.info(
            "Loaded logical-port mapping for peer DUT %s: %d port(s)",
            hostname,
            len(mapping),
        )
        return mapping, None

    return _load


@pytest.fixture(scope="session")
def lport_to_first_subport_mapping_for_dut(
    duthost,
    duthosts,
    lport_to_first_subport_mapping,
):
    """Return a cached loader for an actually used DUT's port mapping."""
    return _build_lport_mapping_loader(
        duthost,
        duthosts,
        lport_to_first_subport_mapping,
    )


# ──────────────────────────────────────────────────────────────────────
# Session-scoped prerequisite fixtures (gates).
# These are session-scoped (computed once per session) but NOT autouse —
# a category opts in by requesting the fixture from its own conftest.py
# (typically via an autouse fixture that lists the gates as parameters).
# Each gate wraps a check primitive in common/prerequisites.py and calls
# pytest.skip on failure so every dependent test is skipped with a clear
# message.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def presence_verified(duthost, port_attributes_dict):
    """Gate: all transceivers in port_attributes_dict are present.

    Opted into by DOM, System, CDB FW (via their category conftests).
    EEPROM does NOT opt in — it owns the presence test cases directly.
    """
    result = check_presence_show_cli(duthost, port_attributes_dict)
    if not result["passed"]:
        pytest.skip(f"presence_verified prerequisite failed - {result['details']}")
    logger.info("presence_verified prerequisite PASSED: %s", result["details"])
    return result


@pytest.fixture(scope="session")
def gold_fw_verified(duthost, port_attributes_dict):
    """Gate: every CMIS active-optical transceiver runs its gold firmware.

    A port is in scope iff its ``EEPROM_ATTRIBUTES.cmis_active_optical`` is
    True; for those ports ``CDB_FIRMWARE_UPGRADE_ATTRIBUTES.gold_firmware_version``
    MUST be configured AND must match the active firmware reported by the CLI.
    Other ports are out of scope (no expectation to compare against).

    Opted into by DOM, System (via their category conftests). CDB FW does
    NOT opt in — it owns the gold-firmware test case directly.
    """
    result = check_gold_firmware(duthost, port_attributes_dict)
    if not result["passed"]:
        pytest.skip(f"gold_fw_verified prerequisite failed - {result['details']}")
    logger.info("gold_fw_verified prerequisite PASSED: %s", result["details"])
    return result


@pytest.fixture(scope="session")
def links_verified(duthost, port_attributes_dict):
    """Gate: every transceiver port in port_attributes_dict is admin-up and oper-up.

    Opted into by EEPROM, DOM, System, CDB FW (via their category
    conftests). Port Config does NOT opt in — its tests query CONFIG_DB
    only and do not require live links.
    """
    result = check_links_up(duthost, port_attributes_dict)
    if not result["passed"]:
        pytest.skip(f"links_verified prerequisite failed - {result['details']}")
    logger.info("links_verified prerequisite PASSED: %s", result["details"])
    return result


# ──────────────────────────────────────────────────────────────────────
# Per-test health-check fixture (autouse, function-scoped).
# Pre-test failures skip the test; post-test failures abort the session.
# Both phases append to health_check_events for the terminal summary.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def expected_pid_changes():
    """Per-test set of monitored-process names allowed to change PID.

    Empty by default, so any monitored-process restart is treated as a
    regression by the post-test health check — the strict behavior every
    existing test relies on, unchanged.

    A test (or a subcategory conftest) that intentionally restarts a daemon
    adds the process name to this set so the parent ``_per_test_health_check``
    treats the PID change as expected instead of a failure. The set is mutable
    and shared with the parent fixture for the duration of the test, so it can
    be populated at runtime — e.g. a test that restarts ``pmon`` (which forces
    an ``xcvrd`` restart) calls ``expected_pid_changes.add("xcvrd")`` before
    issuing the restart. This is additive: the parent fixture remains the
    single owner of the xcvrd/core check; subcategories feed it intent rather
    than overriding it.
    """
    return set()


@pytest.fixture(autouse=True)
def _per_test_health_check(request, duthost, expected_pid_changes):
    """Capture health baseline before each test; verify before and after."""
    baseline = capture_baseline(duthost)
    logger.debug("Health baseline captured for %s", request.node.name)

    pre_checks = [
        (f"process_{process}_running", status == "RUNNING",
         f"Process {process} is {status}, expected RUNNING")
        for process, (status, _pid) in baseline["pid_baselines"].items()
    ]
    run_pre_check(request, pre_checks, health_check_events)

    yield

    result = verify_health(duthost, baseline, expect_pid_change=expected_pid_changes)
    post_checks = [
        ("system_health", result["passed"], "; ".join(result["failures"])),
    ]
    run_post_check(request, post_checks, health_check_events)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print a consolidated health-check report at the end of the session."""
    if not health_check_events:
        return
    terminalreporter.section("Health Check Summary")
    for event in health_check_events:
        action = event.get("action", "")
        action_str = f" action={action}" if action else ""
        terminalreporter.write_line(
            f"  [{event['phase']}{action_str}] {event['test']}: {event['details']}"
        )


@pytest.fixture(scope="session")
def get_lport_to_pport_mapping(duthost):
    """
    Fixture to get the mapping of logical ports to physical ports.

    Uses the canonical shared ``duthost`` fixture (``duthosts[session.dut_index]``)
    so this mapping is computed against the same DUT as the rest of the suite —
    ``port_attributes_dict``, ``lport_to_first_subport_mapping``, the prerequisite
    gates, and the per-test health checks all resolve their DUT the same way.
    """
    lport_to_pport_mapping = get_physical_port_indices(duthost)

    logging.info("Logical to Physical Port Mapping: {}".format(lport_to_pport_mapping))
    return lport_to_pport_mapping
