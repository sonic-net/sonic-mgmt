import os
import pytest
import logging
import warnings
from pathlib import Path

from .inventory.parser import TransceiverInventory

from tests.common.platform.interface_utils import get_physical_port_indices

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


@pytest.fixture(scope='session')
def port_attributes_dict(request, duthost):
    """Session-scoped merged port attributes (BASE + category).

    Loads dut_info.json via DutInfoLoader and merges category attribute files via AttributeManager.
    Optionally validates templates. Failure scenarios abort early to avoid invalid test runs.
    Logs compliance summary (if performed) before returning the merged attributes dict.
    """
    dut_name = duthost.hostname
    if not dut_name:
        pytest.skip("No DUT name available for transceiver attribute initialization")

    platform, hwsku = _load_platform_hwsku(duthost)
    logger.info(
        "Transceiver infra context resolved: dut_name=%s platform=%s hwsku=%s", dut_name, platform, hwsku
    )
    if not platform or not hwsku:
        logger.warning("Platform/HWSKU not determined; platform/hwsku specific overrides may not apply")

    logger.info("Building transceiver base port attributes for DUT '%s'", dut_name)
    loader = DutInfoLoader(REPO_ROOT)
    try:
        base_dict = loader.build_base_port_attributes(dut_name)
    except DutInfoError as e:
        pytest.fail(f"Failed loading base port attributes: {e}")

    if not base_dict:
        pytest.skip(f"No ports found for DUT '{dut_name}' in dut_info.json")

    attr_dir = os.path.join(REPO_ROOT, REL_ATTR_DIR)
    if not os.path.isdir(attr_dir):
        pytest.skip(f"Attributes directory {attr_dir} absent; returning base attributes only")

    logger.info("Merging category attributes from %s", attr_dir)
    mgr = AttributeManager(REPO_ROOT, base_dict)
    try:
        merged = mgr.build_port_attributes(dut_name, platform or '', hwsku or '')
    except AttributeMergeError as e:
        pytest.fail(f"Category attribute merging failed: {e}")
    if not merged:
        pytest.skip(f"No merged attributes found for DUT '{dut_name}'")

    # Run compliance validation (validator handles detailed logging and raises on required misses)
    templates_path = os.path.join(REPO_ROOT, REL_DEPLOYMENT_TEMPLATES_FILE)
    if not request.config.getoption('--skip_transceiver_template_validation') and os.path.isfile(templates_path):
        logger.info("Validating transceiver attributes against templates in %s", templates_path)
        validator = TemplateValidator(REPO_ROOT)
        try:
            # Validate merged attributes; raises on missing required attributes (partials only warn)
            compliance_dict = validator.validate(merged)
            results = compliance_dict.get('results', [])
            fail_messages = []
            full_count = 0
            partial_count = 0
            fail_count = 0
            for r in results:
                status = r.get('status')
                port = r.get('port')
                deployment = r.get('deployment')
                if status == STATUS_FULLY:
                    full_count += 1
                    logger.info("PASS: %s (%s) - %s", port, deployment, status)
                elif status == STATUS_PARTIAL:
                    partial_count += 1
                    missing_opt = ', '.join(r.get('missing_optional', []))
                    warnings.warn(f"PARTIAL: {port} missing optional: {missing_opt}")
                else:
                    fail_count += 1
                    missing_req = ', '.join(r.get('missing_required', []))
                    fail_messages.append(f"{port} missing required: {missing_req}")
            total_ports = compliance_dict.get('total_ports', len(results))
            logger.info(
                "Template validation summary: total=%d full=%d partial=%d fail=%d",
                total_ports,
                full_count,
                partial_count,
                fail_count,
            )
            if fail_messages:
                pytest.fail("Template validation failures:\n" + "\n".join(fail_messages))
        except TemplateValidationError as e:
            pytest.fail(f"Template validation failed: {e}")

    return merged


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
    True; for those ports ``CDB_FW_UPGRADE_ATTRIBUTES.gold_firmware_version``
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


@pytest.fixture(autouse=True)
def _per_test_health_check(request, duthost):
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

    result = verify_health(duthost, baseline)
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
def transceiver_inventory_obj():
    """
    Fixture to provide a single TransceiverInventory object for the session.
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    return TransceiverInventory(base_path)


@pytest.fixture(scope="session")
def get_transceiver_inventory(transceiver_inventory_obj):
    """
    Fixture to provide transceiver inventory information.
    """
    return transceiver_inventory_obj.get_transceiver_info()


@pytest.fixture(scope="session")
def get_transceiver_common_attributes(transceiver_inventory_obj):
    """
    Fixture to provide common attributes from TransceiverInventory.
    """
    return transceiver_inventory_obj.common_attributes


@pytest.fixture(scope="session")
def get_dev_transceiver_details(duthost, get_transceiver_inventory):
    """
    Get transceiver details from transceiver_inventory for the given DUT.

    @param duthost: DUT host
    @param get_transceiver_inventory: Transceiver inventory
    @return: Returns transceiver details in a dictionary for the given DUT with port as key
    """
    hostname = duthost.hostname
    details = get_transceiver_inventory.get(hostname, {})
    if not details:
        logging.error(f"No transceiver details found for host: {hostname}")
    return details


@pytest.fixture(scope="module")
def get_lport_to_pport_mapping(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture to get the mapping of logical ports to physical ports.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lport_to_pport_mapping = get_physical_port_indices(duthost)

    logging.info("Logical to Physical Port Mapping: {}".format(lport_to_pport_mapping))
    return lport_to_pport_mapping
