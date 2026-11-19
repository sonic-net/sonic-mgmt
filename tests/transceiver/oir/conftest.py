"""OIR category conftest.

Backs both halves of ``docs/testplan/transceiver/online_insertion_removal_testplan.md``:
Physical OIR (``test_physical_oir.py``, ``PHYSICAL_OIR_ATTRIBUTES``) and Remote
reseat (``test_remote_reseat.py``, ``REMOTE_RESEAT_ATTRIBUTES``).

Both halves opt into the cross-category ``presence_verified`` and
``links_verified`` session-level prerequisites defined in
``tests/transceiver/conftest.py``: every module under test must start seated
and linked up.  Physical OIR intentionally does NOT request ``gold_fw_verified``
because its behaviour is firmware-version independent; Remote reseat requests
it in its test module, per the prerequisite matrix in
``docs/testplan/transceiver/test_plan.md``.

The fixtures specific to one half are not autouse: each test module opts into
its own through ``pytestmark``, so neither half's attribute category gates the
other's tests.
"""
import http.client
import logging

import pytest

from tests.common.platform.device_utils import SERVER_PORT, start_platform_api_server
from tests.common.platform.interface_utils import get_pport_presence_data
from tests.transceiver.attribute_parser.attribute_keys import (
    PHYSICAL_OIR_ATTRIBUTES_KEY,
    REMOTE_RESEAT_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common.port_selectors import select_attribute_ports
from tests.transceiver.common.prerequisites import build_dom_polling_failures
from tests.transceiver.common.state_management import post_state_restoration
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)

_DUT_SCOPED_OIR_ATTRIBUTES = (
    "ports_under_test",
    "oir_method",
    "physical_oir_timeout_min",
    "simultaneous_oir",
    "physical_oir_stress_iteration",
    "hot_swap_ports_under_test",
)
_DUT_SCOPED_RESEAT_ATTRIBUTES = (
    "ports_under_test",
    "remote_reseat_stress_iteration",
)


@pytest.fixture(autouse=True, scope="package")
def _oir_session_prerequisites(presence_verified, links_verified):
    """Autouse wrapper pulling in the session gates consumed by OIR tests."""
    return


def _select_category_ports(port_attributes_dict, attribute_key, dut_scoped_attributes):
    """Select ports with ``attribute_key`` attributes and validate its DUT-scoped settings.

    Per-transceiver settings stay in ``port_attributes_dict`` and are read from
    each port's ``attribute_key`` shard by the tests. The selected logical port
    names are returned only after the DUT-scoped settings have been validated
    across every configured port.
    """
    ports = select_attribute_ports(port_attributes_dict, attribute_key).primary_ports
    if not ports:
        pytest.skip(f"No {attribute_key} configured for this DUT")

    reference_port = ports[0]
    reference_attrs = port_attributes_dict[reference_port][attribute_key]
    missing = [key for key in dut_scoped_attributes if key not in reference_attrs]
    if missing:
        pytest.fail(
            f"{attribute_key} for {reference_port} missing DUT-scoped setting(s): {missing}"
        )

    inconsistent = {}
    for port in ports:
        category_attrs = port_attributes_dict[port][attribute_key]
        differing_keys = [
            key
            for key in dut_scoped_attributes
            if category_attrs.get(key) != reference_attrs[key]
        ]
        if differing_keys:
            inconsistent[port] = differing_keys
    if inconsistent:
        pytest.fail(f"DUT-scoped {attribute_key} differ by port: {inconsistent}")
    return ports


def _resolve_ports_under_test(port_attributes_dict, attribute_ports, attribute_key, lport_to_pport, label):
    """``{physical index: [logical ports]}`` for the ``attribute_key`` ``ports_under_test``.

    Every logical port of a physical port under test must carry
    ``attribute_key`` attributes.
    """
    pports = port_attributes_dict[attribute_ports[0]][attribute_key]["ports_under_test"]
    if not pports:
        pytest.skip(f"{label} 'ports_under_test' is empty")

    mapping = oir_helpers.resolve_pport_to_lports(lport_to_pport, pports)
    unmapped = [pport for pport, lports in mapping.items() if not lports]
    if unmapped:
        pytest.fail(f"ports_under_test physical port(s) {unmapped} have no logical port on this DUT")

    configured = set(attribute_ports)
    unconfigured = [
        port
        for lports in mapping.values()
        for port in lports
        if port not in configured
    ]
    if unconfigured:
        pytest.fail(f"port(s) under test without {attribute_key}: {unconfigured}")

    logger.info("Ports under test for %s: %s", label, mapping)
    return mapping


# ──────────────────────────────────────────────────────────────────────
# Physical OIR
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def physical_oir_attribute_ports(port_attributes_dict):
    """Select ports with physical OIR attributes and validate DUT-scoped settings."""
    return _select_category_ports(port_attributes_dict, PHYSICAL_OIR_ATTRIBUTES_KEY, _DUT_SCOPED_OIR_ATTRIBUTES)


@pytest.fixture(scope="package")
def _skip_unimplemented_oir_method(port_attributes_dict, physical_oir_attribute_ports):
    """Only the operator-driven ``manual`` method is implemented today."""
    method = port_attributes_dict[
        physical_oir_attribute_ports[0]
    ][PHYSICAL_OIR_ATTRIBUTES_KEY]["oir_method"]
    if method != oir_helpers.OIR_METHOD_MANUAL:
        pytest.skip(f"oir_method '{method}' is not implemented yet")


@pytest.fixture(scope="session")
def oir_pport_to_lports(
    port_attributes_dict,
    physical_oir_attribute_ports,
    get_lport_to_pport_mapping,
):
    """``{physical index: [logical ports]}`` for the configured ``ports_under_test``."""
    return _resolve_ports_under_test(
        port_attributes_dict, physical_oir_attribute_ports, PHYSICAL_OIR_ATTRIBUTES_KEY,
        get_lport_to_pport_mapping, "physical OIR")


@pytest.fixture(scope="session")
def hot_swap_ports_under_test(port_attributes_dict, physical_oir_attribute_ports, oir_pport_to_lports):
    """``[physical index, XcvrApi class name]`` pairs for the TC5/TC6 hot-swap tests."""
    swaps = port_attributes_dict[
        physical_oir_attribute_ports[0]
    ][PHYSICAL_OIR_ATTRIBUTES_KEY]["hot_swap_ports_under_test"]
    if not swaps:
        pytest.skip("physical OIR 'hot_swap_ports_under_test' is empty")

    unknown = [pport for pport, _ in swaps if pport not in oir_pport_to_lports]
    if unknown:
        pytest.fail(f"hot_swap_ports_under_test physical port(s) {unknown} are not in ports_under_test")
    return swaps


@pytest.fixture
def oir_platform_api_conn(duthost, localhost):
    """Platform API server connection; its Sfp objects outlive a hot swap, like xcvrd's."""
    start_platform_api_server(duthost, localhost)
    conn = http.client.HTTPConnection(
        duthost.get_mgmt_ip()["mgmt_ip"], SERVER_PORT, timeout=oir_helpers.PLATFORM_API_TIMEOUT_SEC)
    yield conn
    conn.close()


@pytest.fixture
def _restore_transceivers(
    request,
    duthost,
    port_attributes_dict,
    physical_oir_attribute_ports,
    oir_pport_to_lports,
):
    """Re-seat any module a test left out of its cage before the next test runs."""
    yield

    presence = get_pport_presence_data(duthost)
    missing = [pport for pport in oir_pport_to_lports if pport not in presence]
    if missing:
        pytest.exit(
            "Physical OIR teardown could not determine transceiver presence: "
            f"physical port(s) {missing} missing from CLI output",
            returncode=1,
        )

    absent = [pport for pport in oir_pport_to_lports if not presence[pport]]
    if not absent:
        return
    logger.warning("Physical OIR teardown: re-seating %d module(s) left removed", len(absent))
    oir_attrs = port_attributes_dict[
        physical_oir_attribute_ports[0]
    ][PHYSICAL_OIR_ATTRIBUTES_KEY]
    failures = oir_helpers.perform_oir(
        request, duthost, oir_attrs, absent, present=True,
        action="INSERT the original transceiver(s) - test teardown",
    )
    if failures:
        # The session-scoped presence/link gates do not re-run, so continuing
        # would test a switch with modules still out of their cages.
        pytest.exit(
            "Physical OIR teardown could not re-seat the transceiver(s): "
            + "; ".join(failures),
            returncode=1,
        )


# ──────────────────────────────────────────────────────────────────────
# Remote reseat
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def remote_reseat_attribute_ports(port_attributes_dict):
    """Select ports with remote reseat attributes and validate DUT-scoped settings."""
    return _select_category_ports(port_attributes_dict, REMOTE_RESEAT_ATTRIBUTES_KEY, _DUT_SCOPED_RESEAT_ATTRIBUTES)


@pytest.fixture(scope="session")
def reseat_pport_to_lports(
    port_attributes_dict,
    remote_reseat_attribute_ports,
    get_lport_to_pport_mapping,
):
    """``{physical index: [logical ports]}`` for the remote reseat ``ports_under_test``.

    A remote reseat resets every module under test, so each one must support it.
    """
    mapping = _resolve_ports_under_test(
        port_attributes_dict, remote_reseat_attribute_ports, REMOTE_RESEAT_ATTRIBUTES_KEY,
        get_lport_to_pport_mapping, "remote reseat")
    no_reset = [
        port
        for lports in mapping.values()
        for port in lports
        if not port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY]["transceiver_reset_supported"]
    ]
    if no_reset:
        pytest.fail(f"remote reseat port(s) under test without transceiver_reset_supported: {no_reset}")
    return mapping


@pytest.fixture
def _restore_reseat_state(
    duthost,
    port_attributes_dict,
    reseat_pport_to_lports,
    lport_to_first_subport_mapping,
):
    """Require DOM monitoring on the modules under test, and restore their state after the test.

    The reseat's last step enables DOM monitoring, so it must be enabled before
    too.  A failed remote reseat can leave a module with DOM monitoring
    disabled, in low power mode or with its ports down; all are restored.
    """
    _, lports = oir_helpers.all_ports(reseat_pport_to_lports)
    modules = oir_helpers.parents_of(lports, lport_to_first_subport_mapping)
    failures = build_dom_polling_failures(duthost, modules)
    if failures:
        pytest.fail("Remote reseat requires DOM monitoring on the modules under test: " + "; ".join(failures))

    yield

    # The DOM and port restorations are independent: a failure, or an exception,
    # in one must not keep the other from running or the session from aborting.
    failures = []
    try:
        if build_dom_polling_failures(duthost, modules):
            logger.warning("Remote reseat teardown: re-enabling DOM monitoring on %s", modules)
            failures += oir_helpers.set_dom_monitoring(duthost, modules, enable=True)
    except (Exception, pytest.fail.Exception) as exc:
        logger.exception("Remote reseat teardown: DOM monitoring restoration raised")
        failures.append(f"DOM monitoring restoration raised {exc!r}")
    try:
        summary = post_state_restoration(duthost, {port: port_attributes_dict[port] for port in lports})
    except (Exception, pytest.fail.Exception) as exc:
        logger.exception("Remote reseat teardown: port restoration raised")
        failures.append(f"port restoration raised {exc!r}")
    else:
        restored = {
            key: summary[key]
            for key in ("lpmode_high_restored", "admin_up_restored", "link_bounced")
            if summary[key]
        }
        if restored:
            logger.warning("Remote reseat teardown restored: %s", restored)
        failures += summary["still_failing"]
    if failures:
        # The session-scoped link gate does not re-run, so continuing would
        # test a switch with ports left down or in low power mode.
        pytest.exit(
            "Remote reseat teardown could not restore the port(s) under test: " + "; ".join(failures),
            returncode=1,
        )
