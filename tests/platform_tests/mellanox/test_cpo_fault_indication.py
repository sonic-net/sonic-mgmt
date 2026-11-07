"""
SW-controlled CPO -- Fault Indication tests.

The CPO Fault Indication feature registers the SDK ``interrupt`` fds into
the xcvrd poll loop, delegates the COR-safe EEPROM read of the CPO reason
pages (0x0, 0x11, 0x1A) to ``dom_mgr`` (via the APPL_DB
``REFRESH_COUNTERS_ON_DEMAND`` / ``_DONE`` pub/sub channels), logs parsed
faults to syslog (WARNING) and writes ``xcvr_cpo_*`` fault tokens into the
dedicated STATE_DB field ``TRANSCEIVER_STATUS_SW|<port>.xcvr_fault`` so
gNMI on_change subscribers receive them over the existing STATE_DB
telemetry path.

This feature is the *sole writer* of ``xcvr_fault``; the
``error`` field on the same row stays owned by xcvrd and is never touched
by this feature.

  * TC-1  Single fault  -- WARNING syslog + STATE_DB token + gNMI notify
          (subscribed at row level; see the note in the test body).
  * TC-2  Multiple faults concatenated (|-separated, no duplicates).
  * TC-3  The xcvrd-owned ``error`` field is left untouched while the
          feature writes ``xcvr_fault`` (single-writer guarantee).
  * TC-4  An ELS-scoped fault is written to ALL logical ports of the
          affected vModule.

Fault injection goes through the PMFT access register via ``mlxreg``, on
SIMX and physical ASICs alike; see
``tests/platform_tests/mellanox/cpo_fault_injection.py``. PMFT exposes only
``set_laser_source_fault``, so every injectable fault is ELS/laser scoped --
module-level thermal faults cannot be injected on this platform.

Because one PMFT ``module_index`` is one ELS (one vModule), each test
consumes a distinct vModule; ``target_vmodule`` hands out an unused one
per test.

The suite runs only when the CPO + SW-control gates hold (skipped
otherwise), reusing the gates from
``tests/platform_tests/mellanox/conftest.py``.
"""
import logging
import random
import threading

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.platform.processes_utils import check_pmon_uptime_minutes
from tests.common.utilities import wait_until
from tests.platform_tests.mellanox.cpo_cli_helpers import dump_transceiver_state_db
from tests.platform_tests.mellanox.cpo_fault_helpers import (
    GNMI_LOCAL_ADDR,
    TRANSCEIVER_STATUS_SW_TABLE,
    assert_fault_token_count,
    ensure_xcvr_fault_field,
    reset_baseline,
    fault_tokens,
    get_cpo_logical_ports,
    get_vmodule_port_groups,
    read_xcvr_fault,
    extract_gnmi_values,
    gnmi_subscribe_onchange_on_dut,
    read_xcvrd_error,
    wait_all_tokens,
    wait_fault_token,
)
from tests.platform_tests.mellanox.cpo_fault_injection import (
    CpoFaultInjector,
    syslog_regex_for,
    token_for,
)
from tests.platform_tests.mellanox.software_control_helper import check_sc_sai_attribute_value
from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.helpers.gnmi_utils import (
    GNMIEnvironment,
    copy_certificate_to_dut,
    delete_gnmi_certs,
    prepare_client_cert,
    prepare_root_cert,
    prepare_server_cert,
)
from tests.common.gnmi_setup import apply_cert_config, recover_cert_config

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox"),
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,  # each test drives its own LogAnalyzer
]

# How long to wait for the interrupt to be processed and STATE_DB updated.
# Propagation latency is highly variable on SIMX -- measured in one session:
# ELS 0 reported in 2s, ELS 5 in ~10s, and ELS 6 and 11 in ~90s, the last two
# sitting right on a 90s bound. 120s covers the observed spread with headroom.
FAULT_PROCESS_TIMEOUT = 120
FAULT_PROCESS_INTERVAL = 3
# -expected_count for the TC-1 gNMI client. Deliberately far above any real
# update count so the client runs for the whole streaming timeout and the
# token is searched for afterwards; 0 would make it exit after ~1s.
GNMI_UPDATE_COUNT = 1000
# How long the worker waits for the DUT-local subscriber to connect before
# injecting. Separate from the fault wait: this covers client startup only.
GNMI_CONNECT_TIMEOUT = 60
# Total lifetime of the TC-1 gNMI client (it runs the full time, see
# GNMI_UPDATE_COUNT).
GNMI_SUBSCRIBE_TIMEOUT = 120
# CONFIG_DB checkpoint taken before the gNMI mTLS config is applied, so
# teardown can put the DUT back exactly as it was found.
CPO_GNMI_CHECKPOINT = "cpo_fault_gnmi"


# ---------------------------------------------------------------------------
# Gates + shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def _require_sw_controlled_cpo(
    duthosts, rand_one_dut_hostname, is_cpo_supported,
):
    """Skip suite unless CPO platform + SW control hold."""
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_multi_asic:
        pytest.skip("CPO fault tests require a single-ASIC DUT")
    sw_control = check_sc_sai_attribute_value(duthost)
    missing = []
    if not is_cpo_supported:
        missing.append("CPO platform (hwsku.json port_type=CPO)")
    if not sw_control:
        missing.append("SW control (sai.profile SAI_INDEPENDENT_MODULE_MODE=1)")
    if missing:
        pytest.skip("Test requires: " + "; ".join(missing))


@pytest.fixture(scope="function")
def cpo_gnmi_server(duthost, localhost):
    """Configure the DUT's gNMI server for mTLS, and restore it afterwards.

    Function-scoped and requested by TC-1 alone: it is the only test that
    needs gNMI. Module scope would leave the reconfigured (mTLS) server in
    place for TC-2..TC-4, which neither need it nor should be exposed to
    it -- they would then run against a DUT whose telemetry config differs
    from how they found it.

    Deliberately does NOT reuse ``tests.gnmi.conftest.setup_gnmi_server``:
    that fixture takes ``ptfhost`` and installs the client certificate onto
    PTF, but some CPO testbeds have no PTF host at all. Everything else it does is DUT-local, so this
    fixture calls the same shared helpers minus the PTF steps, and the
    subscription runs on the DUT (see
    ``gnmi_subscribe_onchange_on_dut``).

    The server certificate is bound to ``GNMI_LOCAL_ADDR`` rather than the
    management IP, since that is the address the DUT-local client dials.

    Teardown restores the DUT to how it was found: the gNMI container is
    restarted (returning the gNMI process to its supervisord-managed form),
    the CONFIG_DB checkpoint is rolled back, and the generated certificates
    are removed.

    Setup runs inside the ``try`` so a failure part-way through still gets
    cleaned up, and each teardown step only runs if its setup step started.
    Teardown steps run independently: one failing does not skip the rest,
    and the failures are reported together at the end.
    """
    certs_created = checkpoint_created = cert_config_applied = False
    try:
        certs_created = True
        prepare_root_cert(localhost)
        prepare_server_cert(duthost, localhost, dut_ip=GNMI_LOCAL_ADDR)
        prepare_client_cert(localhost)
        copy_certificate_to_dut(duthost)

        create_checkpoint(duthost, CPO_GNMI_CHECKPOINT)
        checkpoint_created = True
        cert_config_applied = True
        apply_cert_config(duthost)
        yield
    finally:
        failures = []

        def _attempt(step, func, *args):
            try:
                func(*args)
            except (Exception, pytest.fail.Exception) as err:
                logger.error("cpo_gnmi_server teardown: %s failed: %s", step, err)
                failures.append("{}: {}".format(step, err))

        if cert_config_applied:
            _attempt("recover_cert_config", recover_cert_config, duthost)
        if checkpoint_created:
            _attempt("rollback", rollback, duthost, CPO_GNMI_CHECKPOINT)
            duthost.shell("config save -y", module_ignore_errors=True)
        if certs_created:
            _attempt("delete_gnmi_certs", delete_gnmi_certs, localhost)
        pytest_assert(not failures, "gNMI teardown incomplete: " + "; ".join(failures))


@pytest.fixture(scope="module")
def cpo_state_db_snapshot(duthost):
    """One STATE_DB snapshot of all TRANSCEIVER_* tables."""
    pytest_assert(
        wait_until(360, 10, 0, check_pmon_uptime_minutes, duthost),
        "Pmon docker is not ready for test",
    )
    snap = dump_transceiver_state_db(duthost)
    pytest_assert(snap, "STATE_DB has no TRANSCEIVER_* entries")
    return snap


@pytest.fixture(scope="module")
def cpo_vmodule_groups(duthost, cpo_state_db_snapshot):
    """{module_index: [logical_port, ...]} for every CPO vModule."""
    cpo_ports = get_cpo_logical_ports(cpo_state_db_snapshot)
    pytest_assert(cpo_ports, "No CPO ports found in STATE_DB TRANSCEIVER_INFO")
    groups = get_vmodule_port_groups(duthost, cpo_ports)
    pytest_assert(groups, "Could not group CPO ports into vModules")
    return groups


@pytest.fixture(scope="module")
def consumed_vmodules():
    """ELS indices already used for injection in this module run.

    Tracking the consumed set lets every test start from a genuinely fresh
    vModule.
    """
    return set()


@pytest.fixture(scope="function")
def target_vmodule(duthost, cpo_vmodule_groups, consumed_vmodules):
    """Pick a random unused oper-up vModule (ELS index + its logical ports).

    Per the test design the target vModule/ELS/logical port is chosen
    randomly among the eligible (oper-up) CPO vModules; vModules already
    consumed by an earlier test in this run are excluded (see
    ``consumed_vmodules``).
    """
    intf_status = duthost.show_and_parse("show interface status")
    oper_up = {
        e["interface"] for e in intf_status
        if e.get("oper", "").lower() == "up"
    }
    # Faults are injected on laser 0, which surfaces on ports[0], so that
    # slice itself must be oper-up -- another slice of the group being up is
    # not enough.
    eligible = [
        idx for idx, ports in cpo_vmodule_groups.items()
        if idx not in consumed_vmodules and ports and ports[0] in oper_up
    ]
    if not eligible:
        pytest.skip(
            "No unused oper-up CPO vModule left for fault injection "
            "(consumed={})".format(sorted(consumed_vmodules)))
    idx = random.choice(eligible)
    consumed_vmodules.add(idx)
    ports = cpo_vmodule_groups[idx]
    # Laser 0 of the ELS surfaces on the first logical slice of the group.
    target_port = ports[0]
    logger.info("target vModule els=%s target=%s ports=%s", idx, target_port, ports)
    return idx, ports, target_port


@pytest.fixture(scope="function")
def fault_injector(duthost, target_vmodule):
    """CpoFaultInjector bound to the target vModule; fully undone on teardown.

    Teardown runs all three steps ``clear_faults`` needs to undo an
    injection -- disarm the PMFT fault selector, reset the vModule (which
    both clears the pg1A latch and brings the faulted laser's port back
    oper-up), and delete the append-only STATE_DB token. The whole vModule
    group is passed so the token is dropped from every port the fault was
    fanned out to, not just the injected one.
    """
    idx, ports, target_port = target_vmodule
    injector = CpoFaultInjector(duthost, els_index=idx, logical_port=target_port)
    yield injector
    injector.clear_faults(ports=ports)


# ---------------------------------------------------------------------------
# LogAnalyzer helper
# ---------------------------------------------------------------------------
def _start_loganalyzer(duthost, marker_prefix, expected_regexes):
    """Bracket syslog to assert the expected CPO fault WARNING lines appear.

    Only ``expect_regex`` is configured (not ``load_common_config``): this
    suite deliberately verifies that each injected fault produces its own
    WARNING token, and must not fail on pre-existing unrelated syslog noise
    (module-wide LogAnalyzer is disabled via the ``disable_loganalyzer``
    marker). ``match_regex`` is left empty so the analyzer never flags
    unrelated lines as unexpected errors.
    """
    la = LogAnalyzer(ansible_host=duthost, marker_prefix=marker_prefix)
    marker = la.init()
    la.match_regex = []
    la.ignore_regex = []
    la.expect_regex = list(expected_regexes)
    return la, marker


def _assert_expected_syslogs(la, marker):
    result = la.analyze(marker, fail=False)
    missing = result.get("unused_expected_regexp")
    pytest_assert(
        not missing,
        "Missing expected CPO fault WARNING syslog(s): {}; matched={}".format(
            missing, result.get("expect_messages")),
    )


def _gnmi_subscriber_connected(duthost):
    """wait_until predicate: the DUT-local gNMI client has connected.

    The subscriber runs on the DUT itself, so its session shows up as a
    loopback connection to the telemetry port. Waiting for it guarantees
    the subscription is in place before the fault is injected -- otherwise
    the on_change notification would be missed.
    """
    port = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE).gnmi_port
    # ``ss`` prints the state first and the address last, so match on the
    # peer column rather than netstat's "<addr>:<port> ... ESTABLISHED"
    # ordering. ``-H`` drops the header so a match is always a real socket.
    result = duthost.shell(
        "ss -tnH state established '( dport = :{port} or sport = :{port} )'".format(port=port),
        module_ignore_errors=True,
    )
    return bool(result.get("stdout", "").strip())


# ===========================================================================
# TC-1: Single fault -- WARNING log, DB update, gNMI notification
# ===========================================================================
@pytest.mark.usefixtures("cpo_gnmi_server")
def test_tc1_single_fault_indication(duthost, target_vmodule, fault_injector):
    """TC-1: a single CPO fault -> WARNING syslog + STATE_DB token + gNMI."""
    _, _, target_port = target_vmodule
    fault_key = "apc_failure_warning"
    laser = 0
    token = token_for(fault_key, laser)

    with allure.step("Reset baseline: clear xcvr_fault on the target port"):
        reset_baseline(duthost, [target_port])
        # The field must exist before subscribing, or no update is streamed.
        ensure_xcvr_fault_field(duthost, target_port)

    # The injection runs in the background while the gNMI helper blocks in
    # the foreground. This mirrors the existing gNMI on_change tests and
    # guarantees no long-lived subscriber thread survives a test failure.
    #
    # Catch BaseException, not Exception: pytest_assert calls pytest.fail(),
    # whose Failed derives from BaseException. A bare "except Exception"
    # lets it escape the thread unrecorded, leaving worker_result clean and
    # the test reporting a missing STATE_DB token instead of the real cause.
    worker_result = {"connected": False, "injected": False, "exception": None}

    def _inject_worker():
        try:
            worker_result["connected"] = wait_until(
                GNMI_CONNECT_TIMEOUT, 2, 0, _gnmi_subscriber_connected, duthost)
            if not worker_result["connected"]:
                return
            fault_injector.inject_fault(fault_key, laser=laser)
            worker_result["injected"] = True
        except BaseException as exc:  # noqa: BLE001
            worker_result["exception"] = "{}: {}".format(type(exc).__name__, exc)

    la, marker = _start_loganalyzer(
        duthost, "cpo_fault_tc1", [syslog_regex_for(fault_key, laser, target_port)])
    worker = threading.Thread(target=_inject_worker)
    worker.start()
    # Field-level subscription
    # (STATE_DB/TRANSCEIVER_STATUS_SW/<port>/xcvr_fault). The first update is
    # the initial snapshot of the field reset_baseline just cleared (an empty
    # value); a later one is the injected fault token. The initial update
    # count is not stable, so the client runs the full timeout and the token
    # is looked up in the collected values afterwards.
    #
    # The client runs for GNMI_SUBSCRIBE_TIMEOUT in total. Typical connect
    # and propagation are far shorter; the STATE_DB check below carries the
    # full FAULT_PROCESS_TIMEOUT for the slow case.
    path = "{}/{}/xcvr_fault".format(TRANSCEIVER_STATUS_SW_TABLE, target_port)
    gnmi_output, gnmi_stderr = gnmi_subscribe_onchange_on_dut(
        duthost, path, GNMI_UPDATE_COUNT,
        timeout_s=GNMI_SUBSCRIBE_TIMEOUT)
    # The client has exited by now, so the worker is long done.
    worker.join(GNMI_SUBSCRIBE_TIMEOUT)

    # Fail on what actually went wrong, before looking at any downstream
    # effect. Without this the test reports a missing STATE_DB token even
    # when the injection never ran, which points debugging at the feature
    # rather than at the gNMI setup that really failed.
    pytest_assert(not worker.is_alive(), "CPO fault injection worker timed out")
    pytest_assert(
        not worker_result["exception"],
        "CPO fault injection worker raised: {}".format(worker_result["exception"]),
    )
    pytest_assert(
        worker_result["connected"],
        "gNMI on_change subscriber never connected to the telemetry port, so "
        "the fault was never injected. gNMI client stderr={!r}".format(gnmi_stderr),
    )
    pytest_assert(
        worker_result["injected"],
        "CPO fault injection did not complete",
    )

    with allure.step("Verify STATE_DB fault token"):
        db_ok = wait_until(
            FAULT_PROCESS_TIMEOUT, FAULT_PROCESS_INTERVAL, 0,
            wait_fault_token, duthost, target_port, token)
        pytest_assert(
            db_ok,
            "STATE_DB {}|{}.xcvr_fault missing token '{}'; actual={!r}".format(
                TRANSCEIVER_STATUS_SW_TABLE, target_port, token,
                read_xcvr_fault(duthost, target_port)),
        )
        assert_fault_token_count(duthost, target_port, 1)

    with allure.step("Verify WARNING syslog entry"):
        _assert_expected_syslogs(la, marker)

    with allure.step("Verify gNMI on_change notification"):
        values = extract_gnmi_values(gnmi_output)
        pytest_assert(
            token in values,
            "gNMI on_change notification for {}|{}.xcvr_fault did not contain token "
            "'{}'; values={!r}, output={!r}, stderr={!r}".format(
                TRANSCEIVER_STATUS_SW_TABLE, target_port, token,
                values, gnmi_output, gnmi_stderr),
        )


# ===========================================================================
# TC-2: Multiple different faults concatenated in DB
# ===========================================================================
def test_tc2_multiple_faults_concatenated(
    duthost, target_vmodule, fault_injector,
):
    """TC-2: two different faults -> both tokens |-separated, no duplicates.

    Both faults target the same vModule on two different lasers, so the
    shared ELS lane-code page (pg1A:212-219) ends up holding two non-zero
    nibbles and the RMW-union fan-out should render them ``|``-separated
    on every logical port of the vModule.
    """
    _, _, target_port = target_vmodule

    fault_key = "apc_failure_warning"
    first_laser, second_laser = 0, 1
    first_token = token_for(fault_key, first_laser)
    second_token = token_for(fault_key, second_laser)

    la, marker = _start_loganalyzer(
        duthost, "cpo_fault_tc2",
        [syslog_regex_for(fault_key, first_laser, target_port),
         syslog_regex_for(fault_key, second_laser, target_port)])

    with allure.step("Reset baseline: clear xcvr_fault on the target port"):
        reset_baseline(duthost, [target_port])

    with allure.step("Inject two faults on different lasers of one ELS"):
        fault_injector.inject_fault(fault_key, laser=first_laser)
        fault_injector.inject_fault(fault_key, laser=second_laser)

    with allure.step("Both tokens land in xcvr_fault"):
        pytest_assert(
            wait_until(FAULT_PROCESS_TIMEOUT, FAULT_PROCESS_INTERVAL, 0,
                       wait_all_tokens, duthost, target_port,
                       [first_token, second_token]),
            "xcvr_fault missing one of {}; actual={!r}".format(
                [first_token, second_token],
                read_xcvr_fault(duthost, target_port)),
        )

    with allure.step("Verify |-separated, exactly two tokens"):
        # Two tokens that include both expected ones also rules out duplicates.
        tokens_list = assert_fault_token_count(duthost, target_port, 2)
        pytest_assert(
            set(tokens_list) == {first_token, second_token},
            "Unexpected xcvr_fault tokens {}; expected {} and {}".format(
                tokens_list, first_token, second_token),
        )

    with allure.step("Verify WARNING syslog for both faults"):
        _assert_expected_syslogs(la, marker)


# ===========================================================================
# TC-3: Single-writer guarantee -- xcvrd's 'error' field stays untouched
# ===========================================================================
def test_tc3_xcvrd_error_field_untouched(
    duthost, target_vmodule, fault_injector,
):
    """TC-3: the feature writes ``xcvr_fault`` and never the xcvrd ``error``.

    The fault-indication feature is the sole writer of the
    dedicated ``xcvr_fault`` field and must not touch the xcvrd-owned
    ``error`` field on the same TRANSCEIVER_STATUS_SW row. This snapshots
    ``error`` on every port of the vModule before injection and asserts it
    is byte-for-byte unchanged afterwards.

    Note this is deliberately *not* a DOM-vs-platform cross-check: PMFT can
    only inject ELS laser faults (``set_laser_source_fault`` is its one
    writable fault selector), and those do not raise a module-level DOM
    flag such as ``tempHAlarm``, so no injectable fault reaches both paths.
    """
    _, ports, target_port = target_vmodule
    fault_key = "laser_high_power_alarm"
    laser = 0
    token = token_for(fault_key, laser)

    with allure.step("Reset baseline, snapshot xcvrd 'error'"):
        reset_baseline(duthost, ports)
        baseline_errors = {p: read_xcvrd_error(duthost, p) for p in ports}

    with allure.step("Inject ELS laser high-power alarm"):
        fault_injector.inject_fault(fault_key, laser=laser)

    with allure.step("Platform-code path: STATE_DB xcvr_fault token"):
        pytest_assert(
            wait_until(FAULT_PROCESS_TIMEOUT, FAULT_PROCESS_INTERVAL, 0,
                       wait_fault_token, duthost, target_port, token),
            "Platform path: {}|{}.xcvr_fault missing '{}'; actual={!r}".format(
                TRANSCEIVER_STATUS_SW_TABLE, target_port, token,
                read_xcvr_fault(duthost, target_port)),
        )

    with allure.step("Single-writer: xcvrd-owned 'error' field untouched"):
        changed = {
            p: (baseline_errors[p], read_xcvrd_error(duthost, p))
            for p in ports
            if read_xcvrd_error(duthost, p) != baseline_errors[p]
        }
        pytest_assert(
            not changed,
            "xcvrd-owned 'error' field must stay untouched by fault "
            "indication; changed (baseline, current): {}".format(changed),
        )
        leaked = {
            p: read_xcvrd_error(duthost, p) for p in ports
            if token in fault_tokens(read_xcvrd_error(duthost, p))
        }
        pytest_assert(
            not leaked,
            "CPO token '{}' leaked into the xcvrd-owned 'error' field: {}".format(
                token, leaked),
        )

    with allure.step("xcvr_fault still carries the platform token"):
        pytest_assert(
            token in fault_tokens(read_xcvr_fault(duthost, target_port)),
            "Platform-code token '{}' missing from xcvr_fault".format(token),
        )
        assert_fault_token_count(duthost, target_port, 1)


# ===========================================================================
# TC-4: Single vModule fault writes to all related logical ports
# ===========================================================================
def test_tc4_vmodule_fault_all_logical_ports(
    duthost, target_vmodule, fault_injector,
):
    """TC-4: an ELS-scoped fault is written to EVERY logical port of the
    affected vModule, not just the injected one.

    Page 0x1A belongs to the ELS that all banks of a vModule share, so the
    feature fans the token out to every logical port of the vModule -- on
    SN6810_LD that is four banks x two breakout splits = eight ports.
    """
    idx, ports, target_port = target_vmodule

    if len(ports) <= 1:
        pytest.skip("Target CPO vModule maps to a single logical port")

    fault_key = "laser_high_power_alarm"
    laser = 0
    token = token_for(fault_key, laser)

    logger.info("TC-4 vModule els=%s logical ports=%s", idx, ports)

    with allure.step("Reset baseline: clear xcvr_fault on every vModule port"):
        reset_baseline(duthost, ports)

    with allure.step("Inject ELS-scoped fault ({})".format(fault_key)):
        fault_injector.inject_fault(fault_key, laser=laser)

    with allure.step("Verify token present on ALL logical ports"):
        # Wait once, on the first port only. The fan-out is atomic --
        # the feature writes every split of the vModule in one loop,
        # and the resulting WARNING lines share a timestamp to the
        # microsecond -- so once any port has the token the rest already do.
        #
        # Waiting per port would turn a genuine failure into
        # len(ports) * FAULT_PROCESS_TIMEOUT of dead time (eight ports x 120s
        # = 16 minutes) while telling us nothing the first timeout did not.
        pytest_assert(
            wait_until(FAULT_PROCESS_TIMEOUT, FAULT_PROCESS_INTERVAL, 0,
                       wait_fault_token, duthost, ports[0], token),
            "ELS-scoped fault '{}' never reached {}; xcvr_fault={!r}".format(
                token, ports[0], read_xcvr_fault(duthost, ports[0])),
        )
        failures = [
            "{}: xcvr_fault={!r}".format(port, read_xcvr_fault(duthost, port))
            for port in ports[1:]
            if not wait_fault_token(duthost, port, token)
        ]
        pytest_assert(
            not failures,
            "ELS-scoped fault '{}' not written to all vModule ports:\n  - "
            "{}".format(token, "\n  - ".join(failures)),
        )

    with allure.step("Verify exactly one token on every logical port"):
        for port in ports:
            assert_fault_token_count(duthost, port, 1)
