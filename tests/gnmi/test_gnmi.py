from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from tests.common.helpers import gnmi_cli_helpers as helper
from tests.common.helpers.dut_utils import creds_on_dut
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import (
    PygnmiClient,
    PygnmiClientCallError,
    PygnmiClientError,
    StreamMode,
)
from tests.common.utilities import paramiko_ssh, wait_until

from .helper import (
    apply_cert_config,
    build_pygnmi_client,
    dump_gnmi_log,
    wait_for_gnmi_server,
)

logger = logging.getLogger(__name__)
allure.logger = logger

MEMORY_CHECKER_WAIT = 1
MEMORY_CHECKER_CYCLES = 60
MEMORY_SPIKE_CONNECTIONS = 2000

SHOW_PATHS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "cli_paths.json")


@pytest.fixture
def skip_non_container_test(request):
    if not request.config.getoption("--container_test", default=""):
        pytest.skip("Testcase skipped for non container test")


pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures(
        "setup_gnmi_ntp_client_server", "setup_gnmi_server", "setup_gnmi_rotated_server", "check_dut_timestamp"
    ),
]


def test_gnmi_capabilities(pygnmi_client: PygnmiClient):
    """
    Verify GNMI capabilities
    """
    result = pygnmi_client.capabilities()

    model_names = [model.get("name") for model in result.get("supported_models", [])]
    assert "sonic-db" in model_names, (
        "'sonic-db' not found in GNMI capabilities supported_models.\n"
        f"- Model names: {model_names}\n"
        f"- Full response: {result}"
    )

    encodings = result.get("supported_encodings", [])
    assert "json_ietf" in encodings, (
        "'json_ietf' not found in GNMI capabilities supported_encodings.\n"
        f"- Encodings: {encodings}\n"
        f"- Full response: {result}"
    )


@pytest.fixture(scope="function")
def setup_crl_server_on_ptf(ptfhost, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # Determine which address to bind the CRL server to
    dut_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    is_mgmt_ipv6_only = dut_facts.get("is_mgmt_ipv6_only", False)

    if is_mgmt_ipv6_only and ptfhost.mgmt_ipv6:
        # Bind to IPv6 address when DUT is IPv6-only
        bind_addr = ptfhost.mgmt_ipv6
        logger.info(f"DUT is IPv6-only, binding CRL server to IPv6: {bind_addr}")
    else:
        # Bind to all interfaces (default behavior) for IPv4 or mixed environments
        bind_addr = ""
        logger.info("Binding CRL server to all interfaces (IPv4 compatible)")

    ptfhost.shell("rm -f /root/crl.log")

    # Start CRL server with appropriate bind address
    if bind_addr:
        ptfhost.shell(f"nohup /root/env-python3/bin/python /root/crl_server.py --bind {bind_addr} &")
    else:
        ptfhost.shell("nohup /root/env-python3/bin/python /root/crl_server.py &")

    logger.warning("crl server started")

    # Wait untill HTTP server ready
    def server_ready_log_exist(ptfhost):
        res = ptfhost.shell("sed -n '/Ready handle request/p'  /root/crl.log", module_ignore_errors=True)
        logger.debug("crl.log: {}".format(res["stdout_lines"]))
        return len(res["stdout_lines"]) > 0

    wait_until(60, 1, 0, server_ready_log_exist, ptfhost)
    logger.warning("crl server ready")

    yield

    # pkill will use the kill signal -9 as exit code, need ignore error
    ptfhost.shell("pkill -9 -f '/root/env-python3/bin/python /root/crl_server.py'", module_ignore_errors=True)


def test_gnmi_subscribe_sample(rand_selected_dut, pygnmi_client: PygnmiClient):
    """
    Verify GNMI subscribe sample request
    """
    duthost = rand_selected_dut

    # Skip test for supervisor nodes as they don't have Ethernet0 frontpanel port
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    # The server's minimum (MinSampleInterval in sonic-gnmi's db_client.go).
    interval = timedelta(seconds=1)
    # The server re-arms its sample timer only after marshalling each payload, so gaps run long by
    # the marshalling time (large for a whole COUNTERS table on a big DUT), but never short.
    min_gap, max_gap = interval - timedelta(milliseconds=500), interval * 2
    count = 5
    # Only a deadline in case the server stalls: subscribe() returns as soon as it has count notifications.
    timeout = max_gap * count + timedelta(seconds=15)

    def validates_subscribe_sample(path: str, target: str | None = None) -> None:
        # The server sends the snapshot, sync_response, then samples; pygnmi's StreamSubscriber merges
        # everything up to the sync_response into the first notification.
        notifications = list(
            pygnmi_client.subscribe(
                path,
                target=target,
                sample_interval=interval.total_seconds(),
                count=count,
                collect_seconds=timeout.total_seconds(),
            )
        )
        logger.debug("gNMI subscribe notifications: %s", notifications)
        updates = [notification["update"] for notification in notifications if "update" in notification]
        assert len(updates) == count, f"only got {len(updates)} of {count} updates within {timeout}: {notifications}"
        assert notifications[0].get(
            "sync_response"
        ), f"expected sync_response on the first notification: {notifications[0]}"
        assert not any(
            notification.get("sync_response") for notification in notifications[1:]
        ), f"expected sync_response on the first notification only: {notifications}"

        # The first update is the initial snapshot; the rest are periodic samples.
        gaps = [
            timedelta(seconds=(later["timestamp"] - earlier["timestamp"]) / 1e9)
            for earlier, later in zip(updates[1:], updates[2:])
        ]
        assert all(
            min_gap <= gap <= max_gap for gap in gaps
        ), f"expected {min_gap} to {max_gap} between samples, got gaps: {[str(gap) for gap in gaps]}"
        logger.info(f"Successfully received exactly {count} gNMI subscribe sample responses")

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        validates_subscribe_sample("/PSU_INFO", target="STATE_DB")

    with allure.step("Perform gNMI subscribe sample request to sonic DB"):
        validates_subscribe_sample("sonic-db:COUNTERS_DB/localhost/COUNTERS")


def test_gnmi_authorize_failed_with_revoked_cert(
    rand_selected_dut, pygnmi_client: PygnmiClient, setup_crl_server_on_ptf
):
    """
    Verify the gNMI server rejects a Set from a client whose cert is revoked by the CRL
    """
    # setup_gnmi_rotated_server already waited for the server to accept the rotated certs; the
    # revoked client can't check that itself, as every RPC it makes is rejected.
    revoked_client = build_pygnmi_client(rand_selected_dut, "gnmiclient.revoked")
    vnet = {"Vnet1": {"vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2"}}
    error: PygnmiClientError | None = None

    def set_rejected_as_revoked() -> bool:
        nonlocal error
        error = None
        try:
            revoked_client.set(update=[("sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", vnet)])
        except PygnmiClientError as e:
            error = e
        # The server replies with a generic Unauthenticated; only its log has the reason.
        return error is not None and "desc = Peer certificate revoked" in dump_gnmi_log(rand_selected_dut)

    # Retry in case the server failed to download the CRL from PTF.
    assert wait_until(
        30, 10, 0, set_rejected_as_revoked
    ), f"Set with a revoked cert was not rejected as revoked (see the gNMI log above); last error: {error}"
    assert "Unauthenticated" in str(error), f"expected an Unauthenticated error, got: {error}"


def test_osbuild_version(pygnmi_client: PygnmiClient):
    """
    Verify GNMI GET of the OTHERS/osversion/build non-DB path returns a valid
    SONiC build_version.
    """
    result = _get_val(pygnmi_client, "osversion/build", "OTHERS")
    assert "build_version" in result, f"build_version value not found in gNMI response: {result}"
    build_version = result["build_version"]

    assert build_version.startswith("SONiC."), f"build_version is not a SONiC version: {build_version}"
    assert not build_version.upper().startswith(
        "SONIC.NA"
    ), f"invalid build_version value in gnmi output: {build_version}"


def _get_val(client: PygnmiClient, path: str, target: str) -> dict:
    """GET a non-DB path from target (e.g. OTHERS or SHOW) and return its decoded value."""
    result = client.get(path, target=target)
    logger.info("gNMI GET %s response: %s", path, result)
    notifications = result.get("notification") or [{}]
    msg_list = notifications[0].get("update")
    assert msg_list, f"No update in gNMI GET {path} response: {result}"
    val = msg_list[0]["val"]
    assert isinstance(val, dict), f"Expected a JSON object from gNMI GET {path}, got: {val!r}"
    return val


def _get_sysuptime_total(client: PygnmiClient) -> float:
    """GET OTHERS/proc/uptime and return the 'total' field as a float."""
    result = _get_val(client, "proc/uptime", "OTHERS")
    assert "total" in result, f"system uptime 'total' field not found in gnmi output: {result}"
    return float(result["total"])


def test_sysuptime(pygnmi_client: PygnmiClient):
    """
    Verify GNMI GET of the OTHERS/proc/uptime non-DB path returns a float that
    increases over time.
    """
    uptime_first = _get_sysuptime_total(pygnmi_client)
    time.sleep(10)
    uptime_second = _get_sysuptime_total(pygnmi_client)

    assert (
        uptime_second - uptime_first >= 10
    ), f"system uptime did not advance by at least 10s: {uptime_first} -> {uptime_second}"


def test_on_change_updates(rand_selected_dut, pygnmi_client: PygnmiClient):
    """
    Verify GNMI subscribe ON_CHANGE reports a change made with a gNMI Set.
    """
    duthost = rand_selected_dut
    # A test-only APPL_DB table, written with gNMI Set so no Ansible call (which forks this process)
    # runs while the subscription's gRPC channel is open. The server writes APPL_DB through a
    # ProducerStateTable, which keeps entries under "_<table>" until a consumer takes them; this
    # table has no consumer.
    table, key, field = "GNMI_ON_CHANGE_TEST", "test_key", "test_field"
    set_path = f"sonic-db:APPL_DB/localhost/{table}/{key}"
    subscribe_path = f"sonic-db:APPL_DB/localhost/_{table}/{key}"
    value = f"value-{int(time.time())}"
    # A second client: a call on pygnmi_client would close the subscription's channel.
    mutating_client = build_pygnmi_client(duthost)

    # One window for the whole exchange, starting at the first next(): the snapshot,
    # the Set below and our update must all arrive within it.
    total_subscription_timeout = timedelta(seconds=60)
    # Other changes to this key can arrive before ours.
    others: list[dict] = []
    msg: dict | None = None
    try:
        subscription = pygnmi_client.subscribe(
            subscribe_path, stream_mode=StreamMode.ON_CHANGE, collect_seconds=total_subscription_timeout.total_seconds()
        )
        with contextlib.closing(subscription) as notifications:
            # Wait for the initial snapshot, so the subscription is live before triggering the change;
            # otherwise the on-change update can be missed.
            snapshot = next(notifications, None)
            assert (
                snapshot is not None
            ), f"No initial ON_CHANGE snapshot for {subscribe_path} within {total_subscription_timeout}"

            mutating_client.set(update=[(set_path, {field: value})])
            for notification in notifications:
                if value in str(notification):
                    msg = notification
                    break
                others.append(notification)
    finally:
        # Without a consumer, a gNMI delete would leave the ProducerStateTable's key sets behind.
        duthost.shell(f"sonic-db-cli APPL_DB DEL _{table}:{key} {table}_KEY_SET {table}_DEL_SET")

    logger.info("ON_CHANGE notifications received before the expected one: %s", others)
    assert msg is not None, (
        f"No on-change update with {key} {field}={value} within {total_subscription_timeout}; "
        f"got {len(others)} other notifications (logged above)"
    )


def test_mem_spike(rand_selected_dut, pygnmi_client: PygnmiClient):
    """
    The gnmi container memory must stay under threshold when a client continuously
    creates channels with the gnmi server.
    """
    duthost = rand_selected_dut
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    creds = creds_on_dut(duthost)
    stop = threading.Event()

    def open_connections() -> None:
        # Each subscribe() opens a new channel and closes it before returning.
        for _ in range(MEMORY_SPIKE_CONNECTIONS):
            if stop.is_set():
                return
            list(pygnmi_client.subscribe("DOCKER_STATS", target="STATE_DB", count=1))

    # Check memory over paramiko, not duthost.shell: Ansible forks this process, which is unsafe
    # while the worker thread has a gRPC channel open.
    with paramiko_ssh(
        duthost.mgmt_ip, creds["sonicadmin_user"], creds["sonicadmin_password"]
    ) as ssh, ThreadPoolExecutor(max_workers=1) as executor:
        connections = executor.submit(open_connections)
        try:
            for _ in range(MEMORY_CHECKER_CYCLES):
                _, stdout, _ = ssh.exec_command(f"sudo python3 /usr/bin/memory_checker {env.gnmi_container} 419430400")
                output = stdout.read().decode()
                assert stdout.channel.recv_exit_status() == 0, f"Memory utilization has exceeded threshold: {output}"
                time.sleep(MEMORY_CHECKER_WAIT)
        except BaseException:
            stop.set()  # don't wait for the remaining connections
            raise
        connections.result()  # re-raises an exception from the worker


def test_telemetry_show_non_get(pygnmi_client: PygnmiClient, skip_non_container_test):
    """
    The SHOW target only supports GET; a SUBSCRIBE must fail.
    """
    with pytest.raises(PygnmiClientCallError, match="SHOW does not support subscribe"):
        list(pygnmi_client.subscribe("reboot-cause", target="SHOW", count=1))


def test_telemetry_show_get(
    duthosts, rand_one_dut_hostname, request, pygnmi_client: PygnmiClient, skip_non_container_test
):
    """
    Test all SHOW GET paths from cli_paths.json: run each path's setup, gnmi GET
    against the SHOW target, and verify.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Resolve "duthost" to the DUT selected for this test so setup/verify act on
    # the same host the GET queries (request.getfixturevalue("duthost") would
    # resolve to the session DUT index, which can differ on multi-DUT testbeds).
    def resolve_fixture(fx):
        return duthost if fx == "duthost" else request.getfixturevalue(fx)

    with open(SHOW_PATHS_FILE, "r") as show_paths_file:
        show_paths_data = json.load(show_paths_file)

    for path, test_config in show_paths_data.items():
        if test_config["setup"]:
            setup_fixtures = [resolve_fixture(fx) for fx in test_config["setup_fixtures"]]
            getattr(helper, test_config["setup"])(*setup_fixtures, *test_config["setup_args"])
            # The setup step reboots the DUT, which drops the non-persistent gnmi
            # cert server; re-apply it so the SHOW GET runs against the configured server.
            apply_cert_config(duthost)
            wait_for_gnmi_server(duthost)

        output = _get_val(pygnmi_client, path, "SHOW")

        if test_config["verify"]:
            verify_fixtures = [resolve_fixture(fx) for fx in test_config["verify_fixtures"]]
            getattr(helper, test_config["verify"])(*verify_fixtures, *test_config["verify_args"], output)
