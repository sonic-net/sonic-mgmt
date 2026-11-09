import json
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import timedelta

import grpc
import pytest
from pygnmi.create_gnmi_path import gnmi_path_generator
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers import gnmi_cli_helpers as helper
from tests.common.helpers.dut_utils import creds_on_dut
from tests.common.helpers.gnmi_connection import (
    build_native_set_request,
    gnmi_connection,
)
from tests.common.helpers.gnmi_utils import (
    add_gnmi_client_common_name,
    create_revoked_cert_and_crl,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import Encoding, PygnmiClient, StreamMode
from tests.common.utilities import paramiko_ssh, wait_until

logger = logging.getLogger(__name__)
allure.logger = logger

MEMORY_CHECKER_WAIT = 1
MEMORY_CHECKER_CYCLES = 60

SHOW_PATHS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "cli_paths.json")


@pytest.fixture
def skip_non_container_test(request):
    if not request.config.getoption("--container_test", default=""):
        pytest.skip("Testcase skipped for non container test")


pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp"),
]


def test_gnmi_capabilities(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify GNMI capabilities
    """
    client = gnmi_tls.pygnmi_client
    msg = client.capabilities()
    assert any(model.get("name") == "sonic-db" for model in msg.get("supported_models", [])), (
        "'sonic-db' not found in GNMI capabilities response message.\n" "- Actual message: {}"
    ).format(msg)

    assert "json_ietf" in msg.get("supported_encodings", []), (
        "'JSON_IETF' not found in GNMI capabilities response message.\n" "- Actual message: {}"
    ).format(msg)


def gnmi_create_vnet(gnmi_tls):  # noqa: F811
    text = '{"Vnet1": {"vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2"}}'
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE"]
    request = build_native_set_request(update_list[0].split(":", 1)[1].strip("/").split("/"), json.loads(text))
    msg = ""
    try:
        with gnmi_connection(gnmi_tls) as (_, client):
            client.Set(request, timeout=30)
    except Exception as e:
        logger.info("Failed to set: " + str(e))
        msg = str(e)

    gnmi_log = gnmi_tls.duthost.shell("sudo cat /var/log/gnmi.log", module_ignore_errors=True)["stdout"]

    return msg, gnmi_log


@pytest.fixture(scope="function")
def setup_crl_server_on_ptf(ptfhost, localhost, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    duthost = gnmi_tls.duthost

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

    def server_ready_log_exist(ptfhost):
        res = ptfhost.shell("sed -n '/Ready handle request/p'  /root/crl.log", module_ignore_errors=True)
        logger.debug("crl.log: {}".format(res["stdout_lines"]))
        return len(res["stdout_lines"]) > 0

    local_files = (
        "gnmiclient.revoked.crt",
        "gnmiclient.revoked.key",
        "gnmiclient.revoked.csr",
        "sonic.crl.pem",
        "crlext.cnf",
    )
    for filename in local_files:
        if os.path.lexists(filename):
            raise FileExistsError("CRL preparation would overwrite existing file: {}".format(filename))
    # Use the PTF's existing supervisor to own only this HTTP child process.
    ptfhost.command("supervisorctl pid")
    listener = ptfhost.shell("ss -ltnH 'sport = :1234'")
    if listener["stdout"].strip():
        raise RuntimeError("CRL port 1234 is already in use")
    program = "gnmi-crl-" + uuid.uuid4().hex
    config_path = "/etc/supervisor/conf.d/{}.conf".format(program)
    config_written = False
    try:
        create_revoked_cert_and_crl(
            localhost,
            ptfhost,
            duthost,
            ca_cert=gnmi_tls.pygnmi_client.ca_cert,
            ca_key=os.path.join(os.path.dirname(gnmi_tls.pygnmi_client.ca_cert), "gnmiCA.key"),
        )
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" enable_crl true log_level 10')
        role = (
            "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,"
            "gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
        )
        add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)
        _restart_gnoi_server(duthost)

        # The HTTP server loads sonic.crl.pem once, so start it after generation.
        ptfhost.shell("rm -f /root/crl.log")
        bind_arg = " --bind {}".format(bind_addr) if bind_addr else ""
        config_written = True
        ptfhost.copy(
            content=(
                "[program:{name}]\ncommand=/root/env-python3/bin/python /root/crl_server.py{bind}\n"
                "directory=/root\nautostart=true\nautorestart=false\nstartsecs=1\nstartretries=0\n"
                "stopsignal=TERM\nstopwaitsecs=10\n"
            ).format(name=program, bind=bind_arg),
            dest=config_path,
        )
        ptfhost.command("supervisorctl update {}".format(program))
        assert wait_until(
            10,
            1,
            0,
            lambda: "RUNNING"
            in ptfhost.command("supervisorctl status {}".format(program), module_ignore_errors=True)["stdout"],
        ), "CRL supervisor program failed to start: {}".format(program)
        wait_until(60, 1, 0, server_ready_log_exist, ptfhost)

        # Bind only this request to the revoked identity; do not mutate the fixture.
        client = PygnmiClient(
            gnmi_tls.host,
            gnmi_tls.port,
            ca_cert=gnmi_tls.pygnmi_client.ca_cert,
            client_cert="gnmiclient.revoked.crt",
            client_key="gnmiclient.revoked.key",
            connect=False,
        )
        yield replace(gnmi_tls, pygnmi_client=client)
    finally:
        try:
            if config_written:
                # Removing this group makes supervisor stop/reap its own child;
                # no process-name matching or independently reused PID is used.
                ptfhost.file(path=config_path, state="absent")
                status = ptfhost.command("supervisorctl status {}".format(program), module_ignore_errors=True)
                if status["stdout"].split()[:1] == [program]:
                    ptfhost.command("supervisorctl update {}".format(program))
                elif status["stdout"].strip() != "{}: ERROR (no such process)".format(program):
                    raise RuntimeError("Could not determine CRL supervisor state: {}".format(status))
        finally:
            for filename in local_files:
                if os.path.lexists(filename):
                    os.unlink(filename)


def test_gnmi_subscribe_sample(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify GNMI subscribe sample request
    """
    duthost = gnmi_tls.duthost

    # Skip test for supervisor nodes as they don't have Ethernet0 frontpanel port
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    interval = timedelta(seconds=1)
    min_gap, max_gap = interval - timedelta(milliseconds=500), interval * 2
    count = 5
    timeout = max_gap * count + timedelta(seconds=15)
    client = gnmi_tls.pygnmi_client

    def validates_subscribe_sample(output):
        # The initial synchronized batch must contain data; a sync-only shell
        # does not count as a sample. Multiple fields still count as one batch.
        respCnt = sum(bool(response.get("update", {}).get("update")) for response in output)
        assert respCnt == count, f"expected {count} update responses, got {respCnt}"
        assert output[0].get("sync_response"), "Initial SAMPLE response did not synchronize"
        assert not any(response.get("sync_response") for response in output[1:])
        updates = [response["update"] for response in output if "update" in response]
        gaps = [
            timedelta(seconds=(later["timestamp"] - earlier["timestamp"]) / 1e9)
            for earlier, later in zip(updates[1:], updates[2:])
        ]
        assert all(min_gap <= gap <= max_gap for gap in gaps), f"Unexpected sample gaps: {gaps}"

        logger.info(f"Successfully received exactly {count} gNMI subscribe sample responses")

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        stdout_msg = list(
            client.subscribe(
                ["/PSU_INFO"],
                sample_interval=interval.total_seconds(),
                count=count,
                collect_seconds=timeout.total_seconds(),
                target="STATE_DB",
                encoding=Encoding.JSON_IETF,
            )
        )
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)

    with allure.step("Perform gNMI subscribe sample request to sonic DB"):
        stdout_msg = list(
            client.subscribe(
                ["/COUNTERS_DB/localhost/COUNTERS"],
                sample_interval=interval.total_seconds(),
                count=count,
                collect_seconds=timeout.total_seconds(),
                prefix="sonic-db://",
                encoding=Encoding.JSON_IETF,
            )
        )
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)


def test_gnmi_authorize_failed_with_revoked_cert(setup_crl_server_on_ptf):
    """
    Verify a native APPL_DB Set is rejected for a CRL-revoked certificate.
    """
    retry = 3
    msg = ""
    gnmi_log = ""
    while retry > 0:
        retry -= 1
        msg, gnmi_log = gnmi_create_vnet(setup_crl_server_on_ptf)
        # retry when download crl failed, ptf device network not stable
        if "desc = Peer certificate revoked" in gnmi_log:
            break

    assert "Unauthenticated" in msg or "UNAUTHENTICATED" in msg, (
        "'Unauthenticated' error message not found in GNMI response. " "- Actual message: '{}'"
    ).format(msg)

    assert "desc = Peer certificate revoked" in gnmi_log, (
        "'desc = Peer certificate revoked' message not found in GNMI log. " "- Actual GNMI log: '{}'"
    ).format(gnmi_log)


def test_osbuild_version(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify GNMI GET of the OTHERS/osversion/build non-DB path returns a valid
    SONiC build_version.
    """
    client = gnmi_tls.pygnmi_client
    msg_list = client.get(["osversion/build"], target="OTHERS")
    result = "\n".join(
        json.dumps(update["val"]) for notification in msg_list["notification"] for update in notification["update"]
    )

    assert (
        len(re.findall(r'"build_version": "SONiC\.', result)) == 1
    ), "build_version value not found in gnmi output: {}".format(result)
    assert (
        len(re.findall(r"SONiC\.NA", result, flags=re.IGNORECASE)) == 0
    ), "invalid build_version value in gnmi output: {}".format(result)


def _get_sysuptime_total(client):
    """GET OTHERS/proc/uptime and return the 'total' field as a float."""
    msg_list = client.get(["proc/uptime"], target="OTHERS")
    result = "\n".join(
        json.dumps(update["val"]) for notification in msg_list["notification"] for update in notification["update"]
    )
    match = re.search(r'"total":\s*([0-9.]+)', result)
    assert match is not None, "system uptime 'total' field not found in gnmi output: {}".format(result)
    return float(match.group(1))


def test_sysuptime(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify GNMI GET of the OTHERS/proc/uptime non-DB path returns a float that
    increases over time.
    """
    uptime_first = _get_sysuptime_total(gnmi_tls.pygnmi_client)
    time.sleep(10)
    uptime_second = _get_sysuptime_total(gnmi_tls.pygnmi_client)

    assert uptime_second - uptime_first >= 10, "system uptime did not advance by at least 10s: {} -> {}".format(
        uptime_first, uptime_second
    )


def test_on_change_updates(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify GNMI subscribe ON_CHANGE reports a change made with a gNMI Set.
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    table, key, field = "GNMI_ON_CHANGE_TEST", "test_key", "test_field"
    set_path = f"sonic-db:APPL_DB/localhost/{table}/{key}"
    subscribe_path = f"sonic-db:APPL_DB/localhost/_{table}/{key}"
    value = f"value-{int(time.time())}"
    mutating_client = PygnmiClient(
        client.host,
        client.port,
        ca_cert=client.ca_cert,
        client_cert=client.client_cert,
        client_key=client.client_key,
        connect=False,
    )
    timeout = timedelta(seconds=60)
    others = []
    msg = None
    try:
        with closing(
            client.subscribe(subscribe_path, stream_mode=StreamMode.ON_CHANGE, collect_seconds=timeout.total_seconds())
        ) as notifications:
            snapshot = next(notifications, None)
            assert snapshot is not None, f"No initial ON_CHANGE snapshot for {subscribe_path} within {timeout}"
            mutating_client.set(update=[(set_path, {field: value})])
            for notification in notifications:
                if value in str(notification):
                    msg = notification
                    break
                others.append(notification)
    finally:
        duthost.shell(f"sonic-db-cli APPL_DB DEL _{table}:{key} {table}_KEY_SET {table}_DEL_SET")
    logger.info("ON_CHANGE notifications received before the expected one: %s", others)
    assert msg is not None, f"No on-change update with {key} {field}={value} within {timeout}"


def test_mem_spike(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    The gnmi container memory must stay under threshold when a client continuously
    creates channels with the gnmi server.
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    creds = creds_on_dut(duthost)
    stop = threading.Event()

    def open_connections():
        for _ in range(2000):
            if stop.is_set():
                return
            list(client.subscribe("DOCKER_STATS", target="STATE_DB", count=1))

    # Preserve master's no-Ansible-fork memory observer while the channel is open.
    with paramiko_ssh(
        duthost.mgmt_ip, creds["sonicadmin_user"], creds["sonicadmin_password"]
    ) as ssh, ThreadPoolExecutor(max_workers=1) as executor:
        connections = executor.submit(open_connections)
        try:
            for _ in range(MEMORY_CHECKER_CYCLES):
                _, stdout, _ = ssh.exec_command("sudo python3 /usr/bin/memory_checker gnmi 419430400")
                output = stdout.read().decode()
                assert stdout.channel.recv_exit_status() == 0, f"Memory utilization has exceeded threshold: {output}"
                time.sleep(MEMORY_CHECKER_WAIT)
        except BaseException:
            stop.set()
            raise
        connections.result()


def test_telemetry_show_non_get(rand_one_dut_hostname, gnmi_tls, skip_non_container_test):  # noqa: F811
    """
    The SHOW target only supports GET; a SUBSCRIBE must fail.
    """
    request = gnmi_pb2.SubscribeRequest(
        subscribe=gnmi_pb2.SubscriptionList(
            prefix=gnmi_pb2.Path(target="SHOW"),
            mode=gnmi_pb2.SubscriptionList.STREAM,
            encoding=gnmi_pb2.JSON_IETF,
            subscription=[
                gnmi_pb2.Subscription(path=gnmi_path_generator("reboot-cause"), mode=gnmi_pb2.SAMPLE, sample_interval=0)
            ],
        )
    )
    with gnmi_connection(gnmi_tls) as (_, client):
        responses = client.Subscribe(iter([request]), timeout=30)
        try:
            with pytest.raises(grpc.RpcError):
                list(responses)
        finally:
            responses.cancel()


def test_telemetry_show_get(localhost, rand_one_dut_hostname, request, skip_non_container_test, gnmi_tls):  # noqa: F811
    """
    Test all SHOW GET paths from cli_paths.json: run each path's setup, gnmi GET
    against the SHOW target, and verify.
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client

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
            gnmi_tls.reconfigure_after_reboot()

        show_gnmi_out = client.get([path], target="SHOW")

        if test_config["verify"]:
            output = show_gnmi_out["notification"][0]["update"][0]["val"]
            verify_fixtures = [resolve_fixture(fx) for fx in test_config["verify_fixtures"]]
            getattr(helper, test_config["verify"])(*verify_fixtures, *test_config["verify_args"], output)
