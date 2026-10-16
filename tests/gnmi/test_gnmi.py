import pytest
import logging
import re
import time
import random
import threading
import json
import os
from contextlib import closing, ExitStack
from dataclasses import replace

import grpc
from pygnmi.create_gnmi_path import gnmi_path_generator
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls, _restart_gnoi_server  # noqa: F401
from tests.common.helpers import gnmi_cli_helpers as helper
from tests.common.helpers.gnmi_connection import gnmi_connection, build_native_set_request
from tests.common.helpers.gnmi_utils import prepare_root_cert, prepare_server_cert, prepare_client_cert, \
    create_revoked_cert_and_crl, copy_certificate_to_dut, copy_certificate_to_ptf, delete_gnmi_certs, \
    add_gnmi_client_common_name
from tests.common.pygnmi_client import Encoding, PygnmiClient, StreamMode
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure


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
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]


def test_gnmi_capabilities(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI capabilities
    '''
    client = gnmi_tls.pygnmi_client
    msg = client.capabilities()
    assert any(model.get("name") == "sonic-db" for model in msg.get("supported_models", [])), (
        "'sonic-db' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)

    assert "json_ietf" in msg.get("supported_encodings", []), (
        "'JSON_IETF' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)


def gnmi_create_vnet(gnmi_tls):  # noqa: F811
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
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
    dut_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    is_mgmt_ipv6_only = dut_facts.get('is_mgmt_ipv6_only', False)

    if is_mgmt_ipv6_only and ptfhost.mgmt_ipv6:
        # Bind to IPv6 address when DUT is IPv6-only
        bind_addr = ptfhost.mgmt_ipv6
        logger.info(f"DUT is IPv6-only, binding CRL server to IPv6: {bind_addr}")
    else:
        # Bind to all interfaces (default behavior) for IPv4 or mixed environments
        bind_addr = ''
        logger.info("Binding CRL server to all interfaces (IPv4 compatible)")

    def server_ready_log_exist(ptfhost):
        res = ptfhost.shell("sed -n '/Ready handle request/p'  /root/crl.log", module_ignore_errors=True)
        logger.debug("crl.log: {}".format(res["stdout_lines"]))
        return len(res["stdout_lines"]) > 0

    server_started = False
    try:
        # Keep the existing one-off certificate operations, as in the 2038 test.
        prepare_root_cert(localhost)
        prepare_server_cert(duthost, localhost)
        prepare_client_cert(localhost)
        create_revoked_cert_and_crl(localhost, ptfhost, duthost)
        copy_certificate_to_dut(duthost)
        copy_certificate_to_ptf(ptfhost)
        duthost.copy(src="gnmiCA.pem", dest="/etc/sonic/telemetry/gnmiCA.cer")
        duthost.copy(src="gnmiserver.crt", dest="/etc/sonic/telemetry/gnmiserver.cer")
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" enable_crl true log_level 10')
        role = ("gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,"
                "gnmi_dpu_appl_db_readwrite,gnoi_readwrite")
        add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)
        _restart_gnoi_server(duthost)

        # The HTTP server loads sonic.crl.pem once, so start it after generation.
        ptfhost.shell('rm -f /root/crl.log')
        server_started = True
        if bind_addr:
            ptfhost.shell(f'nohup /root/env-python3/bin/python /root/crl_server.py --bind {bind_addr} &')
        else:
            ptfhost.shell('nohup /root/env-python3/bin/python /root/crl_server.py &')
        wait_until(60, 1, 0, server_ready_log_exist, ptfhost)

        # Bind only this request to the revoked identity; do not mutate the fixture.
        client = PygnmiClient(gnmi_tls.host, gnmi_tls.port, ca_cert="gnmiCA.pem",
                              client_cert="gnmiclient.revoked.crt", client_key="gnmiclient.revoked.key",
                              connect=False)
        yield replace(gnmi_tls, pygnmi_client=client)
    finally:
        try:
            if server_started:
                ptfhost.shell("pkill -9 -f '/root/env-python3/bin/python /root/crl_server.py'",
                              module_ignore_errors=True)
        finally:
            delete_gnmi_certs(localhost)


def test_gnmi_subscribe_sample(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI subscribe sample request
    '''
    duthost = gnmi_tls.duthost

    # Skip test for supervisor nodes as they don't have Ethernet0 frontpanel port
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    interval_ms = 5000  # 5 second interval
    count = 5
    client = gnmi_tls.pygnmi_client

    def validates_subscribe_sample(output):
        # The initial synchronized batch must contain data; a sync-only shell
        # does not count as a sample. Multiple fields still count as one batch.
        respCnt = sum(bool(response.get("update", {}).get("update")) for response in output)
        assert respCnt == count, f"expected {count} update responses, got {respCnt}"
        assert output[0].get("sync_response"), "Initial SAMPLE response did not synchronize"

        logger.info(f"Successfully received exactly {count} gNMI subscribe sample responses")

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        stdout_msg = list(client.subscribe(
            ["/PSU_INFO"], sample_interval=interval_ms / 1000, count=count,
            collect_seconds=30, target="STATE_DB", encoding=Encoding.JSON_IETF,
        ))
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)

    with allure.step("Perform gNMI subscribe sample request to sonic DB"):
        stdout_msg = list(client.subscribe(
            ["/COUNTERS_DB/localhost/COUNTERS"], sample_interval=interval_ms / 1000, count=count,
            collect_seconds=30, prefix="sonic-db://", encoding=Encoding.JSON_IETF,
        ))
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)


def test_gnmi_authorize_failed_with_revoked_cert(setup_crl_server_on_ptf):
    '''
    Verify a native APPL_DB Set is rejected for a CRL-revoked certificate.
    '''
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
        "'Unauthenticated' error message not found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)

    assert "desc = Peer certificate revoked" in gnmi_log, (
        "'desc = Peer certificate revoked' message not found in GNMI log. "
        "- Actual GNMI log: '{}'"
    ).format(gnmi_log)


def test_osbuild_version(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI GET of the OTHERS/osversion/build non-DB path returns a valid
    SONiC build_version.
    '''
    client = gnmi_tls.pygnmi_client
    msg_list = client.get(["osversion/build"], target="OTHERS")
    result = "\n".join(
        json.dumps(update["val"])
        for notification in msg_list["notification"] for update in notification["update"]
    )

    assert len(re.findall(r'"build_version": "SONiC\.', result)) == 1, (
        "build_version value not found in gnmi output: {}".format(result))
    assert len(re.findall(r'SONiC\.NA', result, flags=re.IGNORECASE)) == 0, (
        "invalid build_version value in gnmi output: {}".format(result))


def _get_sysuptime_total(client):
    """GET OTHERS/proc/uptime and return the 'total' field as a float."""
    msg_list = client.get(["proc/uptime"], target="OTHERS")
    result = "\n".join(
        json.dumps(update["val"])
        for notification in msg_list["notification"] for update in notification["update"]
    )
    match = re.search(r'"total":\s*([0-9.]+)', result)
    assert match is not None, (
        "system uptime 'total' field not found in gnmi output: {}".format(result))
    return float(match.group(1))


def test_sysuptime(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI GET of the OTHERS/proc/uptime non-DB path returns a float that
    increases over time.
    '''
    uptime_first = _get_sysuptime_total(gnmi_tls.pygnmi_client)
    time.sleep(10)
    uptime_second = _get_sysuptime_total(gnmi_tls.pygnmi_client)

    assert uptime_second - uptime_first >= 10, (
        "system uptime did not advance by at least 10s: {} -> {}".format(
            uptime_first, uptime_second))


def test_on_change_updates(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI subscribe ON_CHANGE on STATE_DB NEIGH_STATE_TABLE reports a BGP
    neighbor state change.
    '''
    duthost = gnmi_tls.duthost
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    ns = random.choice(duthost.get_asic_namespace_list())
    bgp_neighbor = random.choice(list(duthost.get_bgp_neighbors(ns).keys()))
    asic_id = duthost.get_asic_id_from_namespace(ns)
    original_state = duthost.get_bgp_neighbor_info(bgp_neighbor, asic_id)["bgpState"]
    new_state = "Established" if original_state.lower() == "active" else "Active"

    namespace_name = ns if ns else "localhost"
    path_list = ["/sonic-db:STATE_DB/{}/NEIGH_STATE_TABLE".format(namespace_name)]

    client = gnmi_tls.pygnmi_client
    try:
        with closing(client.subscribe(
                path_list, stream_mode=StreamMode.ON_CHANGE, count=2, collect_seconds=60)) as subscription:
            # The native client runs on the runner, not the PTF. Its initial
            # synchronized response establishes readiness before changing state.
            msg = [next(subscription)]
            cmd = "sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor, new_state)
            cmd = duthost.get_cli_cmd_for_namespace(cmd, ns)
            duthost.shell(cmd)
            msg.extend(subscription)
    finally:
        # Restore the original neighbor state after closing the subscription.
        cmd = "sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor, original_state)
        cmd = duthost.get_cli_cmd_for_namespace(cmd, ns)
        duthost.shell(cmd)

    msg = json.dumps(msg)
    assert msg != "", "Did not get output from native on-change client"
    assert bgp_neighbor in msg, (
        "Did not find neighbor {} in on-change update: {}".format(bgp_neighbor, msg))


def test_mem_spike(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    '''
    The gnmi container memory must stay under threshold when a client continuously
    creates channels with the gnmi server.
    '''
    duthost = gnmi_tls.duthost
    request = gnmi_pb2.SubscribeRequest(subscribe=gnmi_pb2.SubscriptionList(
        prefix=gnmi_pb2.Path(target="STATE_DB"), mode=gnmi_pb2.SubscriptionList.STREAM,
        encoding=gnmi_pb2.JSON_IETF, subscription=[gnmi_pb2.Subscription(
            path=gnmi_path_generator("DOCKER_STATS"), mode=gnmi_pb2.SAMPLE,
            sample_interval=10_000_000_000)]))
    stop_creating = threading.Event()
    errors = []

    def client_worker():
        try:
            # Keep contexts alive across requests and through the measurement.
            # This controls retention explicitly, unlike the old CLI's GC lifetime.
            for _ in range(2000):
                if stop_creating.is_set():
                    break
                _, client = connections.enter_context(gnmi_connection(gnmi_tls))
                responses = client.Subscribe(iter([request]), timeout=30)
                try:
                    next(response for response in responses if response.HasField("update"))
                finally:
                    responses.cancel()
        except Exception as error:
            errors.append(error)

    with ExitStack() as connections:
        client_thread = threading.Thread(target=client_worker)
        client_thread.start()
        try:
            for _ in range(MEMORY_CHECKER_CYCLES):
                ret = duthost.shell("python3 /usr/bin/memory_checker gnmi 419430400", module_ignore_errors=True)
                assert ret["rc"] == 0, "Memory utilization has exceeded threshold"
                time.sleep(MEMORY_CHECKER_WAIT)
        except BaseException:
            stop_creating.set()
            raise
        finally:
            # Only release retained channels after the worker stops adding them.
            client_thread.join()
    if errors:
        raise errors[0]


def test_telemetry_show_non_get(rand_one_dut_hostname, gnmi_tls, skip_non_container_test):  # noqa: F811
    '''
    The SHOW target only supports GET; a SUBSCRIBE must fail.
    '''
    request = gnmi_pb2.SubscribeRequest(subscribe=gnmi_pb2.SubscriptionList(
        prefix=gnmi_pb2.Path(target="SHOW"), mode=gnmi_pb2.SubscriptionList.STREAM,
        encoding=gnmi_pb2.JSON_IETF, subscription=[gnmi_pb2.Subscription(
            path=gnmi_path_generator("reboot-cause"), mode=gnmi_pb2.SAMPLE, sample_interval=0)]))
    with gnmi_connection(gnmi_tls) as (_, client):
        responses = client.Subscribe(iter([request]), timeout=30)
        try:
            with pytest.raises(grpc.RpcError):
                list(responses)
        finally:
            responses.cancel()


def test_telemetry_show_get(localhost, rand_one_dut_hostname, request,
                            skip_non_container_test, gnmi_tls):  # noqa: F811
    '''
    Test all SHOW GET paths from cli_paths.json: run each path's setup, gnmi GET
    against the SHOW target, and verify.
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client

    # Resolve "duthost" to the DUT selected for this test so setup/verify act on
    # the same host the GET queries (request.getfixturevalue("duthost") would
    # resolve to the session DUT index, which can differ on multi-DUT testbeds).
    def resolve_fixture(fx):
        return duthost if fx == "duthost" else request.getfixturevalue(fx)

    with open(SHOW_PATHS_FILE, 'r') as show_paths_file:
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
