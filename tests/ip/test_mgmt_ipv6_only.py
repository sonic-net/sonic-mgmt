import logging

import pytest
import re

from tests.common.utilities import get_mgmt_ipv6, check_output, run_show_features
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.bgp import run_bgp_facts
from tests.common.helpers.tacacs.tacacs_helper import ssh_remote_run_retry, tacacs_v6_context
from tests.common.helpers.ntp_helper import run_ntp, setup_ntp_context
from tests.common.helpers.ntp_helper import run_ntp, setup_ntp_context, ntp_daemon_in_use     # noqa F401
from tests.common.helpers.telemetry_helper import setup_streaming_telemetry_context
from tests.common.helpers.syslog_helpers import run_syslog, check_default_route     # noqa F401
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.fixtures.duthost_utils import duthosts_ipv6_mgmt_only # noqa F401
from tests.common.fixtures.tacacs import tacacs_creds # noqa F401


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def pytest_generate_tests(metafunc):
    if "ptf_use_ipv6" in metafunc.fixturenames:
        metafunc.parametrize("ptf_use_ipv6", [True], scope="module")


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(loganalyzer):
    ignore_regex = [
        # For dualtor duts, we set up mux simulator on the servers,
        # but if the server doesn't have IPv6 addr, the mux simulator is unavailable,
        # Then y cable issue is reported, since the IPv6 test only focus on the mgmt plane,
        # we can ignore this error log
        # Sample logs:

        # Mar 28 05:18:28.331508 dut INFO logrotate: Sending SIGHUP to OA log_file_name: /var/log/swss/sairedis.rec
        # Mar 28 05:18:28.459615 dut WARNING pmon#CCmisApi: y_cable_port 11: attempt=6, GET http://192.168.0.1:8082/mux/vms21-6/20 for physical_port 11 failed with URLError(timeout('timed out')) # noqa E501
        # Mar 28 05:18:28.459615 dut WARNING pmon#CCmisApi: y_cable_port 11: Retry GET http://192.168.0.1:8082/mux/vms21-6/20 for physical port 11 timeout after 30 seconds, attempted=6 # noqa E501
        # Mar 28 05:18:28.460209 dut ERR pmon#CCmisApi: Error: Could not establish the active side for Y cable port Ethernet40 to perform read_y_cable update state db # noqa E501
        # Mar 28 05:18:28.460598 dut NOTICE swss#orchagent: message repeated 2 times: [ :- start: performing log rotate]
        # Mar 28 05:18:28.460598 dut NOTICE swss#orchagent: :- addOperation: Mux setting State DB entry (hw state unknown, mux state unknown) for port Ethernet40 # noqa E501
        # Mar 28 05:18:28.461333 dut NOTICE mux#linkmgrd: MuxManager.cpp:288 addOrUpdateMuxPortMuxState: Ethernet40: state db mux state: unknown # noqa E501
        # Mar 28 05:18:28.461640 dut NOTICE mux#linkmgrd: link_manager/LinkManagerStateMachineActiveStandby.cpp:686 handleMuxStateNotification: Ethernet40: state db mux state: Unknown # noqa E501
        # Mar 28 05:18:28.462126 dut NOTICE mux#linkmgrd: link_manager/LinkManagerStateMachineActiveStandby.cpp:1297 LinkProberWaitMuxUnknownLinkUpTransitionFunction: Ethernet40 # noqa E501

        ".*ERR pmon#CCmisApi: Error: Could not establish the active side for Y cable port Ethernet[0-9]* to perform read_y_cable update state db", # noqa E501
    ]

    if loganalyzer:
        for hostname in loganalyzer.keys():
            loganalyzer[hostname].ignore_regex.extend(ignore_regex)


def log_eth0_interface_info(duthosts):
    for duthost in duthosts:
        duthost_interface = duthost.shell("sudo ifconfig eth0")['stdout']
        logging.debug(f"Checking host[{duthost.hostname}] ifconfig eth0:[{duthost_interface}] after fixture") # noqa E231


def log_tacacs(duthosts, ptfhost):
    for duthost in duthosts:
        # Print debug info for ipv6 pingability
        ptfhost_vars = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars
        if 'ansible_hostv6' in ptfhost_vars:
            tacacs_server_ip = ptfhost_vars['ansible_hostv6']
            ping_result = duthost.shell(f"ping {tacacs_server_ip} -c 1 -W 3", module_ignore_errors=True)["stdout"]
            logging.debug(f"Checking ping_result [{ping_result}]")

        # Print debug info for mgmt interfaces and forced mgmt routes
        mgmt_interface_keys = duthost.command("sonic-db-cli CONFIG_DB keys 'MGMT_INTERFACE|*'")['stdout']
        logging.debug(f"mgmt_interface_keys: {mgmt_interface_keys}")
        for intf_key in mgmt_interface_keys.split('\n'):
            logging.debug(f"interface key: {intf_key}")
            intf_values = intf_key.split('|')
            if len(intf_values) != 3:
                logging.debug(f"Unexpected interface key: {intf_key}")
                continue
            forced_mgmt_rte = duthost.command(f"sonic-db-cli CONFIG_DB HGET '{intf_key}' forced_mgmt_routes@")['stdout']
            logging.debug(f"forced_mgmt_routes: {forced_mgmt_rte}, interface address: {intf_values[2]}")


def test_bgp_facts_ipv6_only(duthosts_ipv6_mgmt_only,       # noqa F411
                             enum_frontend_dut_hostname, enum_asic_index):
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    log_eth0_interface_info(duthosts_ipv6_mgmt_only)
    run_bgp_facts(duthosts_ipv6_mgmt_only[enum_frontend_dut_hostname], enum_asic_index)


def test_show_features_ipv6_only(duthosts_ipv6_mgmt_only,   # noqa F411
                                 enum_dut_hostname):
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    log_eth0_interface_info(duthosts_ipv6_mgmt_only)
    run_show_features(duthosts_ipv6_mgmt_only, enum_dut_hostname)


def test_image_download_ipv6_only(creds, duthosts_ipv6_mgmt_only,   # noqa F411
                                  enum_dut_hostname):
    """
    Test image download in mgmt ipv6 only scenario
    """
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    log_eth0_interface_info(duthosts_ipv6_mgmt_only)
    duthost = duthosts_ipv6_mgmt_only[enum_dut_hostname]
    image_url = creds.get("test_image_url", {}).get("ipv6", "")
    pytest_require(len(image_url) != 0, "Cannot get image url")
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mgmt_interfaces = cfg_facts.get("MGMT_INTERFACE", {}).keys()
    for mgmt_interface in mgmt_interfaces:
        output = duthost.shell("curl --fail --interface {} {}".format(mgmt_interface, image_url),
                               module_ignore_errors=True)
        if output["rc"] == 0:
            break
    else:
        pytest.fail("Failed to download image from image_url {} via any of {}"
                    .format(image_url, list(mgmt_interfaces)))


@pytest.mark.parametrize("dummy_syslog_server_ip_a, dummy_syslog_server_ip_b",
                         [("fd82:b34f:cc99::100", None),
                          ("fd82:b34f:cc99::100", "fd82:b34f:cc99::200")])
def test_syslog_ipv6_only(duthosts_ipv6_mgmt_only, check_default_route,          # noqa F411
                          rand_selected_dut, dummy_syslog_server_ip_a,
                          dummy_syslog_server_ip_b):
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    log_eth0_interface_info(duthosts_ipv6_mgmt_only)
    run_syslog(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, check_default_route)


def test_snmp_ipv6_only(duthosts_ipv6_mgmt_only,            # noqa F411
                        enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    log_eth0_interface_info(duthosts_ipv6_mgmt_only)
    duthost = duthosts_ipv6_mgmt_only[enum_rand_one_per_hwsku_hostname]
    hostipv6 = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_hostv6']

    sysDescr_oid = ".1.3.6.1.2.1.1.1.0"
    # Query by specifying udp6 protocol along with host IPv6
    snmpget = "snmpget -v2c -c {} udp6:[{}] {}".format(
        creds_all_duts[duthost.hostname]['snmp_rocommunity'], hostipv6, sysDescr_oid)
    result = localhost.shell(snmpget)['stdout_lines']

    assert result is not None, "Failed to get snmp result from localhost"
    assert result[0] is not None, "Failed to get snmp result from DUT IPv6 {}".format(hostipv6)
    assert "SONiC Software Version" in result[0], "Sysdescr not found in SNMP result from DUT IPv6 {}".format(hostipv6)


def test_ro_user_ipv6_only(localhost, ptfhost, duthosts_ipv6_mgmt_only, tacacs_creds,     # noqa F411
                           enum_rand_one_per_hwsku_hostname):
    duthost = duthosts_ipv6_mgmt_only[enum_rand_one_per_hwsku_hostname]
    with tacacs_v6_context(ptfhost, duthost, tacacs_creds):
        # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
        log_eth0_interface_info(duthosts_ipv6_mgmt_only)
        dutipv6 = get_mgmt_ipv6(duthost)
        log_tacacs(duthosts_ipv6_mgmt_only, ptfhost)

        res = ssh_remote_run_retry(localhost, dutipv6, ptfhost, tacacs_creds['tacacs_ro_user'],
                                   tacacs_creds['tacacs_ro_user_passwd'], 'cat /etc/passwd')
        check_output(res, 'test', 'remote_user')


def test_rw_user_ipv6_only(localhost, ptfhost, duthosts_ipv6_mgmt_only, tacacs_creds,    # noqa F411
                           enum_rand_one_per_hwsku_hostname):
    duthost = duthosts_ipv6_mgmt_only[enum_rand_one_per_hwsku_hostname]
    with tacacs_v6_context(ptfhost, duthost, tacacs_creds):
        # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
        log_eth0_interface_info(duthosts_ipv6_mgmt_only)
        dutipv6 = get_mgmt_ipv6(duthost)
        log_tacacs(duthosts_ipv6_mgmt_only, ptfhost)

        res = ssh_remote_run_retry(localhost, dutipv6, ptfhost, tacacs_creds['tacacs_rw_user'],
                                   tacacs_creds['tacacs_rw_user_passwd'], "cat /etc/passwd")
        check_output(res, 'testadmin', 'remote_user_su')


def test_telemetry_output_ipv6_only(duthosts_ipv6_mgmt_only,        # noqa F411
                                    enum_rand_one_per_hwsku_hostname,
                                    localhost, ptfhost, gnxi_path):
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    duthost = duthosts_ipv6_mgmt_only[enum_rand_one_per_hwsku_hostname]
    with setup_streaming_telemetry_context(True, duthost, localhost, ptfhost, gnxi_path):
        log_eth0_interface_info(duthosts_ipv6_mgmt_only)
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        if duthost.is_supervisor_node():
            pytest.skip(
                "Skipping test as no Ethernet0 frontpanel port on supervisor")
        dut_ip = get_mgmt_ipv6(duthost)
        cmd = "~/gnmi_get -xpath_target COUNTERS_DB -xpath COUNTERS/Ethernet0 -target_addr \
            [%s]:%s -logtostderr -insecure" % (dut_ip, env.gnmi_port)
        show_gnmi_out = duthost.shell(cmd)['stdout']
        result = str(show_gnmi_out)
        inerrors_match = re.search("SAI_PORT_STAT_IF_IN_ERRORS", result)
        pytest_assert(inerrors_match is not None,
                      "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi output")


# use function scope fixture so that duthosts_ipv6_mgmt_only will run before setup_ntp_func
def test_ntp_ipv6_only(duthosts_ipv6_mgmt_only,             # noqa F411
                       rand_one_dut_hostname, ptfhost, ptf_use_ipv6, ntp_daemon_in_use):  # noqa F811
    # Add a temporary debug log to see if DUTs are reachable via IPv6 mgmt-ip. Will remove later
    duthost = duthosts_ipv6_mgmt_only[rand_one_dut_hostname]
    with setup_ntp_context(ptfhost, duthost, ptf_use_ipv6):
        log_eth0_interface_info(duthosts_ipv6_mgmt_only)
        run_ntp(duthost, ntp_daemon_in_use)
