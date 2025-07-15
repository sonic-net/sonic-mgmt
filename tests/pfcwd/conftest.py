import logging
import pytest
import os
import os.path

from tests.common.fixtures.conn_graph_facts import conn_graph_facts         # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa: F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa: F401
from tests.common.fixtures.ptfhost_utils import pause_garp_service          # noqa: F401
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.cisco_data import is_cisco_device
from tests.common.utilities import str2bool

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Command line args specific for the pfcwd test

    Args:
        parser: pytest parser object

    Returns:
        None

    """
    parser.addoption('--warm-reboot', action='store', type=bool, default=False,
                     help='Warm reboot needs to be enabled or not')
    parser.addoption('--restore-time', action='store', type=int, default=3000,
                     help='PFC WD storm restore interval')
    parser.addoption('--fake-storm', action='store', type=str2bool, default=True,
                     help='Fake storm for most ports instead of using pfc gen')
    parser.addoption('--two-queues', action='store_true', default=True,
                     help='Run test with sending traffic to both queues [3, 4]')


@pytest.fixture(scope="module")
def two_queues(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, fanouthosts):
    """
    Enable/Disable sending traffic to queues [4, 3]
    By default send to queue 4

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Returns:
        two_queues: False/True
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_asic_type = duthost.facts["asic_type"].lower()
    # On Mellanox devices, if the leaf-fanout is running EOS, then only one queue is supported
    if dut_asic_type == "mellanox":
        for fanouthost in list(fanouthosts.values()):
            fanout_os = fanouthost.get_fanout_os()
            if fanout_os == 'eos':
                return False
    return request.config.getoption('--two-queues')


@pytest.fixture(scope="module")
def fake_storm(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Enable/disable fake storm based on platform and input parameters

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Returns:
        fake_storm: False/True
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return False if (isMellanoxDevice(duthost) or is_cisco_device(duthost)) \
        else request.config.getoption('--fake-storm')


@pytest.fixture(scope="module")
def setup_dut_test_params(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, conn_graph_facts, tbinfo,     # noqa: F811
):
    """
    Sets up all the parameters needed for the PFCWD tests

    Args:
        duthost: AnsibleHost instance for DUT
        ptfhost: AnsibleHost instance for PTF
        conn_graph_facts: fixture that contains the parsed topology info

    Yields:
        dut_info: dictionary containing dut information
    """
    dut_test_params = {'basicParams': {'is_dualtor': False}}
    if "dualtor" in tbinfo["topo"]["name"]:
        dut_test_params["basicParams"]["is_dualtor"] = True
        vlan_cfgs = tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']
        if vlan_cfgs and 'default_vlan_config' in vlan_cfgs:
            default_vlan_name = vlan_cfgs['default_vlan_config']
            if default_vlan_name:
                for vlan in list(vlan_cfgs[default_vlan_name].values()):
                    if 'mac' in vlan and vlan['mac']:
                        dut_test_params["basicParams"]["def_vlan_mac"] = vlan['mac']
                        break

    logger.info("dut_test_params : {}".format(dut_test_params))
    yield dut_test_params


# icmp_responder need to be paused during the test because the test case
# configures static IP address on ptf host and sends ICMP reply to DUT.
@pytest.fixture(scope="module", autouse=True)
def pfcwd_pause_service(ptfhost):
    needs_resume = {"icmp_responder": False, "garp_service": False}

    out = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True).get("stdout", "")
    if 'RUNNING' in out:
        needs_resume["icmp_responder"] = True
        ptfhost.shell("supervisorctl stop icmp_responder")

    out = ptfhost.shell("supervisorctl status garp_service", module_ignore_errors=True).get("stdout", "")
    if 'RUNNING' in out:
        needs_resume["garp_service"] = True
        ptfhost.shell("supervisorctl stop garp_service")

    logger.debug("pause_service needs_resume {}".format(needs_resume))

    yield

    if needs_resume["icmp_responder"]:
        ptfhost.shell("supervisorctl start icmp_responder")
        needs_resume["icmp_responder"] = False
    if needs_resume["garp_service"]:
        ptfhost.shell("supervisorctl start garp_service")
        needs_resume["garp_service"] = False

    logger.debug("pause_service needs_resume {}".format(needs_resume))


@pytest.fixture(scope="function", autouse=False)
def set_pfc_time_cisco_8000(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        setup_pfc_test):

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    test_ports = setup_pfc_test['test_ports']

    # Lets limit this to cisco and T2 only.
    if duthost.facts['asic_type'] != "cisco-8000":
        yield
        return

    PFC_TIME_SET_SCRIPT = "pfcwd/cisco/set_pfc_time.py"
    PFC_TIME_RESET_SCRIPT = "pfcwd/cisco/default_pfc_time.py"

    for port in test_ports:
        asic_id = ""
        if duthost.sonichost.is_multi_asic:
            asic_id = duthost.get_port_asic_instance(port).asic_index
        set_pfc_timer_cisco_8000(
            duthost,
            asic_id,
            PFC_TIME_SET_SCRIPT,
            port)

    yield

    for port in test_ports:
        asic_id = ""
        if duthost.sonichost.is_multi_asic:
            asic_id = duthost.get_port_asic_instance(port).asic_index
        set_pfc_timer_cisco_8000(
            duthost,
            asic_id,
            PFC_TIME_RESET_SCRIPT,
            port)


def set_pfc_timer_cisco_8000(duthost, asic_id, script, port):

    script_name = os.path.basename(script)
    dut_script_path = f"/tmp/{script_name}"
    duthost.copy(src=script, dest=dut_script_path)
    duthost.shell(f"sed -i 's/INTERFACE/{port}/' {dut_script_path}")
    duthost.docker_copy_to_all_asics(
        container_name=f"syncd{asic_id}",
        src=dut_script_path,
        dst="/")

    asic_arg = ""
    if asic_id != "":
        asic_arg = f"-n asic{asic_id}"
    duthost.shell(f"show platform npu script {asic_arg} -s {script_name}")


@pytest.fixture(autouse=True, scope="module")
def cleanup(duthosts, ptfhost, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that remove ip address of ethX interface at ptf and clear arp at dut
    :param duthosts: dut instance
    :param ptfhost: ptf instance
    :return: None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    ptfhost.remove_ip_addresses()
    duthost.command("sonic-clear arp")
