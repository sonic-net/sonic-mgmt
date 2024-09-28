import logging
import pytest
from tests.common.platform.interface_utils import get_dpu_npu_ports_from_hwsku
from tests.common.helpers.dut_utils import get_program_info, kill_process_by_pid, is_container_running

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'm0', 'mx'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)


@pytest.fixture(scope="function")
def restart_orchagent(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    container_name = asic.get_docker_name("swss")
    program_name = "orchagent"

    logger.info("Restarting program '{}' in container '{}'".format(program_name, container_name))

    duthost.shell("sudo config feature autorestart {} disabled".format(container_name))
    _, program_pid = get_program_info(duthost, container_name, program_name)
    kill_process_by_pid(duthost, container_name, program_name, program_pid)
    is_running = is_container_running(duthost, container_name)
    pytest_assert(is_running, "Container '{}' is not running. Exiting...".format(container_name))
    duthost.shell("docker exec {} supervisorctl start {}".format(container_name, program_name))
    yield


def test_lldp(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost,
              collect_techsupport_all_duts, enum_frontend_asic_index, request):
    """ verify the LLDP message on DUT """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    config_facts = duthost.asic_instance(
        enum_frontend_asic_index).config_facts(host=duthost.hostname, source="running")['ansible_facts']
    internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
    lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=enum_frontend_asic_index,
        skip_interface_pattern_list=["eth0", "Ethernet-BP", "Ethernet-IB"] + internal_port_list)['ansible_facts']
    if not list(lldpctl_facts['lldpctl'].items()):
        pytest.fail("No LLDP neighbors received (lldpctl_facts are empty)")
    for k, v in list(lldpctl_facts['lldpctl'].items()):
        # Compare the LLDP neighbor name with minigraph neigbhor name (exclude the management port)
        assert v['chassis']['name'] == config_facts['DEVICE_NEIGHBOR'][k]['name']
        # Compare the LLDP neighbor interface with minigraph neigbhor interface (exclude the management port)
        if request.config.getoption("--neighbor_type") == 'eos':
            assert v['port']['ifname'] == config_facts['DEVICE_NEIGHBOR'][k]['port']
        else:
            # Dealing with KVM that advertises port description
            assert v['port']['descr'] == config_facts['DEVICE_NEIGHBOR'][k]['port']


def check_lldp_neighbor(duthost, localhost, eos, sonic, collect_techsupport_all_duts,
                        enum_frontend_asic_index, tbinfo, request):
    """ verify LLDP information on neighbors """

    res = duthost.shell(
        "docker exec -i lldp lldpcli show chassis | grep \"SysDescr:\" | sed -e 's/^\\s*SysDescr:\\s*//g'")
    dut_system_description = res['stdout']
    internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
    lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=enum_frontend_asic_index,
        skip_interface_pattern_list=["eth0", "Ethernet-BP", "Ethernet-IB"] + internal_port_list)['ansible_facts']
    config_facts = duthost.asic_instance(enum_frontend_asic_index).config_facts(host=duthost.hostname,
                                                                                source="running")['ansible_facts']
    if not list(lldpctl_facts['lldpctl'].items()):
        pytest.fail("No LLDP neighbors received (lldpctl_facts are empty)")
    # We use the MAC of mgmt port to generate chassis ID as LLDPD dose.
    # To be compatible with PR #3331, we keep using router MAC on T2 devices
    switch_mac = ""
    if tbinfo["topo"]["type"] != "t2":
        mgmt_alias = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_mgmt_interface"]["alias"]
        switch_mac = duthost.get_dut_iface_mac(mgmt_alias)
    elif tbinfo["topo"]["type"] == "t2":
        switch_mac = config_facts['DEVICE_METADATA']['localhost']['mac'].lower()
    else:
        switch_mac = duthost.facts['router_mac']

    nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})

    for k, v in list(lldpctl_facts['lldpctl'].items()):
        try:
            hostip = v['chassis']['mgmt-ip']
        except Exception:
            logger.info("Neighbor device {} does not sent management IP via lldp".format(v['chassis']['name']))
            hostip = nei_meta[v['chassis']['name']]['mgmt_addr']

        if request.config.getoption("--neighbor_type") == 'eos':
            nei_lldp_facts = localhost.lldp_facts(host=hostip, version='v2c', community=eos['snmp_rocommunity'])[
                'ansible_facts']
            neighbor_interface = v['port']['ifname']
        else:
            nei_lldp_facts = localhost.lldp_facts(host=hostip, version='v2c', community=sonic['snmp_rocommunity'])[
                'ansible_facts']
            neighbor_interface = v['port']['local']
        # Verify the published DUT system name field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_name'] == duthost.hostname
        # Verify the published DUT chassis id field is not empty
        if request.config.getoption("--neighbor_type") == 'eos':
            assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id'] == \
                "0x%s" % (switch_mac.replace(':', ''))
        else:
            assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id'] == switch_mac

        # Verify the published DUT system description field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_desc'] == dut_system_description
        # Verify the published DUT port id field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_id'] == \
            config_facts['PORT'][k]['alias']
        # Verify the published DUT port description field is correct
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_desc'] == \
            config_facts['PORT'][k]['description']


def test_lldp_neighbor(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, eos, sonic,
                       collect_techsupport_all_duts, loganalyzer, enum_frontend_asic_index, tbinfo, request):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if loganalyzer:
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend([
            ".*ERR syncd#syncd: :- check_fdb_event_notification_data.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb \
                notifications, NOT translating and NOT storing in ASIC DB.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: FDB notification was \
                not sent since it contain invalid OIDs, bug.*",
        ])
    check_lldp_neighbor(duthost, localhost, eos, sonic, collect_techsupport_all_duts,
                        enum_frontend_asic_index, tbinfo, request)


@pytest.mark.disable_loganalyzer
def test_lldp_neighbor_post_orchagent_reboot(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, eos,
                                             sonic, collect_techsupport_all_duts,
                                             enum_frontend_asic_index, tbinfo, request, restart_orchagent):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    check_lldp_neighbor(duthost, localhost, eos, sonic, collect_techsupport_all_duts,
                        enum_frontend_asic_index, tbinfo, request)
