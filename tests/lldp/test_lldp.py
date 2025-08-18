import logging
import pytest
import time
from tests.common.platform.interface_utils import get_dpu_npu_ports_from_hwsku
from tests.common.helpers.dut_utils import get_program_info, kill_process_by_pid, is_container_running
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'm0', 'mx', 'm1'),
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
    feature_name = "swss"
    container_name = asic.get_docker_name(feature_name)
    program_name = "orchagent"

    pre_lldpctl_facts = get_num_lldpctl_facts(duthost, enum_frontend_asic_index)
    assert pre_lldpctl_facts != 0, (
        "Cannot get lldp neighbor information. "
        "No LLDP neighbor entries were detected before restarting orchagent. "
        "pre_lldpctl_facts value: {}"
    ).format(pre_lldpctl_facts)

    if duthost.facts['switch_type'] == "voq":
        """ VOQ type chassis does not support warm restart of orchagent. Use restart service here """
        duthost.shell("sudo systemctl reset-failed")
        duthost.shell("sudo systemctl restart {}".format(asic.get_service_name("swss")))
        # make sure all critical services are up
        assert wait_until(600, 5, 30, duthost.critical_services_fully_started), (
            "Not all critical services are fully started after restarting orchagent. "
            "Hostname: {}\n"
            "Platform: {}\n"
            "HWSKU: {}\n"
        ).format(
            duthost.hostname,
            duthost.facts.get("platform"),
            duthost.facts.get("hwsku")
        )

        # wait for ports to be up and lldp neighbor information has been received by dut
        assert wait_until(300, 20, 60,
                          lambda: pre_lldpctl_facts == get_num_lldpctl_facts(duthost, enum_frontend_asic_index)), (
            "Cannot get all lldp entries. "
            "Expected LLDP entries: {}\n"
            "Current LLDP entries: {}"
        ).format(
            pre_lldpctl_facts,
            get_num_lldpctl_facts(duthost, enum_frontend_asic_index)
        )

        # add delay here to make sure neighbor devices also have received lldp packets from dut and neighbor
        # information has been updated properly
        time.sleep(30)
    else:
        logger.info("Restarting program '{}' in container '{}'".format(program_name, container_name))
        # disable feature autorestart. Feature is enabled/disabled at feature level and
        # not per container namespace level.
        duthost.shell("sudo config feature autorestart {} disabled".format(feature_name))
        _, program_pid = get_program_info(duthost, container_name, program_name)
        kill_process_by_pid(duthost, container_name, program_name, program_pid)
        is_running = is_container_running(duthost, container_name)
        pytest_assert(
            is_running,
            (
                "Container '{}' is not running."
            ).format(container_name)
        )

        duthost.shell("docker exec {} supervisorctl start {}".format(container_name, program_name))
    yield


def get_num_lldpctl_facts(duthost, enum_frontend_asic_index):
    internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
    lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=enum_frontend_asic_index,
        skip_interface_pattern_list=["eth0", "Ethernet-BP", "Ethernet-IB"] + internal_port_list)['ansible_facts']
    if not list(lldpctl_facts['lldpctl'].items()):
        return 0
    return len(lldpctl_facts['lldpctl'])


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
        assert v['chassis']['name'] == config_facts['DEVICE_NEIGHBOR'][k]['name'], (
            "LLDP neighbor name mismatch. Expected '{}', but got '{}'."
        ).format(
            config_facts['DEVICE_NEIGHBOR'][k]['name'],
            v['chassis']['name']
        )

        # Compare the LLDP neighbor interface with minigraph neigbhor interface (exclude the management port)
        if request.config.getoption("--neighbor_type") == 'eos':
            assert v['port']['ifname'] == config_facts['DEVICE_NEIGHBOR'][k]['port'], (
                "LLDP neighbor port interface name mismatch. Expected '{}', but got '{}'."
            ).format(
                config_facts['DEVICE_NEIGHBOR'][k]['port'],
                v['port']['ifname']
            )

        else:
            # Dealing with KVM that advertises port description
            assert v['port']['descr'] == config_facts['DEVICE_NEIGHBOR'][k]['port'], (
                "LLDP neighbor port description mismatch. Expected '{}', but got '{}'."
            ).format(
                config_facts['DEVICE_NEIGHBOR'][k]['port'],
                v['port']['descr']
            )


def check_lldp_neighbor(duthost, localhost, eos, sonic, collect_techsupport_all_duts,
                        enum_rand_one_frontend_asic_index, tbinfo, request):
    """ verify LLDP information on neighbors """
    asic = enum_rand_one_frontend_asic_index

    res = duthost.shell(
        "docker exec -i lldp{} lldpcli show chassis | grep \"SysDescr:\" | sed -e 's/^\\s*SysDescr:\\s*//g'".format(
            '' if asic is None else asic))
    dut_system_description = res['stdout']
    internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
    lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=asic,
        skip_interface_pattern_list=["eth0", "Ethernet-BP", "Ethernet-IB"] + internal_port_list)['ansible_facts']
    config_facts = duthost.asic_instance(asic).config_facts(host=duthost.hostname, source="running")['ansible_facts']
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
        assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_name'] == duthost.hostname, (
            "LLDP neighbor system name mismatch for interface '{}'. "
            "Expected '{}', but got '{}'."
        ).format(
            neighbor_interface,
            duthost.hostname,
            nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_name']
        )

        # Verify the published DUT chassis id field is not empty
        if request.config.getoption("--neighbor_type") == 'eos':
            assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id'] == \
                "0x%s" % (switch_mac.replace(':', '')), (
                "LLDP neighbor chassis ID mismatch for interface '{}'. "
                "Expected chassis ID: '{}', but got: '{}'."
            ).format(
                neighbor_interface,
                "0x%s" % (switch_mac.replace(':', '')),
                nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id']
            )

        else:
            assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id'] == switch_mac, (
                "LLDP neighbor chassis ID mismatch for interface '{}'. "
                "Expected chassis ID: '{}', but got: '{}'."
            ).format(
                neighbor_interface,
                switch_mac,
                nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_chassis_id']
            )

        # Verify the published DUT system description field is correct
            assert (
                nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_desc']
                == dut_system_description
            ), (
                "LLDP neighbor system description mismatch for interface '{}'. "
                "Expected system description: '{}', but got: '{}'."
            ).format(
                neighbor_interface,
                dut_system_description,
                nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_sys_desc']
            )

        # Verify the published DUT port id field is correct
            assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_id'] == \
                config_facts['PORT'][k]['alias'], (
                "LLDP neighbor port ID mismatch for interface '{}'. "
                "Expected port ID (alias) from config_facts: '{}', but got from LLDP: '{}'."
            ).format(
                neighbor_interface,
                config_facts['PORT'][k]['alias'],
                nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_id']
            )

        # Verify the published DUT port description field is correct
            assert nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_desc'] == \
                config_facts['PORT'][k]['description'], (
                "LLDP neighbor port description mismatch for interface '{}'. "
                "Expected port description from config_facts: '{}', but got from LLDP: '{}'."
            ).format(
                neighbor_interface,
                config_facts['PORT'][k]['description'],
                nei_lldp_facts['ansible_lldp_facts'][neighbor_interface]['neighbor_port_desc']
            )


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
    duthost.shell("sudo config feature autorestart swss enabled")
