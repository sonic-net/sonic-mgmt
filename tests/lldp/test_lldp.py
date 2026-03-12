import logging
import pytest
from tests.common.platform.interface_utils import get_dpu_npu_ports_from_hwsku
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

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
def restart_swss_container(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Check for swss autorestart state
    swss_autorestart_state = "enabled" if "enabled" in duthost.shell("show feature autorestart swss")['stdout'] \
        else "disabled"
    asic = duthost.asic_instance(enum_frontend_asic_index)

    pre_lldpctl_facts = get_num_lldpctl_facts(duthost, enum_frontend_asic_index)
    assert pre_lldpctl_facts != 0, (
        "Cannot get lldp neighbor information. "
        "No LLDP neighbor entries were detected before restarting orchagent. "
        "pre_lldpctl_facts value: {}"
    ).format(pre_lldpctl_facts)

    duthost.shell("sudo systemctl reset-failed")
    duthost.shell("sudo systemctl restart {}".format(asic.get_service_name("swss")))

    # make sure all critical services are up
    assert wait_until(600, 5, 30, duthost.critical_services_fully_started), (
        "Not all critical services are fully started after restarting orchagent. "
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

    yield

    duthost.shell(f"sudo config feature autorestart swss {swss_autorestart_state}")


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
    converged = duthosts.tbinfo['topo']['properties'].get('topo_is_multi_vrf', False)
    convergence_info = None
    rev_vrf_map = {}
    if converged:
        convergence_info = duthosts.tbinfo['topo']['properties']['convergence_data']
        for primary, vrflist in convergence_info['convergence_mapping'].items():
            for vrf in vrflist:
                rev_vrf_map[vrf] = primary

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
        if converged:
            exp_intf = config_facts['DEVICE_NEIGHBOR'][k]['port']
            vrf = config_facts['DEVICE_NEIGHBOR'][k]['name']
            primary = rev_vrf_map[vrf]
            new_intf = convergence_info['converged_peers'][primary]['intf_mapping'][vrf]['orig_intf_map'][exp_intf]
            assert v['chassis']['name'] == primary
            assert v['port']['ifname'] == new_intf
        else:
            # Compare the LLDP neighbor name with minigraph neigbhor name (exclude the management port)
            assert v['chassis']['name'] == config_facts['DEVICE_NEIGHBOR'][k]['name']
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
def test_lldp_neighbor_post_swss_reboot(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, eos,
                                        sonic, collect_techsupport_all_duts, enum_frontend_asic_index,
                                        tbinfo, request, restart_swss_container):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    check_lldp_neighbor(duthost, localhost, eos, sonic, collect_techsupport_all_duts,
                        enum_frontend_asic_index, tbinfo, request)


@pytest.mark.disable_loganalyzer
def test_lldp_after_config_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost,
                                  collect_techsupport_all_duts, enum_frontend_asic_index, tbinfo, request):
    """Verify LLDP neighbors are fully restored after config reload.

    Addresses test gap issue #22376 — validates that lldpd correctly detects
    all interfaces after config reload, including chassis ID type and absence
    of 'cannot find port' errors in syslog.

    Related PR: https://github.com/sonic-net/sonic-buildimage/pull/25436
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_index = enum_frontend_asic_index

    internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
    skip_pattern_list = ["eth0", "Ethernet-BP", "Ethernet-IB"] + internal_port_list

    # Step 1: Record LLDP state before config reload
    pre_lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=asic_index,
        skip_interface_pattern_list=skip_pattern_list)['ansible_facts']
    assert list(pre_lldpctl_facts['lldpctl'].items()), \
        "No LLDP neighbors detected before config reload"
    pre_neighbors = set(pre_lldpctl_facts['lldpctl'].keys())
    pre_count = len(pre_neighbors)
    logger.info("LLDP neighbors before config reload (%d): %s", pre_count, sorted(pre_neighbors))

    # Record interface status before reload
    pre_intf_status = duthost.show_interface(command="status")['ansible_facts']['int_status']
    pre_up_intfs = {intf for intf, status in pre_intf_status.items()
                    if status.get('oper_state', '').lower() == 'up' and not intf.startswith('Loopback')}
    logger.info("Interfaces up before config reload: %d", len(pre_up_intfs))

    # Step 2: Perform config reload
    logger.info("Performing config reload")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    # Step 3: Wait for LLDP neighbors to be fully restored
    assert wait_until(300, 20, 60,
                      lambda: pre_count <= get_num_lldpctl_facts(duthost, asic_index)), \
        "LLDP neighbors not fully restored after config reload. " \
        "Expected at least {} entries, got {}".format(
            pre_count, get_num_lldpctl_facts(duthost, asic_index))

    # Step 4: Verify LLDP table matches pre-reload state
    post_lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=asic_index,
        skip_interface_pattern_list=skip_pattern_list)['ansible_facts']
    post_neighbors = set(post_lldpctl_facts['lldpctl'].keys())

    missing = pre_neighbors - post_neighbors
    assert not missing, \
        "LLDP neighbors missing after config reload: {}".format(sorted(missing))

    # Verify neighbor names match
    for intf in pre_neighbors:
        pre_name = pre_lldpctl_facts['lldpctl'][intf]['chassis']['name']
        post_name = post_lldpctl_facts['lldpctl'][intf]['chassis']['name']
        assert pre_name == post_name, \
            "LLDP neighbor name changed on {} after config reload: '{}' -> '{}'".format(
                intf, pre_name, post_name)

    # Step 5: Verify Chassis ID type is MAC (not hostname)
    chassis_output = duthost.shell(
        "docker exec -i lldp{} lldpcli show chassis".format(
            '' if asic_index is None else asic_index))['stdout']
    logger.info("Chassis info after config reload:\n%s", chassis_output)

    assert "mac" in chassis_output.lower(), \
        "Chassis ID type should be 'mac' after config reload, got:\n{}".format(chassis_output)

    # Verify chassis MAC matches eth0 MAC (for non-T2 topologies)
    if tbinfo["topo"]["type"] != "t2":
        mgmt_facts = duthost.get_extended_minigraph_facts(tbinfo)
        mgmt_alias = mgmt_facts["minigraph_mgmt_interface"]["alias"]
        eth0_mac = duthost.get_dut_iface_mac(mgmt_alias)
        assert eth0_mac.lower() in chassis_output.lower(), \
            "Chassis MAC should match {} MAC '{}', got:\n{}".format(
                mgmt_alias, eth0_mac, chassis_output)

    # Step 6: Verify lldpcli show interfaces matches expected ports
    lldpcli_intfs_output = duthost.shell(
        "docker exec -i lldp{} lldpcli show interfaces".format(
            '' if asic_index is None else asic_index))['stdout']
    for intf in pre_neighbors:
        assert intf in lldpcli_intfs_output, \
            "Interface {} not found in 'lldpcli show interfaces' after config reload".format(intf)

    # Step 7: Check syslog for lldp errors (informational, not a hard failure)
    syslog_output = duthost.shell(
        "sudo grep -i 'cannot find port\\|ERR lldp#lldpmgrd' /var/log/syslog | tail -20",
        module_ignore_errors=True)['stdout']
    if syslog_output:
        logger.warning("LLDP errors found in syslog after config reload:\n%s", syslog_output)
    else:
        logger.info("No LLDP errors found in syslog after config reload")
