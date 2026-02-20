import logging
import re
import pytest
from tests.common.platform.interface_utils import get_dpu_npu_ports_from_hwsku
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert

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


def test_lldp_interfaces(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                         enum_frontend_asic_index, tbinfo, loganalyzer):
    """
    Test LLDP functionality to verify all interfaces and chassis information are correct.
    This test is similar to test_lldp_interface_config_reload but without performing config reload.

    Steps:
    1. Record all interfaces from 'show interface status'
    2. Verify LLDP table matches recorded interfaces
    3. Verify lldpcli interfaces match recorded interfaces
    4. Verify chassis ID and capabilities
    5. Check syslog for LLDP errors using loganalyzer
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    # Configure loganalyzer to fail if LLDP errors are found
    if loganalyzer:
        # Add LLDP error patterns to match_regex (will fail if found)
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].match_regex.extend([
            ".*cannot find port.*",
            ".*ERR lldp#lldpmgrd.*"
        ])

    with loganalyzer[enum_rand_one_per_hwsku_frontend_hostname] if loganalyzer else None:
        logger.info("Step 1: Recording all interfaces")
        # Get all interfaces from 'show interface status' using show_and_parse
        intf_status_output = duthost.show_and_parse("show interface status")

        # Save all original interfaces
        all_interfaces = {intf['interface'] for intf in intf_status_output}
        logger.info("All interfaces from 'show interface status': {}".format(sorted(all_interfaces)))
        logger.info("All interfaces in total: {}".format(len(all_interfaces)))

        # Get chassis MAC address from management interface
        mgmt_alias = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_mgmt_interface"]["alias"]
        expected_chassis_mac = duthost.get_dut_iface_mac(mgmt_alias).lower()
        logger.info("Expected chassis MAC address: {}".format(expected_chassis_mac))

        logger.info("Step 2: Verifying LLDP table")
        # Get LLDP table output
        lldp_table_output = duthost.shell("show lldp table")['stdout']
        lldp_table_interfaces = set()
        for line in lldp_table_output.split('\n'):
            if line.strip() and not line.startswith('Capability') and not line.startswith('LocalPort') \
               and not line.startswith('---') and not line.startswith('Total'):
                parts = line.split()
                if parts:
                    interface = parts[0]
                    lldp_table_interfaces.add(interface)

        logger.info("LLDP table interfaces: {}".format(sorted(lldp_table_interfaces)))
        logger.info("LLDP table interfaces in total: {}".format(len(lldp_table_interfaces)))

        # Verify eth0 is in LLDP table
        pytest_assert('eth0' in lldp_table_interfaces,
                      "eth0 is missing from LLDP table")

        # For LLDP table comparison: exclude eth0 from lldp_table, exclude PortChannels and admin down from intf_status
        lldp_table_interfaces_no_eth0 = lldp_table_interfaces - {'eth0'}

        # Filter intf_status_output: exclude PortChannel interfaces and admin down interfaces
        intf_status_filtered_for_lldp = {
            intf['interface'] for intf in intf_status_output
            if not intf['interface'].startswith('PortChannel') and intf['admin'].lower() == 'up'
        }

        missing_in_lldp_table = intf_status_filtered_for_lldp - lldp_table_interfaces_no_eth0
        extra_in_lldp_table = lldp_table_interfaces_no_eth0 - intf_status_filtered_for_lldp

        if missing_in_lldp_table:
            logger.warning("Interfaces (admin up, no PortChannels) missing in LLDP table: {}".format(
                sorted(missing_in_lldp_table)))
        if extra_in_lldp_table:
            logger.warning("Interfaces in LLDP table but not in filtered interface status: {}".format(
                sorted(extra_in_lldp_table)))

        if not missing_in_lldp_table and not extra_in_lldp_table:
            logger.info("LLDP table and interface status (admin up, no PortChannels) match perfectly")

        pytest_assert(intf_status_filtered_for_lldp == lldp_table_interfaces_no_eth0,
                      "Interface mismatch between 'show interface status' (admin up, no PortChannels) and LLDP table. "
                      "Missing in LLDP table: {}, Extra in LLDP table: {}".format(
                          sorted(missing_in_lldp_table), sorted(extra_in_lldp_table)))

        logger.info("Step 3: Verifying lldpcli show interfaces")
        # Get lldpcli interfaces
        lldpcli_output = duthost.shell(
            "docker exec lldp{} lldpcli show interfaces".format(
                asic.get_asic_index() if duthost.is_multi_asic else ""
            )
        )['stdout']

        lldpcli_interfaces = set()
        for line in lldpcli_output.split('\n'):
            if line.startswith('Interface:'):
                interface = line.split('Interface:')[1].strip()
                lldpcli_interfaces.add(interface)

        logger.info("lldpcli interfaces: {}".format(sorted(lldpcli_interfaces)))
        logger.info("lldpcli interfaces in total: {}".format(len(lldpcli_interfaces)))

        # Verify eth0 is in lldpcli interfaces
        pytest_assert('eth0' in lldpcli_interfaces,
                      "eth0 is missing from lldpcli interfaces")

        # For lldpcli comparison: exclude eth0 from lldpcli, exclude only PortChannels from intf_status
        lldpcli_interfaces_no_eth0 = lldpcli_interfaces - {'eth0'}

        # Filter intf_status_output: exclude only PortChannel interfaces (keep admin down)
        intf_status_filtered_for_lldpcli = {
            intf['interface'] for intf in intf_status_output
            if not intf['interface'].startswith('PortChannel')
        }

        missing_in_lldpcli = intf_status_filtered_for_lldpcli - lldpcli_interfaces_no_eth0
        extra_in_lldpcli = lldpcli_interfaces_no_eth0 - intf_status_filtered_for_lldpcli

        if missing_in_lldpcli:
            logger.warning("Interfaces (no PortChannels) missing in lldpcli: {}".format(
                sorted(missing_in_lldpcli)))
        if extra_in_lldpcli:
            logger.warning("Interfaces in lldpcli but not in interface status: {}".format(
                sorted(extra_in_lldpcli)))

        if not missing_in_lldpcli and not extra_in_lldpcli:
            logger.info("lldpcli and interface status (no PortChannels) match perfectly")

        pytest_assert(intf_status_filtered_for_lldpcli == lldpcli_interfaces_no_eth0,
                      "Interface mismatch between 'show interface status' (no PortChannels) and lldpcli. "
                      "Missing in lldpcli: {}, Extra in lldpcli: {}".format(
                          sorted(missing_in_lldpcli), sorted(extra_in_lldpcli)))
        # Verify that all interfaces from 'show interface status' that have LLDP neighbors are present
        internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
        lldpctl_facts = duthost.lldpctl_facts(
            asic_instance_id=enum_frontend_asic_index,
            skip_interface_pattern_list=["Ethernet-BP", "Ethernet-IB"] + internal_port_list
        )['ansible_facts']

        # Verify eth0 is in lldpctl_facts
        pytest_assert('eth0' in lldpctl_facts.get('lldpctl', {}),
                      "eth0 is missing from lldpctl_facts")

        # Get interfaces from lldpctl_facts (excluding eth0)
        lldpctl_facts_interfaces = set(lldpctl_facts.get('lldpctl', {}).keys()) - {'eth0'}
        logger.info("lldpctl_facts interfaces (excluding eth0): {}".format(sorted(lldpctl_facts_interfaces)))
        logger.info("lldpctl_facts interfaces in total: {}".format(len(lldpctl_facts_interfaces)))

        # Compare intf_status_output with lldpctl_facts interfaces
        # (exclude PortChannels and admin down from intf_status)
        intf_status_filtered_for_lldpctl = {
            intf['interface'] for intf in intf_status_output
            if not intf['interface'].startswith('PortChannel') and intf['admin'].lower() == 'up'
        }

        missing_in_lldpctl_facts = intf_status_filtered_for_lldpctl - lldpctl_facts_interfaces
        extra_in_lldpctl_facts = lldpctl_facts_interfaces - intf_status_filtered_for_lldpctl

        if missing_in_lldpctl_facts:
            logger.warning("Interfaces in 'show interface status' but missing in lldpctl_facts: {}".format(
                sorted(missing_in_lldpctl_facts)))
        if extra_in_lldpctl_facts:
            logger.warning("Interfaces in lldpctl_facts but not in 'show interface status': {}".format(
                sorted(extra_in_lldpctl_facts)))

        if not missing_in_lldpctl_facts and not extra_in_lldpctl_facts:
            logger.info("lldpctl_facts and interface status (admin up, no PortChannels) match perfectly")

        pytest_assert(intf_status_filtered_for_lldpctl == lldpctl_facts_interfaces,
                      "Interface mismatch between 'show interface status' and lldpctl_facts "
                      "(admin up, no PortChannels). "
                      "Missing in lldpctl_facts: {}, Extra in lldpctl_facts: {}".format(
                          sorted(missing_in_lldpctl_facts), sorted(extra_in_lldpctl_facts)))

        for interface in lldpctl_facts.get('lldpctl', {}):
            pytest_assert(interface in lldpcli_interfaces,
                          "Interface {} from lldpctl_facts is missing in lldpcli interfaces".format(interface))

        logger.info("Step 4: Verifying Chassis ID and Capabilities")
        # Get chassis information
        chassis_output = duthost.shell(
            "docker exec lldp{} lldpcli show chassis".format(
                asic.get_asic_index() if duthost.is_multi_asic else ""
            )
        )['stdout']

        logger.info("Chassis output:\n{}".format(chassis_output))

        # Verify ChassisID type is mac
        chassis_id_match = re.search(r'ChassisID:\s+mac\s+([0-9a-f:]+)', chassis_output, re.IGNORECASE)
        pytest_assert(chassis_id_match is not None,
                      "ChassisID with type 'mac' not found in chassis output")

        actual_chassis_mac = chassis_id_match.group(1).lower()
        pytest_assert(actual_chassis_mac == expected_chassis_mac,
                      "Chassis MAC mismatch. Expected: {}, Got: {}".format(
                          expected_chassis_mac, actual_chassis_mac))

        # Verify Capabilities are present with correct status
        pytest_assert(re.search(r'Capability:\s+Bridge,\s+on', chassis_output, re.IGNORECASE),
                      "Bridge capability should be 'on' in chassis output")
        pytest_assert(re.search(r'Capability:\s+Router,\s+on', chassis_output, re.IGNORECASE),
                      "Router capability should be 'on' in chassis output")
        pytest_assert(re.search(r'Capability:\s+Wlan,\s+off', chassis_output, re.IGNORECASE),
                      "Wlan capability should be 'off' in chassis output")
        pytest_assert(re.search(r'Capability:\s+Station,\s+off', chassis_output, re.IGNORECASE),
                      "Station capability should be 'off' in chassis output")

    logger.info("Test completed successfully. All LLDP checks passed.")


def test_lldp_interface_config_reload(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                      enum_frontend_asic_index, tbinfo, loganalyzer):
    """
    Test LLDP functionality after config reload to verify all interfaces and chassis information are correct.
    This test covers the issue: https://github.com/sonic-net/sonic-mgmt/issues/22376

    Steps:
    1. Record all interfaces before the test
    2. Perform config reload
    3. Verify LLDP table matches recorded interfaces
    4. Verify lldpcli interfaces match recorded interfaces
    5. Verify chassis ID and capabilities
    6. Check syslog for LLDP errors using loganalyzer
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)

    # Configure loganalyzer to check for specific LLDP errors while ignoring expected config reload errors
    if loganalyzer:
        # Add LLDP error patterns to match_regex (will fail if found)
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].match_regex.extend([
            ".*cannot find port.*",
            ".*ERR lldp#lldpmgrd.*"
        ])

        # Ignore expected errors during config reload
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend([
            ".*ERR memory_checker.*",
            ".*ERR.* container .* not running.*",
            ".*ERR.* Failed to get container ID.*",
            ".*ERR.* Container .* is not running.*",
            ".*ERR syncd#syncd.*",
            ".*ERR kernel.*",
            ".*ERR.*: route already exists.*",
            ".*ERR.*PortInitDone.*",
            ".*ERR.*Incomplete key.*",
            ".*ERR.*portsyncd.*",
            ".*ERR.*neighsyncd.*"
        ])

    with loganalyzer[enum_rand_one_per_hwsku_frontend_hostname] if loganalyzer else None:
        logger.info("Step 1: Recording all interfaces before config reload")
        # Get all interfaces from 'show interface status' using show_and_parse
        intf_status_output = duthost.show_and_parse("show interface status")

        # Save all original interfaces
        all_pre_reload_interfaces = {intf['interface'] for intf in intf_status_output}
        logger.info("All interfaces before config reload: {}".format(sorted(all_pre_reload_interfaces)))
        logger.info("All interfaces in total: {}".format(len(all_pre_reload_interfaces)))

        # Get chassis MAC address from eth0 before reload
        mgmt_alias = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_mgmt_interface"]["alias"]
        expected_chassis_mac = duthost.get_dut_iface_mac(mgmt_alias).lower()
        logger.info("Expected chassis MAC address: {}".format(expected_chassis_mac))

        logger.info("Step 2: Performing config reload")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        logger.info("Step 3: Waiting for system to stabilize after config reload")
        # Wait for LLDP to converge
        assert wait_until(300, 10, 0, duthost.critical_services_fully_started), \
            "Not all critical services are fully started after config reload"

        # Additional wait for LLDP neighbors to be discovered
        pytest_assert(
            wait_until(180, 10, 0, lambda: get_num_lldpctl_facts(duthost, enum_frontend_asic_index) > 0),
            "No LLDP neighbors discovered after config reload"
        )

        logger.info("Step 4: Verifying LLDP table after config reload")
        # Get LLDP table output
        lldp_table_output = duthost.shell("show lldp table")['stdout']
        post_reload_lldp_interfaces = set()
        for line in lldp_table_output.split('\n'):
            if line.strip() and not line.startswith('Capability') and not line.startswith('LocalPort') \
               and not line.startswith('---') and not line.startswith('Total'):
                parts = line.split()
                if parts:
                    interface = parts[0]
                    post_reload_lldp_interfaces.add(interface)

        logger.info("LLDP table interfaces after reload: {}".format(sorted(post_reload_lldp_interfaces)))

        # Verify eth0 is in LLDP table
        pytest_assert('eth0' in post_reload_lldp_interfaces,
                      "eth0 is missing from LLDP table after config reload")

        # For LLDP table comparison: exclude eth0 from lldp_table, exclude PortChannels and admin down from intf_status
        post_reload_lldp_interfaces_no_eth0 = post_reload_lldp_interfaces - {'eth0'}

        # Filter intf_status_output: exclude PortChannel interfaces and admin down interfaces
        intf_status_filtered_for_lldp = {
            intf['interface'] for intf in intf_status_output
            if not intf['interface'].startswith('PortChannel') and intf['admin'].lower() == 'up'
        }

        missing_in_lldp_table = intf_status_filtered_for_lldp - post_reload_lldp_interfaces_no_eth0
        extra_in_lldp_table = post_reload_lldp_interfaces_no_eth0 - intf_status_filtered_for_lldp

        if missing_in_lldp_table:
            logger.warning("Interfaces (admin up, no PortChannels) missing in LLDP table after reload: {}".format(
                sorted(missing_in_lldp_table)))
        if extra_in_lldp_table:
            logger.warning("Interfaces in LLDP table but not in filtered interface status after reload: {}".format(
                sorted(extra_in_lldp_table)))

        if not missing_in_lldp_table and not extra_in_lldp_table:
            logger.info("LLDP table and interface status (admin up, no PortChannels) match perfectly after reload")

        pytest_assert(intf_status_filtered_for_lldp == post_reload_lldp_interfaces_no_eth0,
                      "Interface mismatch between pre-reload (admin up, no PortChannels) and LLDP table after reload. "
                      "Missing in LLDP table: {}, Extra in LLDP table: {}".format(
                          sorted(missing_in_lldp_table), sorted(extra_in_lldp_table)))

        logger.info("Step 5: Verifying lldpcli show interfaces")
        # Get lldpcli interfaces
        lldpcli_output = duthost.shell(
            "docker exec lldp{} lldpcli show interfaces".format(
                asic.get_asic_index() if duthost.is_multi_asic else ""
            )
        )['stdout']

        lldpcli_interfaces = set()
        for line in lldpcli_output.split('\n'):
            if line.startswith('Interface:'):
                interface = line.split('Interface:')[1].strip()
                lldpcli_interfaces.add(interface)

        logger.info("lldpcli interfaces after reload: {}".format(sorted(lldpcli_interfaces)))

        # Verify eth0 is in lldpcli interfaces
        pytest_assert('eth0' in lldpcli_interfaces,
                      "eth0 is missing from lldpcli interfaces after config reload")

        # For lldpcli comparison: exclude eth0 from lldpcli, exclude only PortChannels from intf_status
        lldpcli_interfaces_no_eth0 = lldpcli_interfaces - {'eth0'}

        # Filter intf_status_output: exclude only PortChannel interfaces (keep admin down)
        intf_status_filtered_for_lldpcli = {
            intf['interface'] for intf in intf_status_output
            if not intf['interface'].startswith('PortChannel')
        }

        missing_in_lldpcli = intf_status_filtered_for_lldpcli - lldpcli_interfaces_no_eth0
        extra_in_lldpcli = lldpcli_interfaces_no_eth0 - intf_status_filtered_for_lldpcli

        if missing_in_lldpcli:
            logger.warning("Interfaces (no PortChannels) missing in lldpcli after reload: {}".format(
                sorted(missing_in_lldpcli)))
        if extra_in_lldpcli:
            logger.warning("Interfaces in lldpcli but not in interface status after reload: {}".format(
                sorted(extra_in_lldpcli)))

        if not missing_in_lldpcli and not extra_in_lldpcli:
            logger.info("lldpcli and interface status (no PortChannels) match perfectly after reload")

        pytest_assert(intf_status_filtered_for_lldpcli == lldpcli_interfaces_no_eth0,
                      "Interface mismatch between pre-reload (no PortChannels) and lldpcli after reload. "
                      "Missing in lldpcli: {}, Extra in lldpcli: {}".format(
                          sorted(missing_in_lldpcli), sorted(extra_in_lldpcli)))

        # Verify that all interfaces from 'show interface status' that have LLDP neighbors are present
        internal_port_list = get_dpu_npu_ports_from_hwsku(duthost)
        lldpctl_facts = duthost.lldpctl_facts(
            asic_instance_id=enum_frontend_asic_index,
            skip_interface_pattern_list=["Ethernet-BP", "Ethernet-IB"] + internal_port_list
        )['ansible_facts']

        # Verify eth0 is in lldpctl_facts
        pytest_assert('eth0' in lldpctl_facts.get('lldpctl', {}),
                      "eth0 is missing from lldpctl_facts after config reload")

        # Get interfaces from lldpctl_facts (excluding eth0)
        lldpctl_facts_interfaces = set(lldpctl_facts.get('lldpctl', {}).keys()) - {'eth0'}
        logger.info("lldpctl_facts interfaces after reload (excluding eth0): {}".format(
            sorted(lldpctl_facts_interfaces)))
        logger.info("lldpctl_facts interfaces in total: {}".format(len(lldpctl_facts_interfaces)))

        # Compare intf_status_output with lldpctl_facts interfaces
        # (exclude PortChannels and admin down from intf_status)
        intf_status_filtered_for_lldpctl = {
            intf['interface'] for intf in intf_status_output
            if not intf['interface'].startswith('PortChannel') and intf['admin'].lower() == 'up'
        }

        missing_in_lldpctl_facts = intf_status_filtered_for_lldpctl - lldpctl_facts_interfaces
        extra_in_lldpctl_facts = lldpctl_facts_interfaces - intf_status_filtered_for_lldpctl

        if missing_in_lldpctl_facts:
            logger.warning("Interfaces before reload but missing in lldpctl_facts after reload: {}".format(
                sorted(missing_in_lldpctl_facts)))
        if extra_in_lldpctl_facts:
            logger.warning("Interfaces in lldpctl_facts but not before reload: {}".format(
                sorted(extra_in_lldpctl_facts)))

        if not missing_in_lldpctl_facts and not extra_in_lldpctl_facts:
            logger.info("lldpctl_facts and interface status (admin up, no PortChannels) "
                        "match perfectly after reload")

        pytest_assert(intf_status_filtered_for_lldpctl == lldpctl_facts_interfaces,
                      "Interface mismatch between pre-reload and lldpctl_facts after reload "
                      "(admin up, no PortChannels). "
                      "Missing in lldpctl_facts: {}, Extra in lldpctl_facts: {}".format(
                          sorted(missing_in_lldpctl_facts), sorted(extra_in_lldpctl_facts)))

        for interface in lldpctl_facts.get('lldpctl', {}):
            pytest_assert(interface in lldpcli_interfaces,
                          "Interface {} from lldpctl_facts is missing in lldpcli interfaces".format(interface))

        logger.info("Step 6: Verifying Chassis ID and Capabilities")
        # Get chassis information
        chassis_output = duthost.shell(
            "docker exec lldp{} lldpcli show chassis".format(
                asic.get_asic_index() if duthost.is_multi_asic else ""
            )
        )['stdout']

        logger.info("Chassis output:\n{}".format(chassis_output))

        # Verify ChassisID type is mac
        chassis_id_match = re.search(r'ChassisID:\s+mac\s+([0-9a-f:]+)', chassis_output, re.IGNORECASE)
        pytest_assert(chassis_id_match is not None,
                      "ChassisID with type 'mac' not found in chassis output")

        actual_chassis_mac = chassis_id_match.group(1).lower()
        pytest_assert(actual_chassis_mac == expected_chassis_mac,
                      "Chassis MAC mismatch. Expected: {}, Got: {}".format(
                          expected_chassis_mac, actual_chassis_mac))

        # Verify Capabilities are present with correct status
        pytest_assert(re.search(r'Capability:\s+Bridge,\s+on', chassis_output, re.IGNORECASE),
                      "Bridge capability should be 'on' in chassis output")
        pytest_assert(re.search(r'Capability:\s+Router,\s+on', chassis_output, re.IGNORECASE),
                      "Router capability should be 'on' in chassis output")
        pytest_assert(re.search(r'Capability:\s+Wlan,\s+off', chassis_output, re.IGNORECASE),
                      "Wlan capability should be 'off' in chassis output")
        pytest_assert(re.search(r'Capability:\s+Station,\s+off', chassis_output, re.IGNORECASE),
                      "Station capability should be 'off' in chassis output")

    logger.info("Test completed successfully. All LLDP checks passed after config reload.")
