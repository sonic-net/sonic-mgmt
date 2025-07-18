import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

# Use original ports intead of sub interfaces for ptfadapter if it's t0-backend
PTF_PORT_MAPPING_MODE = "use_orig_interface"


def get_interface_status(dut, interface):
    """
    Get interface status from 'show interfaces status' output
    """
    command = f"show interfaces status | grep {interface}"
    output = dut.shell(command)
    return output['stdout']


def get_switchport_mode(dut, interface):
    """
    Get switchport mode from 'show interfaces switchport status' output
    Returns the mode or None if interface not found
    """
    command = f"show interfaces switchport status | grep -w {interface}"
    output = dut.shell(command)
    if output['rc'] == 0 and output['stdout'].strip():
        return output['stdout'].split()[-1]  # Get the last column (Mode)
    return None


def setup_portchannel(dut, portchannel_name, member_ports):
    """
    Create PortChannel and add member ports
    Returns: True if successful, False otherwise
    """
    try:
        # Create PortChannel
        dut.shell(f"config portchannel add {portchannel_name}")

        # Add member ports
        for port in member_ports:
            dut.shell(f"config portchannel member add {portchannel_name} {port}")

        return True
    except Exception as e:
        logger.error(f"Failed to setup PortChannel {portchannel_name}: {str(e)}")
        return False


def setup_vlan_and_members(dut, mode, vlan_id, members):
    """
    Create VLAN and add members
    Returns: True if successful, False otherwise
    """
    try:
        # Create VLAN
        dut.shell(f"config vlan add {vlan_id}")

        # Add members
        for member in members:
            dut.shell(f"config vlan member add {vlan_id} {member}")

        return True
    except Exception as e:
        logger.error(f"Failed to setup VLAN {vlan_id}: {str(e)}")
        return False


def cleanup_portchannel(dut, portchannel_name, member_ports):
    """Cleanup PortChannel configuration"""
    try:
        # Remove member ports
        for port in member_ports:
            dut.shell(f"config portchannel member del {portchannel_name} {port}")

        dut.shell(f"config portchannel del {portchannel_name}")
    except Exception as e:
        logger.error(f"Failed to cleanup PortChannel {portchannel_name}: {str(e)}")


def cleanup_vlan(dut, vlan_id, members):
    """Cleanup VLAN configuration"""
    try:
        for member in members:
            dut.shell(f"config vlan member del {vlan_id} {member}")
        dut.shell(f"config vlan del {vlan_id}")
    except Exception as e:
        logger.error(f"Failed to cleanup VLAN {vlan_id}: {str(e)}")


def restore_orig_configs(duthost, original_mode, intf):
    """Restore previous mode of interface"""
    logger.info(f"Restoring original interface:{intf} mode:{original_mode}")
    duthost.shell("config switchport mode {} {}".format(original_mode, intf))


def get_available_ports(duthost, tbinfo, num_of_ports=1):
    """Find num_of_ports available i.e not part of any vlan or portchannel"""
    available_ports = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    intfList = mg_facts['minigraph_port_name_to_alias_map'].keys()

    vlanDict = mg_facts['minigraph_vlans']

    poDict = mg_facts['minigraph_portchannels']

    found_intf = None
    for intf in intfList:
        for vlan, vlanData in vlanDict.items():
            if intf not in vlanData['members']:
                found_intf = intf
            else:
                found_intf = None
        if found_intf:
            for po, poData in poDict.items():
                if found_intf in poData['members']:
                    found_intf = None
        if found_intf and len(available_ports) < num_of_ports:
            available_ports.append(found_intf)

    return available_ports


def get_free_lag_intf(duthost):
    """Create a portchannel interface from available idx"""
    portchannels = list(duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts'].get('PORTCHANNEL', {}).keys())

    for portchannel_idx in range(1, 10000):  # Max len of portchannel index can be '9999'
        lag_port = 'PortChannel{}'.format(portchannel_idx)

        if lag_port not in portchannels:
            return lag_port

    return None


@pytest.mark.parametrize("mode, vlan", [("access", None), ("trunk", "10"), ("routed", None)])
def test_ethernet_switchport_mode(duthosts, rand_one_dut_hostname, tbinfo, mode, vlan):
    """
    Test switchport mode configuration for Ethernet Interfaces with VLAN membership
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Fetch ports which are not part of vlan or portchannel
    intfList = get_available_ports(duthost, tbinfo)
    pytest_assert(len(intfList) != 0, "There are no available ports")

    intf = intfList[0]
    original_mode = get_switchport_mode(duthost, intf)

    logger.info(f"Testing {intf} with mode {mode}")

    try:
        # Configure switchport mode if vlan
        if mode != original_mode:
            duthost.shell(f"config switchport mode {mode} {intf}")

        # Setup VLAN and add members if needed
        if vlan:
            pytest_assert(setup_vlan_and_members(duthost, mode, vlan, [intf]),
                          f"Failed to setup VLAN {vlan}")

        # Verify Interface switchport mode
        intf_mode = get_switchport_mode(duthost, intf)
        pytest_assert(intf_mode == mode,
                      f"Interface {intf} shows mode {intf_mode} instead of {mode}")

        # Verify from Interface status
        out = duthost.show_and_parse("show interfaces status {}".format(intf))
        pytest_assert(out[0]['vlan'] == mode,
                      f"Interface {intf} shows mode {out[0]['vlan']} instead of {mode}")
    finally:
        # Cleanup
        if vlan:
            cleanup_vlan(duthost, vlan, [intf])
        if mode != original_mode:
            restore_orig_configs(duthost, original_mode, intf)


@pytest.mark.parametrize("mode, vlan", [("access", None), ("trunk", "10"), ("routed", None)])
def test_portchannel_switchport_mode(duthosts, rand_one_dut_hostname, tbinfo, mode, vlan):
    """
    Test switchport mode configuration for PortChannels with VLAN membership
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Fetch free portchannel index
    portchannel = get_free_lag_intf(duthost)
    pytest_assert(portchannel is not None, "Free portchannel idx is NOT found!!")

    # Fetch ports which are not part of vlan or portchannel
    num_of_members = 2
    members = get_available_ports(duthost, tbinfo, num_of_members)
    pytest_assert(len(members) == num_of_members,
                  f"There are no available ports, requested:{num_of_members}, available:{len(members)}")

    logger.info(f"Testing {portchannel} with mode {mode}")

    try:
        # Setup PortChannel
        pytest_assert(setup_portchannel(duthost, portchannel, members),
                      f"Failed to setup {portchannel}")

        # Configure switchport mode
        duthost.shell(f"config switchport mode {mode} {portchannel}")

        # Setup VLAN and add members if needed
        if vlan:
            pytest_assert(setup_vlan_and_members(duthost, mode, vlan, [portchannel]),
                          f"Failed to setup VLAN {vlan}")

        # Verify PortChannel mode
        po_mode = get_switchport_mode(duthost, portchannel)
        pytest_assert(po_mode == mode,
                      f"PortChannel {portchannel} shows mode {po_mode} instead of {mode}")

        # Verify from Interface status
        out = duthost.show_and_parse("show interfaces status {}".format(portchannel))
        pytest_assert(out[0]['vlan'] == mode,
                      f"Interface {portchannel} shows mode {out[0]['vlan']} instead of {mode}")

    finally:
        # Cleanup
        if vlan:
            cleanup_vlan(duthost, vlan, [portchannel])
        cleanup_portchannel(duthost, portchannel, members)
