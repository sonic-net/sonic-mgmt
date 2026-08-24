import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)


def skip_if_switchport_mode_unsupported(duthost):
    """Skip the test on images that predate sonic-net/sonic-utilities#3788.

    That change introduced the 'show interfaces switchport status' command and
    made the VLAN column of 'show interfaces status' reflect the configured
    switchport mode (access/trunk/routed). Without it these tests cannot pass,
    so skip cleanly instead of reporting a failure.
    """
    result = duthost.shell("show interfaces switchport status", module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.skip("'show interfaces switchport status' is not supported on this image "
                    "(requires sonic-net/sonic-utilities#3788)")


def get_switchport_mode(dut, interface):
    """
    Get switchport mode from 'show interfaces switchport status' output
    Returns the mode or None if interface not found
    """
    for row in dut.show_and_parse("show interfaces switchport status"):
        if row.get('interface') == interface:
            return row.get('mode')
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
    Create VLAN and add members.

    Membership type follows the switchport mode: access ports are added
    untagged (-u) while trunk ports are added tagged (default). This makes the
    'mode' argument actually drive the VLAN membership type.
    Returns: True if successful, False otherwise
    """
    try:
        # Create VLAN
        dut.shell(f"config vlan add {vlan_id}")

        # Add members tagged (trunk) or untagged (access) based on mode
        untagged = "-u " if mode == "access" else ""
        for member in members:
            dut.shell(f"config vlan member add {untagged}{vlan_id} {member}")

        return True
    except Exception as e:
        logger.error(f"Failed to setup VLAN {vlan_id}: {str(e)}")
        return False


def cleanup_portchannel(dut, portchannel_name, member_ports):
    """Cleanup PortChannel configuration.

    Member removals are isolated so that a single failure does not abort the
    cleanup and leak an orphan PortChannel for subsequent runs.
    """
    # Remove member ports, swallowing per-member errors so we always attempt
    # to delete the PortChannel itself afterwards.
    for port in member_ports:
        try:
            dut.shell(f"config portchannel member del {portchannel_name} {port}")
        except Exception as e:
            logger.error(f"Failed to remove {port} from {portchannel_name}: {str(e)}")

    try:
        dut.shell(f"config portchannel del {portchannel_name}")
    except Exception as e:
        logger.error(f"Failed to delete PortChannel {portchannel_name}: {str(e)}")


def cleanup_vlan(dut, vlan_id, members):
    """Cleanup VLAN configuration"""
    try:
        for member in members:
            dut.shell(f"config vlan member del {vlan_id} {member}")
        dut.shell(f"config vlan del {vlan_id}")
    except Exception as e:
        logger.error(f"Failed to cleanup VLAN {vlan_id}: {str(e)}")


def set_switchport_mode(duthost, intf, mode):
    """Set the switchport mode on intf idempotently.

    'config switchport mode <mode> <intf>' returns a non-zero rc when the
    interface is already in that mode (e.g. a routed port left at the default
    'routed' mode), so skip the command when no change is needed.
    """
    if get_switchport_mode(duthost, intf) == mode:
        logger.info(f"{intf} is already in {mode} mode; skipping switchport config")
        return
    duthost.shell(f"config switchport mode {mode} {intf}")


def restore_orig_configs(duthost, original_mode, intf):
    """Restore previous mode of interface.

    Skips restoration when the original mode is unknown (None), since
    'config switchport mode None <intf>' is an invalid command.
    """
    if original_mode is None:
        logger.info(f"No original switchport mode captured for {intf}; skipping restore")
        return
    logger.info(f"Restoring original interface:{intf} mode:{original_mode}")
    set_switchport_mode(duthost, intf, original_mode)


def get_available_ports(duthost, tbinfo, num_of_ports=1):
    """Find num_of_ports available i.e not part of any vlan or portchannel.
    When num_of_ports > 1, returns ports with the same speed so they can be
    added to a PortChannel together.
    """
    available_ports = []
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    intfList = mg_facts['minigraph_port_name_to_alias_map'].keys()

    vlanDict = mg_facts['minigraph_vlans']

    poDict = mg_facts['minigraph_portchannels']

    for intf in intfList:
        in_vlan = any(intf in vlanData['members'] for vlanData in vlanDict.values())
        in_portchannel = any(intf in poData['members'] for poData in poDict.values())
        if not in_vlan and not in_portchannel:
            available_ports.append(intf)

    if num_of_ports <= 1:
        return available_ports[:num_of_ports]

    intf_status = {x.get('interface'): x for x in duthost.show_and_parse('show interfaces status')}

    speed_groups = {}
    for port in available_ports:
        speed = intf_status.get(port, {}).get('speed', 'N/A')
        speed_groups.setdefault(speed, []).append(port)

    for speed, ports in sorted(speed_groups.items(), key=lambda x: len(x[1]), reverse=True):
        if len(ports) >= num_of_ports:
            logger.info(f"Selected {num_of_ports} ports with matching speed {speed}: {ports[:num_of_ports]}")
            return ports[:num_of_ports]

    logger.warning(f"Could not find {num_of_ports} available ports with the same speed")
    return available_ports[:num_of_ports]


def get_free_lag_intf(duthost):
    """Create a portchannel interface from available idx"""
    portchannels = list(duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts'].get('PORTCHANNEL', {}).keys())

    for portchannel_idx in range(1, 10000):  # Max len of portchannel index can be '9999'
        lag_port = 'PortChannel{}'.format(portchannel_idx)

        if lag_port not in portchannels:
            return lag_port

    return None


def configure_and_verify_switchport_mode(duthost, intf, mode, vlan):
    """Configure the switchport mode (and optional VLAN membership) on intf and
    verify it is reflected by both 'show interfaces switchport status' and the
    VLAN column of 'show interfaces status'.

    Shared by the Ethernet and PortChannel tests to avoid duplicating the
    configure/verify body.
    """
    set_switchport_mode(duthost, intf, mode)

    if vlan:
        pytest_assert(setup_vlan_and_members(duthost, mode, vlan, [intf]),
                      f"Failed to setup VLAN {vlan}")

    intf_mode = get_switchport_mode(duthost, intf)
    pytest_assert(intf_mode == mode,
                  f"Interface {intf} shows mode {intf_mode} instead of {mode}")

    out = duthost.show_and_parse("show interfaces status {}".format(intf))
    pytest_assert(out and out[0].get('vlan') == mode,
                  f"Interface {intf} shows mode {out[0].get('vlan') if out else None} instead of {mode}")


@pytest.mark.parametrize("mode, vlan", [("access", None), ("trunk", "10"), ("routed", None)])
def test_ethernet_switchport_mode(duthosts, rand_one_dut_hostname, tbinfo, mode, vlan):
    """
    Test switchport mode configuration for Ethernet Interfaces with VLAN membership
    """
    duthost = duthosts[rand_one_dut_hostname]
    skip_if_switchport_mode_unsupported(duthost)

    # Fetch ports which are not part of vlan or portchannel
    intfList = get_available_ports(duthost, tbinfo)
    pytest_assert(len(intfList) != 0, "There are no available ports")

    intf = intfList[0]
    original_mode = get_switchport_mode(duthost, intf)

    logger.info(f"Testing {intf} with mode {mode}")

    try:
        configure_and_verify_switchport_mode(duthost, intf, mode, vlan)
    finally:
        # Cleanup
        if vlan:
            cleanup_vlan(duthost, vlan, [intf])
        restore_orig_configs(duthost, original_mode, intf)


@pytest.mark.parametrize("mode, vlan", [("access", None), ("trunk", "10"), ("routed", None)])
def test_portchannel_switchport_mode(duthosts, rand_one_dut_hostname, tbinfo, mode, vlan):
    """
    Test switchport mode configuration for PortChannels with VLAN membership
    """
    duthost = duthosts[rand_one_dut_hostname]
    skip_if_switchport_mode_unsupported(duthost)

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

        configure_and_verify_switchport_mode(duthost, portchannel, mode, vlan)
    finally:
        # Cleanup
        if vlan:
            cleanup_vlan(duthost, vlan, [portchannel])
        cleanup_portchannel(duthost, portchannel, members)
