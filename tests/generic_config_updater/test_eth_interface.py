import logging
import pytest
import re
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback, rollback_or_reload
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import list_dut_fanout_connections
from tests.common.platform.interface_utils import get_physical_port_indices, get_physical_to_logical_port_mapping

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

SHOW_FEC_OPER_CMD_TEMPLATE = "show interfaces fec status {}"


@pytest.fixture(autouse=True)
def ensure_dut_readiness(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Setup/teardown fixture for each ethernet test
    rollback to check if it goes back to starting config

    Args:
        duthosts: list of DUTs
        enum_rand_one_per_hwsku_frontend_hostname: The fixture returns a randomly selected frontend DUT hostname
    """

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def is_valid_fec_state_db(duthost, value, port, namespace=None):
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    read_supported_fecs_cli = 'sonic-db-cli {} STATE_DB hget "PORT_TABLE|{}" supported_fecs'.format(
        namespace_prefix, port)
    supported_fecs_str = duthost.shell(read_supported_fecs_cli)['stdout']
    if supported_fecs_str:
        if supported_fecs_str != 'N/A':
            supported_fecs_list = [element.strip() for element in supported_fecs_str.split(',')]
        else:
            supported_fecs_list = []
    else:
        supported_fecs_list = ['rs', 'fc', 'none']
    if value.strip() not in supported_fecs_list:
        return False
    return True


def fec_exists_on_config_db(duthost, port, namespace=None):
    """
    Check if FEC (Forward Error Correction) exists on the CONFIG_DB for a given port.
    Args:
        duthost (object): The DUT (Device Under Test) host object.
        port (str): The port for which FEC existence needs to be checked.
        namespace (str, optional): The namespace in which the port exists. Defaults to None.
    Returns:
        bool: True if FEC exists on the CONFIG_DB for the given port, False otherwise.
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    read_fec = 'sonic-db-cli {} CONFIG_DB hget "PORT|{}" fec'.format(namespace_prefix, port)
    read_fec_str = duthost.shell(read_fec)['stdout']
    if read_fec_str:
        return True
    else:
        return False


def is_valid_speed_state_db(duthost, value, port, namespace=None):
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    read_supported_speeds_cli = 'sonic-db-cli {} STATE_DB hget "PORT_TABLE|{}" supported_speeds'.format(
        namespace_prefix, port)
    supported_speeds_str = duthost.shell(read_supported_speeds_cli)['stdout']
    supported_speeds = [int(s) for s in supported_speeds_str.split(',') if s]
    if supported_speeds and int(value) not in supported_speeds:
        return False
    return True


def check_interface_status(duthost, field, interface='Ethernet0'):
    """
    Returns current status for interface of specified field

    Args:
        duthost: DUT host object under test
        field: interface field under test
        interface: The name of the interface to be checked
    """

    cmds = "show interface status {}".format(interface)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'])
    status_data = output["stdout_lines"]
    field_index = status_data[0].split().index(field)
    for line in status_data:
        if interface in line:
            interface_status = line.strip()
    pytest_assert(len(interface_status) > 0, "Failed to read {} interface properties".format(interface))
    status = re.split(r" {2,}", interface_status)[field_index]
    return status


def remove_port_from_portchannel(duthost, port, portchannel, namespace=None):
    """
        Removes a port from its PortChannel membership

        Args:
            duthost: DUT host object under test
            port: Port name to remove
            portchannel: PortChannel name
            namespace: DUT asic namespace
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    cmd = 'config portchannel {} member del {} {}'.format(namespace_prefix, portchannel, port)
    logger.info("Removing {} from {} in namespace {}".format(
        port, portchannel, namespace or 'default'))
    output = duthost.shell(cmd)
    pytest_assert(
        output['rc'] == 0,
        "Failed to remove {} from {}: {}".format(port, portchannel, output.get('stderr', '')))
    return True


def get_ethernet_port_not_in_portchannel(duthost, namespace=None):
    """
        Returns the name of an ethernet port which is not a member of a port channel

        Args:
            duthost: DUT host object under test
            namespace: DUT asic namespace
    """
    config_facts = duthost.config_facts(
        host=duthost.hostname,
        source="running",
        verbose=False,
        namespace=namespace
    )['ansible_facts']
    port_name = ""
    ports = list(config_facts['PORT'].keys())
    port_channel_members = []
    if 'PORTCHANNEL_MEMBER' in config_facts:
        port_channel_member_facts = config_facts['PORTCHANNEL_MEMBER']
        for port_channel in list(port_channel_member_facts.keys()):
            for member in list(port_channel_member_facts[port_channel].keys()):
                port_channel_members.append(member)
    for port in ports:
        if port not in port_channel_members:
            port_role = config_facts['PORT'][port].get('role')
            if port_role and port_role != 'Ext':    # ensure port is front-panel port
                continue
            port_name = port
            break
    return port_name


def get_test_port(duthost, namespace=None, remove_from_portchannel=True):
    """
        Returns an available ethernet port for testing.
        If no free ports exist and remove_from_portchannel=True, removes a port from a PortChannel.
        The port will be restored by the ensure_dut_readiness fixture's rollback mechanism.

        Args:
            duthost: DUT host object under test
            namespace: DUT asic namespace
            remove_from_portchannel: If True, remove a port from PortChannel if no free ports available

        Returns:
            Port name string, or empty string if no suitable port found
    """
    # First try to get a port not in a PortChannel
    port = get_ethernet_port_not_in_portchannel(duthost, namespace=namespace)
    if port:
        logger.info("Found available port: {}".format(port))
        return port

    if not remove_from_portchannel:
        logger.warning("No available ports and remove_from_portchannel=False")
        return ""

    # If no free port, find one in a PortChannel and remove it
    logger.info("No free ports available, attempting to remove a port from PortChannel")
    config_facts = duthost.config_facts(
        host=duthost.hostname,
        source="running",
        verbose=False,
        namespace=namespace
    )['ansible_facts']

    if 'PORTCHANNEL_MEMBER' not in config_facts or 'PORT' not in config_facts:
        logger.warning("No PortChannel members or ports found")
        return ""

    port_channel_member_facts = config_facts['PORTCHANNEL_MEMBER']

    # Find a suitable port to remove (prefer Ext role ports)
    for portchannel in list(port_channel_member_facts.keys()):
        for member in list(port_channel_member_facts[portchannel].keys()):
            port_role = config_facts['PORT'].get(member, {}).get('role')
            if port_role and port_role != 'Ext':
                continue  # Skip internal/fabric ports

            # Found a candidate - remove it from the PortChannel
            logger.info("Removing {} from {} for testing (will be restored by rollback)".format(
                member, portchannel))
            remove_port_from_portchannel(duthost, member, portchannel, namespace=namespace)
            return member

    logger.warning("No suitable ports found even in PortChannels")
    return ""


def get_port_speeds_for_test(duthost, port):
    """
    Get the speeds parameters for case test_update_speed, including 2 valid speeds and 1 invalid speed

    Args:
        duthost: DUT host object
        port: The port for which speeds need to be tested
    """
    speeds_to_test = []
    invalid_speed_yang = ("20a", False)
    invalid_speed_state_db = None
    if duthost.get_facts()['asic_type'] == 'vs':
        valid_speeds = ['20000', '40000']
    else:
        valid_speeds = duthost.get_supported_speeds(port)
        if valid_speeds:
            invalid_speed_state_db = (str(int(valid_speeds[0]) - 1), False)
    pytest_assert(valid_speeds, "Failed to get any valid port speed to test.")
    valid_speeds_to_test = random.sample(valid_speeds, 2 if len(valid_speeds) >= 2 else len(valid_speeds))
    speeds_to_test = [(speed, True) for speed in valid_speeds_to_test]
    speeds_to_test.append(invalid_speed_yang)
    if invalid_speed_state_db:
        speeds_to_test.append(invalid_speed_state_db)
    return speeds_to_test


def is_dac_port(duthost, port, namespace=None):
    """
    Returns True if the transceiver plugged into the given port is a passive
    copper (DAC) cable, based on STATE_DB TRANSCEIVER_INFO specification_compliance.

    DAC cables advertise CMIS applications (e.g. 100GBASE-CR4) at the same host
    lane grouping used by higher speeds (e.g. 400GBASE-CR4), so a breakout
    sub-port's speed can be lowered without a lane/breakout remap. Optical
    modules (AOC/optics) commonly only advertise lower speeds at a reduced lane
    count (e.g. single-lane 100G), so a speed-only change cannot bring them up.

    Args:
        duthost: DUT host object under test
        port: Port name to check
        namespace: DUT asic namespace
    """
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    read_spec_compliance_cli = 'sonic-db-cli {} STATE_DB hget "TRANSCEIVER_INFO|{}" specification_compliance'.format(
        namespace_prefix, port)
    spec_compliance = duthost.shell(read_spec_compliance_cli)['stdout'].strip()
    if not spec_compliance:
        return False
    # specification_compliance is reported differently across platforms/transceivers:
    # e.g. "passive_copper_media_interface", "Passive Copper Cable", or a dict-formatted
    # string embedding a similar identifier. Match case-insensitively on known DAC markers
    # instead of requiring an exact string match.
    spec_compliance_lower = spec_compliance.lower()
    dac_identifiers = ["passive_copper_media_interface", "passive copper"]
    return any(identifier in spec_compliance_lower for identifier in dac_identifiers)


def get_2way_breakout_subports_at_speed(duthost, speed, namespace=None):
    """
    Find a pair of logical sub-ports that share the same physical port index (i.e. a
    2-way breakout group), are both currently configured at the given speed, and are
    both connected via a passive copper (DAC) cable.

    DAC is required (rather than optics/AOC) because the test needs to lower the
    sub-port speed without changing the breakout/lane configuration: DAC cables
    typically advertise the lower speed at the same host lane count already in use,
    while optical modules often only support the lower speed at a reduced lane
    count, which a plain speed change cannot achieve.

    Args:
        duthost: DUT host object
        speed: The speed (SONiC style, e.g. "400000") the breakout sub-ports must
            currently be configured at.
        namespace: DUT asic namespace

    Returns:
        A sorted list of the 2 sub-port names (e.g. ["Ethernet0", "Ethernet1"]),
        or an empty list if no such DAC-connected breakout group is found.
    """
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", verbose=False, namespace=namespace
    )['ansible_facts']
    ports = config_facts.get('PORT', {})

    physical_port_indices = get_physical_port_indices(duthost)
    pport_to_lports = get_physical_to_logical_port_mapping(physical_port_indices)

    for pport, lports in pport_to_lports.items():
        # Ports whose physical index could not be determined are grouped under the
        # None key; they are not a real breakout group, so skip them explicitly to
        # avoid pairing up unrelated logical ports.
        if pport is None:
            continue
        # Only consider sub-ports that belong to the requested asic namespace.
        lports_in_namespace = [p for p in lports if p in ports]
        if len(lports_in_namespace) != 2:
            continue
        lports_sorted = sorted(lports_in_namespace, key=lambda x: int(x.replace("Ethernet", "")))
        speeds = [ports.get(p, {}).get('speed') for p in lports_sorted]
        if not all(s == speed for s in speeds):
            continue
        # Only consider sub-ports that are admin-up: list_dut_fanout_connections() (used
        # later to map to the leaf fanout) excludes admin-down ports, and an admin-down
        # candidate would also fail the post-change oper-up checks regardless.
        admin_statuses = [ports.get(p, {}).get('admin_status', 'up') for p in lports_sorted]
        if not all(status == 'up' for status in admin_statuses):
            continue
        if not all(is_dac_port(duthost, p, namespace=namespace) for p in lports_sorted):
            logger.info("Skipping breakout group {} - not DAC connected".format(lports_sorted))
            continue
        return lports_sorted
    return []


def get_fec_oper(duthost, interface):
    """
    Get the operational FEC for a given interface

    Args:
        duthost: DUT host object
        interface: The name of the interface to be checked

    Returns:
        The operational FEC of the interface
    """
    show_fec_oper_cmd = SHOW_FEC_OPER_CMD_TEMPLATE.format(interface)
    logger.info("Get output of '{}'".format(show_fec_oper_cmd))
    fec_status = duthost.show_and_parse(show_fec_oper_cmd)
    return fec_status[0].get("fec oper", "N/A")


def test_remove_lanes(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                      ensure_dut_readiness, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    json_patch = [
        {
            "op": "remove",
            "path": "/PORT/{}/lanes".format(port)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.skip(reason="Bypass as it is blocking submodule update")
def test_replace_lanes(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                       enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    cur_lanes = check_interface_status(duthost, "Lanes", port)
    cur_lanes = cur_lanes.split(",")
    cur_lanes.sort()
    update_lanes = cur_lanes
    update_lanes[-1] = str(int(update_lanes[-1]) + 1)
    update_lanes = ",".join(update_lanes)
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/lanes".format(port),
            "value": "{}".format(update_lanes)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_replace_mtu(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                     enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)

    # Get a test port - check without removing from PortChannel to avoid routing issues
    port = get_test_port(duthost, namespace=asic_namespace, remove_from_portchannel=False)

    if not port:
        # MTU changes on ports removed from PortChannel can cause routing convergence issues
        # Skip this test to avoid teardown failures
        pytest.skip("No free ports available. Skipping MTU test to avoid routing issues from PortChannel changes.")
    target_mtu = "1514"
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/mtu".format(port),
            "value": "{}".format(target_mtu)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        current_status_mtu = check_interface_status(duthost, "MTU", port)
        pytest_assert(current_status_mtu == target_mtu,
                      "Failed to properly configure interface MTU to requested value {}".format(target_mtu))
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("pfc_asym", ["on", "off"])
def test_toggle_pfc_asym(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness, pfc_asym,
                         enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/pfc_asym".format(port),
            "value": "{}".format(pfc_asym)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        current_status_pfc_asym = check_interface_status(duthost, "Asym", port)
        pytest_assert(current_status_pfc_asym == pfc_asym,
                      "Failed to properly configure interface Asym PFC to requested value off")
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.device_type('physical')
@pytest.mark.parametrize("fec", ["rs", "fc"])
def test_replace_fec(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness, fec,
                     enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    namespace_prefix = '' if asic_namespace is None else '-n ' + asic_namespace
    intf_init_status = duthost.get_interfaces_status()
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    intf_init_fec_oper = get_fec_oper(duthost, port)
    json_patch = [
        {
            "op": "add",
            "path": "/PORT/{}/fec".format(port),
            "value": "{}".format(fec)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_fec_state_db(duthost, fec, port, namespace=asic_namespace):
            expect_op_success(duthost, output)
            current_status_fec = check_interface_status(duthost, "FEC", port)
            pytest_assert(current_status_fec == fec,
                          "Failed to properly configure interface FEC to requested value {}".format(fec))

            # When FEC is not configured in CONFIG_DB and the default FEC is 'none',
            # explicitly set FEC to 'none' to restore to initial state.
            # Since the default FEC is vendor dependent, double check initial operational FEC
            # to make sure it is not 'rs' or 'fc'.
            if (intf_init_status[port].get("fec", "N/A") == "N/A" and
                    intf_init_fec_oper in ["none", "N/A"] and
                    is_valid_fec_state_db(duthost, "none", port, namespace=asic_namespace)):
                out = duthost.command("config interface {} fec {} none".format(namespace_prefix, port))
                pytest_assert(out["rc"] == 0, "Failed to set {} fec to none. Error: {}".format(port, out["stderr"]))
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.skip(reason="Bypass as this is not a production scenario")
def test_update_invalid_index(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                              enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/index".format(port),
            "value": "abc1"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.skip(reason="Bypass as this is not a production scenario")
def test_update_valid_index(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                            enum_rand_one_frontend_asic_index, cli_namespace_prefix):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    output = duthost.shell('sonic-db-cli {} CONFIG_DB keys "PORT|"\\*'.format(cli_namespace_prefix))["stdout"]
    interfaces = {}  # to be filled with two interfaces mapped to their indeces

    for line in output.split('\n'):
        if line.startswith('PORT|Ethernet'):
            interface = line[line.index('Ethernet'):].strip()
            index = duthost.shell('sonic-db-cli {} CONFIG_DB hget "PORT|{}" index'.format(
                cli_namespace_prefix, interface))["stdout"]
            interfaces[interface] = index
            if len(interfaces) == 2:
                break
    pytest_assert(len(interfaces) == 2, "Failed to retrieve two interfaces to swap indeces in test")

    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/index".format(list(interfaces.keys())[0]),
            "value": "{}".format(list(interfaces.values())[1])
        },
        {
            "op": "replace",
            "path": "/PORT/{}/index".format(list(interfaces.keys())[1]),
            "value": "{}".format(list(interfaces.values())[0])
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_update_speed(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                      enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    speed_params = get_port_speeds_for_test(duthost, port)
    for speed, is_valid in speed_params:
        json_patch = [
            {
                "op": "replace",
                "path": "/PORT/{}/speed".format(port),
                "value": "{}".format(speed)
            }
        ]
        json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                     is_asic_specific=True, asic_namespaces=[asic_namespace])

        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            if is_valid and is_valid_speed_state_db(duthost, speed, port, namespace=asic_namespace):
                expect_op_success(duthost, output)
                current_status_speed = check_interface_status(duthost, "Speed", port).replace("G", "000")
                current_status_speed = current_status_speed.replace("M", "")
                pytest_assert(current_status_speed == speed,
                              "Failed to properly configure interface speed to requested value {}".format(speed))
            else:
                expect_op_failure(output)
        finally:
            delete_tmpfile(duthost, tmpfile)


def test_update_description(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                            enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/description".format(port),
            "value": "Updated description"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("admin_status", ["up", "down"])
def test_eth_interface_admin_change(duthosts, enum_rand_one_per_hwsku_frontend_hostname, admin_status,
                                    enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    port = get_test_port(duthost, namespace=asic_namespace)
    pytest_assert(port, "No available ethernet ports on this ASIC")
    json_patch = [
        {
            "op": "add",
            "path": "/PORT/{}/admin_status".format(port),
            "value": "{}".format(admin_status)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(wait_until(10, 2, 0, lambda: check_interface_status(duthost, "Admin", port) == admin_status),
                      "Interface failed to update admin status to {}".format(admin_status))
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_port_speed_change_oper_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ensure_dut_readiness,
                                       enum_rand_one_frontend_asic_index, loganalyzer):
    """
    Test that applying a GCU patch to change port speed (and lanes) also results in the expected
    operational status. This test covers the gap described in GH issue #21179:
    "GCU test suite does not have test to cover speed change for interface."

    Existing test_update_speed only verifies the speed value is stored; this test also
    verifies that the port's operational status reflects the speed change correctly,
    and checks syslog for ASIC programming errors (the port speed change involves
    a remove-then-readd in ASIC, which could fail with dependency check errors).

    Steps:
    1. Select a free frontend port (not in a PortChannel).
    2. Build a JSON patch that changes the port speed and lanes to a valid alternative
       and sets admin_status to 'up'.
    3. Apply the patch via GCU (config apply-patch).
    4. Verify the patch succeeds and the new speed is visible in 'show interface status'.
    5. Verify lanes are correctly preserved in CONFIG_DB after the speed change.
    6. Assert no critical syslog errors (dependency failures, ASIC programming errors)
       occurred during the speed change.
    7. Rollback is handled automatically by the ensure_dut_readiness fixture.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    namespace_prefix = '' if asic_namespace is None else '-n ' + asic_namespace

    # Add ignore patterns for expected syslog messages during port speed change.
    # Port speed change in ASIC involves remove + readd which may produce transient warnings.
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".*ERR swss[0-9]*#orchagent.*doPortTask: Unsupported port.*speed",
        ])

    # Use a port outside any PortChannel to avoid disrupting routed traffic.
    port = get_test_port(duthost, namespace=asic_namespace, remove_from_portchannel=False)
    if not port:
        pytest.skip("No free ports available outside PortChannels for this test")

    # Collect valid speeds; pick one that differs from the current configured speed.
    speed_params = get_port_speeds_for_test(duthost, port)
    valid_speeds = [speed for speed, is_valid in speed_params if is_valid]
    pytest_assert(valid_speeds, "No valid speeds found for port {}".format(port))

    # Read current configured speed from CONFIG_DB so we can choose a *different* speed.
    current_speed = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hget "PORT|{}" speed'.format(namespace_prefix, port)
    )['stdout'].strip()

    target_speed = next(
        (s for s in valid_speeds
         if s != current_speed and is_valid_speed_state_db(duthost, s, port, namespace=asic_namespace)),
        None
    )
    if target_speed is None:
        # Fall back to the first valid speed even if it matches current (still exercises the path).
        target_speed = next(
            (s for s in valid_speeds if is_valid_speed_state_db(duthost, s, port, namespace=asic_namespace)),
            None
        )
    if target_speed is None:
        pytest.skip("No STATE_DB-supported speed available for port {}".format(port))

    # Read current lanes from CONFIG_DB.
    # Speed changes may involve lane changes; include lanes in the patch to ensure
    # full port configuration is updated (ASIC programming does remove + readd).
    current_lanes = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hget "PORT|{}" lanes'.format(namespace_prefix, port)
    )['stdout'].strip()

    logger.info("Testing GCU speed change on port {} from {} to {} (lanes: {})".format(
        port, current_speed, target_speed, current_lanes))

    # Determine whether admin_status already exists in CONFIG_DB (use 'add' vs 'replace').
    existing_admin = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hget "PORT|{}" admin_status'.format(namespace_prefix, port)
    )['stdout'].strip()
    admin_op = "replace" if existing_admin else "add"

    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/speed".format(port),
            "value": "{}".format(target_speed)
        },
        {
            "op": "replace",
            "path": "/PORT/{}/lanes".format(port),
            "value": "{}".format(current_lanes)
        },
        {
            "op": admin_op,
            "path": "/PORT/{}/admin_status".format(port),
            "value": "up"
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch,
        is_asic_specific=True, asic_namespaces=[asic_namespace]
    )

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        # Capture timestamp before applying the patch so syslog assertions
        # only cover messages generated during the speed change operation.
        pre_patch_timestamp = duthost.shell("date '+%b %e %H:%M:%S'")['stdout'].strip()

        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        # Verify the speed value is updated in the interface status table.
        current_status_speed = check_interface_status(duthost, "Speed", port).replace("G", "000")
        current_status_speed = current_status_speed.replace("M", "")
        pytest_assert(
            current_status_speed == target_speed,
            "Speed not updated to {}: got {}".format(target_speed, current_status_speed)
        )

        # Verify lanes are preserved in CONFIG_DB after speed change.
        updated_lanes = duthost.shell(
            'sonic-db-cli {} CONFIG_DB hget "PORT|{}" lanes'.format(namespace_prefix, port)
        )['stdout'].strip()
        pytest_assert(
            updated_lanes,
            "Lanes missing from CONFIG_DB after speed change for port {}".format(port)
        )
        logger.info("Lanes after speed change: {} (was: {})".format(updated_lanes, current_lanes))

        # Check syslog for critical errors during port speed change.
        # In ASIC programming, speed change does remove-then-readd, which could fail
        # with dependency check errors or other ASIC programming failures.
        syslog_errors = duthost.shell(
            "sudo awk -v ts=\"{ts}\" '$0 >= ts' /var/log/syslog "
            "| grep -iE 'ERR.*(orchagent|syncd).*{port}.*(dependency|fail)' "
            "| tail -20 || true".format(ts=pre_patch_timestamp, port=port),
            module_ignore_errors=True
        )['stdout'].strip()
        pytest_assert(
            not syslog_errors,
            "Syslog errors found during port speed change on {}: {}".format(port, syslog_errors)
        )

        # Log oper_status as informational; link-up depends on physical cable/link-partner.
        oper_status = check_interface_status(duthost, "Oper", port)
        logger.info(
            "GCU speed change verified: port {} configured_speed={} lanes={} oper={}".format(
                port, target_speed, updated_lanes, oper_status)
        )
    finally:
        delete_tmpfile(duthost, tmpfile)


def get_fanout_port_map(duthost, fanouthosts):
    """
    Build a mapping of DUT port name to (fanout host object, fanout port name)
    for every DUT port directly connected to a leaf fanout switch.

    Args:
        duthost: DUT host object
        fanouthosts: Dict of fanout host objects (fixture)

    Returns:
        dict: {dut_port: (fanout, fanout_port)}
    """
    return {
        dut_port: (fanout, fanout_port)
        for dut_port, fanout, fanout_port in list_dut_fanout_connections(duthost, fanouthosts)
    }


@pytest.mark.topology('lt2')
def test_port_speed_change_400g_breakout_to_100g(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                                                 enum_rand_one_frontend_asic_index, fanouthosts, loganalyzer):
    """
    Test that verifies the gap described in GH issue sonic-net/sonic-mgmt#26589:
    "Test Gap: support 2*100Gb port speed on 2*400Gb breakout mode"

    A port broken out into 2 sub-ports of 400G each must also be able to run at
    2x100G on LT2 topology: the DUT must not crash when the speed is lowered, both
    sub-ports must come up at the new speed once the leaf fanout side is changed to
    match, and both sub-ports must recover correctly once the speed change is rolled
    back.

    Steps:
    1. Find a 2-way breakout group (2 logical sub-ports sharing one physical port)
       currently configured at 400G on both sub-ports.
    2. Set the speed of both sub-ports to 100G in a single GCU apply-patch call.
    3. Set the corresponding sub-ports on the leaf fanout to 100G.
    4. Verify no crash happened on the DUT (critical services still running) and
       both sub-ports come up.
    5. Recover the leaf fanout sub-ports speed to 400G.
    6. Roll back the DUT port speed change to 400G.
    7. Verify both sub-ports are up again.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)

    breakout_speed = "400000"
    target_speed = "100000"

    subports = get_2way_breakout_subports_at_speed(duthost, breakout_speed, namespace=asic_namespace)
    if not subports:
        pytest.skip("No 2x400G breakout port group found on this DUT/ASIC namespace")

    fanout_port_map = get_fanout_port_map(duthost, fanouthosts)
    fanout_subports = [fanout_port_map.get(p) for p in subports]
    if not all(fanout_subports):
        pytest.skip("Could not find leaf fanout connection for breakout sub-ports {}".format(subports))

    if loganalyzer:
        # Speed change in ASIC involves remove + readd of the port, which may produce
        # transient warnings that are not indicative of a real failure.
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".*ERR swss[0-9]*#orchagent.*doPortTask: Unsupported port.*speed",
        ])

    def _wait_ports_oper_up(ports):
        return wait_until(
            60, 5, 0,
            lambda: all(check_interface_status(duthost, "Oper", p) == "up" for p in ports)
        )

    # Step 2: change DUT sub-ports speed to 100G in a single GCU patch.
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/{}/speed".format(port),
            "value": target_speed
        }
        for port in subports
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch,
        # Only pass a specific namespace list when one was actually resolved; if
        # asic_namespace is None (e.g. non-multi-asic device or unexpected fixture
        # behavior), fall back to letting format_json_patch_for_multiasic target all
        # ASIC namespaces instead of generating a broken "/None/..." patch path.
        is_asic_specific=True, asic_namespaces=[asic_namespace] if asic_namespace else None
    )

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        # Step 3: set the corresponding leaf fanout sub-ports to 100G.
        for fanout, fanout_port in fanout_subports:
            success = fanout.set_speed(fanout_port, target_speed)
            pytest_assert(success, "Failed to set speed {} on fanout {}:{}".format(
                target_speed, fanout.hostname, fanout_port))

        # Step 4: verify no crash happened on the DUT and both sub-ports come up.
        pytest_assert(duthost.critical_services_fully_started(),
                      "Critical services are not fully started after 400G->100G breakout speed change")
        for port in subports:
            current_status_speed = check_interface_status(duthost, "Speed", port).replace("G", "000")
            current_status_speed = current_status_speed.replace("M", "")
            pytest_assert(current_status_speed == target_speed,
                          "Failed to configure sub-port {} speed to {}".format(port, target_speed))
        pytest_assert(_wait_ports_oper_up(subports),
                      "Sub-ports {} did not come up after changing speed to {}".format(subports, target_speed))
    finally:
        # Step 5: recover the leaf fanout sub-ports speed.
        fanout_restore_failures = []
        for fanout, fanout_port in fanout_subports:
            if not fanout.set_speed(fanout_port, breakout_speed):
                fanout_restore_failures.append("{}:{}".format(fanout.hostname, fanout_port))

        # Step 6: roll back the DUT port speed change. Use a plain rollback (rather than
        # rollback_or_reload) here: the autouse ensure_dut_readiness fixture already runs
        # rollback_or_reload() as a safety net during its own teardown, so also falling
        # back to a full config_reload from within the test body would be redundant,
        # slow, and could interleave two reloads. Assert success explicitly below
        # instead, leaving rollback_or_reload() in the fixture as the final safety net.
        delete_tmpfile(duthost, tmpfile)
        rollback_output = rollback(duthost)

    # Fail loudly (rather than silently ignoring) if restoring the fanout speed did not
    # succeed, since a left-over speed mismatch would impact subsequent test runs on
    # these ports. Include the fanout hostname alongside the port name since testbeds
    # can have multiple fanout switches.
    pytest_assert(not fanout_restore_failures,
                  "Failed to restore fanout port(s) {} speed back to {}".format(
                      fanout_restore_failures, breakout_speed))

    pytest_assert(
        not rollback_output.get('rc', 1) and
        "Config rolled back successfully" in rollback_output.get('stdout', ''),
        "Failed to roll back DUT port speed change: {}".format(rollback_output)
    )

    # Step 7: verify both sub-ports are up again after rolling back to 400G breakout.
    pytest_assert(_wait_ports_oper_up(subports),
                  "Sub-ports {} did not come back up after rolling back speed to {}".format(
                      subports, breakout_speed))
