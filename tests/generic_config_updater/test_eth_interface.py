import logging
import pytest
import re
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

SHOW_FEC_OPER_CMD_TEMPLATE = "show interfaces fec status {}"


@pytest.fixture(autouse=True)
def ensure_dut_readiness(duthosts, rand_one_dut_front_end_hostname):
    """
    Setup/teardown fixture for each ethernet test
    rollback to check if it goes back to starting config

    Args:
        duthosts: list of DUTs
        rand_one_dut_front_end_hostname: The fixture returns a randomly selected frontend DUT hostname
    """

    duthost = duthosts[rand_one_dut_front_end_hostname]
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
    if 'PORTCHANNEL_MEMBER' not in config_facts:
        if len(ports) > 0:
            port_name = ports[0]
        return port_name
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


def test_remove_lanes(duthosts, rand_one_dut_front_end_hostname,
                      ensure_dut_readiness, enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
def test_replace_lanes(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                       enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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


def test_replace_mtu(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                     enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
def test_toggle_pfc_asym(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, pfc_asym,
                         enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
def test_replace_fec(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, fec,
                     enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
def test_update_invalid_index(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                              enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
def test_update_valid_index(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                            enum_rand_one_frontend_asic_index, cli_namespace_prefix):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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


def test_update_speed(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                      enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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


def test_update_description(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                            enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
def test_eth_interface_admin_change(duthosts, rand_one_dut_front_end_hostname, admin_status,
                                    enum_rand_one_frontend_asic_index):
    duthost = duthosts[rand_one_dut_front_end_hostname]
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
