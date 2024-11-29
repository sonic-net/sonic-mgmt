import logging
import pytest
import re
import random

from tests.common.config_reload import config_reload
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

DEFAULT_INTERFACE = {
    0: "Ethernet0",
    1: "Ethernet144"
}


@pytest.fixture(autouse=True)
def ensure_dut_readiness(duthosts, rand_one_dut_front_end_hostname):
    """
    Setup/teardown fixture for each ethernet test
    rollback to check if it goes back to starting config

    Args:
        duthosts: list of DUTs
        rand_one_dut_front_end_hostname: The fixture returns a randomly selected DUT hostname
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


def check_interface_status(duthost, field, interface):
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


def get_ethernet_port_not_in_portchannel(duthost, namespace=None):
    """
        Returns the name of an ethernet port which is not a member of a port channel

        Args:
            duthost: DUT host object under test
            namespace: DUT asic namespace. asic0, asic1, localhost
    """

    port_name = ""
    config_facts = duthost.config_facts(
        host=duthost.hostname,
        source="running",
        verbose=False,
        namespace=namespace
    )['ansible_facts']
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


def test_remove_lanes(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]

    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")

    json_patch = [
        {
            "op": "remove",
            "path": "{}/PORT/{}/lanes".format(json_namespace, port)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.skip(reason="Bypass as it is blocking submodule update")
def test_replace_lanes(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")

    cur_lanes = check_interface_status(duthost, "Lanes", port)
    cur_lanes = cur_lanes.split(",")
    cur_lanes.sort()
    update_lanes = cur_lanes
    update_lanes[-1] = str(int(update_lanes[-1]) + 1)
    update_lanes = ",".join(update_lanes)

    json_patch = [
        {
            "op": "replace",
            "path": "{}/PORT/{}/lanes".format(json_namespace, port),
            "value": "{}".format(update_lanes)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_replace_mtu(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, _asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    # Can't directly change mtu of the port channel member
    # So find a ethernet port that are not in a port channel
    port_name = get_ethernet_port_not_in_portchannel(duthost, asic_namespace)

    pytest_assert(port_name, "No available ethernet ports, all ports are in port channels.")
    target_mtu = "1514"
    json_patch = [
        {
            "op": "replace",
            "path": "{}/PORT/{}/mtu".format(json_namespace, port_name),
            "value": "{}".format(target_mtu)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        current_status_mtu = check_interface_status(duthost, "MTU", port_name)
        pytest_assert(current_status_mtu == target_mtu,
                      "Failed to properly configure interface MTU to requested value {}".format(target_mtu))
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("pfc_asym", ["on", "off"])
def test_toggle_pfc_asym(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, pfc_asym,
                         rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")
    json_patch = [
        {
            "op": "replace",
            "path": "{}/PORT/{}/pfc_asym".format(json_namespace, port),
            "value": "{}".format(pfc_asym)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

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
                     rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")
    json_patch = [
        {
            "op": "add",
            "path": "{}/PORT/{}/fec".format(json_namespace, port),
            "value": "{}".format(fec)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    fec_cfg_exists = fec_exists_on_config_db(duthost, port, namespace=asic_namespace)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid_fec_state_db(duthost, fec, port, namespace=asic_namespace):
            expect_op_success(duthost, output)
            current_status_fec = check_interface_status(duthost, "FEC", port)
            pytest_assert(current_status_fec == fec,
                          "Failed to properly configure interface FEC to requested value {}".format(fec))

            # The rollback after the test cannot revert the fec, when fec is not configured in config_db.json
            # adding generic check to restore fec if not included in config_db.json
            # keeping previous platform check for backwards compatibility
            if duthost.facts['platform'] in ['x86_64-arista_7050_qx32s'] or fec_cfg_exists is False:
                config_reload(duthost, safe_reload=True)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.skip(reason="Bypass as this is not a production scenario")
def test_update_invalid_index(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                              rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")
    json_patch = [
        {
            "op": "replace",
            "path": "{}/PORT/{}/index".format(json_namespace, port),
            "value": "abc1"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.skip(reason="Bypass as this is not a production scenario")
def test_update_valid_index(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness,
                            rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, _asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    namespace_prefix = '' if asic_namespace is None else '-n ' + asic_namespace
    output = duthost.shell('sonic-db-cli {} CONFIG_DB keys "PORT|"\\*'.format(namespace_prefix))["stdout"]
    interfaces = {}  # to be filled with two interfaces mapped to their indeces

    for line in output.split('\n'):
        if line.startswith('PORT|Ethernet'):
            interface = line[line.index('Ethernet'):].strip()
            index = duthost.shell('sonic-db-cli {} CONFIG_DB hget "PORT|{}" index'.format(
                namespace_prefix, interface))["stdout"]
            interfaces[interface] = index
            if len(interfaces) == 2:
                break
    pytest_assert(len(interfaces) == 2, "Failed to retrieve two interfaces to swap indeces in test")

    json_patch = [
        {
            "op": "replace",
            "path": "{}/PORT/{}/index".format(json_namespace, list(interfaces.keys())[0]),
            "value": "{}".format(list(interfaces.values())[1])
        },
        {
            "op": "replace",
            "path": "{}/PORT/{}/index".format(json_namespace, list(interfaces.keys())[1]),
            "value": "{}".format(list(interfaces.values())[0])
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_update_speed(duthosts, rand_one_dut_front_end_hostname, ensure_dut_readiness, rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")
    speed_params = get_port_speeds_for_test(duthost, port)
    for speed, is_valid in speed_params:
        json_patch = [
            {
                "op": "replace",
                "path": "{}/PORT/{}/speed".format(json_namespace, port),
                "value": "{}".format(speed)
            }
        ]
        json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

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
                            rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")
    json_patch = [
        {
            "op": "replace",
            "path": "{}/PORT/{}/description".format(json_namespace, port),
            "value": "Updated description"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("admin_status", ["up", "down"])
def test_eth_interface_admin_change(duthosts, rand_one_dut_front_end_hostname, admin_status,
                                    rand_front_end_asic_namespace):
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_front_end_asic_namespace
    json_namespace = '' if asic_namespace is None else '/' + asic_namespace
    asic_index = 0 if asic_id is None else asic_id
    port = DEFAULT_INTERFACE.get(asic_index, "DefaultPort")
    json_patch = [
        {
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, port),
            "value": "{}".format(admin_status)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(wait_until(10, 2, 0, lambda: check_interface_status(duthost, "Admin", port) == admin_status),
                      "Interface failed to update admin status to {}".format(admin_status))
    finally:
        delete_tmpfile(duthost, tmpfile)
