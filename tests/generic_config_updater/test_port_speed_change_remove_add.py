import logging
import re
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('t2'),
]

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def ensure_dut_readiness(duthosts, rand_one_dut_front_end_hostname):
    """
    Setup/teardown fixture for each test.
    Creates a checkpoint before the test and rolls back after.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def is_valid_speed_state_db(duthost, value, port, namespace=None):
    """Check if a speed value is valid according to STATE_DB supported_speeds."""
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
    Returns current status for interface of specified field.

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
    interface_status = ""
    for line in status_data:
        if interface in line:
            interface_status = line.strip()
    pytest_assert(len(interface_status) > 0, "Failed to read {} interface properties".format(interface))
    status = re.split(r" {2,}", interface_status)[field_index]
    return status


def get_ethernet_port_not_in_portchannel(duthost, namespace=None):
    """
    Returns the name of an ethernet port which is not a member of a port channel.

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
            if port_role and port_role != 'Ext':
                continue
            port_name = port
            break
    return port_name


@pytest.mark.device_type('physical')
def test_port_speed_change_via_remove_add(duthosts, rand_one_dut_front_end_hostname,
                                          ensure_dut_readiness,
                                          enum_rand_one_frontend_asic_index, loganalyzer):
    """
    Test port speed change via GCU remove-then-add patch on T2 chassis linecards.

    Covers the use case described in GH issue #23585:
    A T2 linecard has a 400G-capable SKU but a port is configured at a lower speed
    (e.g. 100G). GCU patches are used to remove the lower-speed port entry and add
    the port back at the higher speed (e.g. 400G).

    Unlike test_update_speed (which does an in-place replace on the speed field),
    this test exercises the full remove + add workflow that is used in production
    for port speed migration on T2 chassis linecards.

    Steps:
    1. Select a free frontend port (not in a PortChannel).
    2. Read the port's full configuration from CONFIG_DB.
    3. Identify a valid target speed different from the current speed.
    4. Build a GCU JSON patch that removes the port entry, then adds it back
       with the new speed (and appropriate lanes, alias, index, etc.).
    5. Apply the patch via GCU (config apply-patch).
    6. Verify the patch succeeds and the new speed is visible in 'show interface status'.
    7. Verify the full port configuration is present in CONFIG_DB after the add.
    8. Assert no critical syslog errors (dependency failures, ASIC programming errors)
       occurred during the remove + add operation.
    9. Rollback is handled automatically by the ensure_dut_readiness fixture.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace = None if enum_rand_one_frontend_asic_index is None else \
        'asic{}'.format(enum_rand_one_frontend_asic_index)
    namespace_prefix = '' if asic_namespace is None else '-n ' + asic_namespace

    # Add ignore patterns for expected syslog messages during port remove + add.
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".*ERR swss[0-9]*#orchagent.*doPortTask: Unsupported port.*speed",
            r".*ERR swss[0-9]*#orchagent.*removeLag.*",
            r".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*",
        ])

    # Use a port outside any PortChannel to avoid disrupting routed traffic.
    port = get_ethernet_port_not_in_portchannel(duthost, namespace=asic_namespace)
    if not port:
        pytest.skip("No free ports available outside PortChannels for this test")

    # Read the full port configuration from CONFIG_DB.
    port_config_str = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hgetall "PORT|{}"'.format(namespace_prefix, port)
    )['stdout'].strip()
    pytest_assert(port_config_str, "Failed to read CONFIG_DB entry for port {}".format(port))

    # Parse the hgetall output (alternating key/value lines) into a dict.
    port_config_lines = port_config_str.split('\n')
    port_config = {}
    for i in range(0, len(port_config_lines) - 1, 2):
        key = port_config_lines[i].strip()
        value = port_config_lines[i + 1].strip()
        if key:
            port_config[key] = value

    current_speed = port_config.get('speed', '')
    pytest_assert(current_speed, "No speed configured for port {}".format(port))

    # Get supported speeds and find a target speed different from the current one.
    if duthost.get_facts()['asic_type'] == 'vs':
        valid_speeds = ['20000', '40000']
    else:
        valid_speeds = duthost.get_supported_speeds(port)
    pytest_assert(valid_speeds, "No supported speeds found for port {}".format(port))

    target_speed = next(
        (s for s in valid_speeds
         if s != current_speed and is_valid_speed_state_db(duthost, s, port, namespace=asic_namespace)),
        None
    )
    if target_speed is None:
        pytest.skip("No alternative valid speed available for port {} (current: {})".format(port, current_speed))

    logger.info("Testing GCU remove+add speed change on port {} from {} to {}".format(
        port, current_speed, target_speed))

    # Build the new port config with the target speed.
    new_port_config = dict(port_config)
    new_port_config['speed'] = target_speed
    new_port_config['admin_status'] = 'up'

    # Build a GCU JSON patch: remove the port, then add it back with the new config.
    json_patch = [
        {
            "op": "remove",
            "path": "/PORT/{}".format(port)
        },
        {
            "op": "add",
            "path": "/PORT/{}".format(port),
            "value": new_port_config
        }
    ]
    json_patch = format_json_patch_for_multiasic(
        duthost=duthost, json_data=json_patch,
        is_asic_specific=True, asic_namespaces=[asic_namespace]
    )

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        pre_patch_timestamp = duthost.shell("date '+%b %e %H:%M:%S'")['stdout'].strip()

        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        # Verify the speed value is updated in the interface status table.
        current_status_speed = check_interface_status(duthost, "Speed", port).replace("G", "000")
        current_status_speed = current_status_speed.replace("M", "")
        pytest_assert(
            current_status_speed == target_speed,
            "Speed not updated to {} after remove+add: got {}".format(target_speed, current_status_speed)
        )

        # Verify the port entry exists in CONFIG_DB with expected fields after the add.
        restored_speed = duthost.shell(
            'sonic-db-cli {} CONFIG_DB hget "PORT|{}" speed'.format(namespace_prefix, port)
        )['stdout'].strip()
        pytest_assert(
            restored_speed == target_speed,
            "CONFIG_DB speed mismatch after remove+add: expected {}, got {}".format(target_speed, restored_speed)
        )

        restored_lanes = duthost.shell(
            'sonic-db-cli {} CONFIG_DB hget "PORT|{}" lanes'.format(namespace_prefix, port)
        )['stdout'].strip()
        pytest_assert(
            restored_lanes,
            "Lanes missing from CONFIG_DB after remove+add for port {}".format(port)
        )

        restored_alias = duthost.shell(
            'sonic-db-cli {} CONFIG_DB hget "PORT|{}" alias'.format(namespace_prefix, port)
        )['stdout'].strip()
        original_alias = port_config.get('alias', '')
        if original_alias:
            pytest_assert(
                restored_alias == original_alias,
                "Alias mismatch after remove+add: expected {}, got {}".format(original_alias, restored_alias)
            )

        # Check syslog for critical errors during the remove + add operation.
        syslog_errors = duthost.shell(
            "sudo awk -v ts=\"{ts}\" '$0 >= ts' /var/log/syslog "
            "| grep -iE 'ERR.*(orchagent|syncd).*{port}.*(dependency|fail)' "
            "| tail -20 || true".format(ts=pre_patch_timestamp, port=port),
            module_ignore_errors=True
        )['stdout'].strip()
        pytest_assert(
            not syslog_errors,
            "Syslog errors found during port remove+add on {}: {}".format(port, syslog_errors)
        )

        oper_status = check_interface_status(duthost, "Oper", port)
        logger.info(
            "GCU remove+add speed change verified: port {} speed={} lanes={} alias={} oper={}".format(
                port, target_speed, restored_lanes, restored_alias, oper_status)
        )
    finally:
        delete_tmpfile(duthost, tmpfile)
