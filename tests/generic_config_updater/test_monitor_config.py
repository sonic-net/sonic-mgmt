import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback, rollback_or_reload

logger = logging.getLogger(__name__)

MONITOR_CONFIG_TEST_CP        = "monitor_config_test"
MONITOR_CONFIG_INITIAL_CP     = "monitor_config_initial"
MONITOR_CONFIG_ACL_TABLE      = "EVERFLOW_DSCP"
MONITOR_CONFIG_ACL_RULE       = "RULE_1"
MONITOR_CONFIG_MIRROR_SESSION = "mirror_session_dscp"
MONITOR_CONFIG_POLICER        = "policer_dscp"


@pytest.fixture(scope='module')
def get_valid_acl_ports(cfg_facts):
    """ Get valid acl ports that could be added to ACL table
    valid ports refers to the portchannels and ports not belongs portchannel
    """
    ports = set()
    portchannel_members = set()

    portchannel_member_dict = cfg_facts.get('PORTCHANNEL_MEMBER', {})
    for po, po_members in portchannel_member_dict.items():
        ports.add(po)
        for po_member in po_members:
            portchannel_members.add(po_member)

    port_dict = cfg_facts.get('PORT', {})
    for key in port_dict:
        if key not in portchannel_members:
            ports.add(key)

    return list(ports)


def bgp_monitor_config_cleanup(duthost):
    """ Test requires no monitor config
    Clean up current monitor config if existed
    """
    cmds = []
    cmds.append('sonic-db-cli CONFIG_DB del "ACL_TABLE|{}"'.format(MONITOR_CONFIG_ACL_TABLE))
    cmds.append('sonic-db-cli CONFIG_DB del "ACL_RULE|{}|{}"'.format(MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE))
    cmds.append('sonic-db-cli CONFIG_DB del "MIRROR_SESSION|{}"'.format(MONITOR_CONFIG_MIRROR_SESSION))
    cmds.append('sonic-db-cli CONFIG_DB del "POLICER|everflow_static_policer"'.format(MONITOR_CONFIG_POLICER))

    output = duthost.shell_cmds(cmds=cmds)['results']
    for res in output:
        pytest_assert(not res['rc'],
            "bgp monitor config cleanup failed."
        )


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for syslog config

    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

    finally:
        delete_checkpoint(duthost)


def verify_monitor_config(duthost):
    """
    This config contains 4 parts: ACL_TABLE, ACL_RULE, POLICER, MIRROR_SESSION

    admin@vlab-01:~$ show acl table EVERFLOW_DSCP_TEST
    Name                Type         Binding    Description         Stage
    ------------------  -----------  ---------  ------------------  -------
    EVERFLOW_DSCP_TEST  MIRROR_DSCP  Ethernet0  EVERFLOW_DSCP_TEST  ingress
                                     ...

    admin@vlab-01:~$ show acl rule EVERFLOW_DSCP_TEST RULE_1
    Table               Rule      Priority  Action                                    Match
    ------------------  ------  ----------  ----------------------------------------  -------
    EVERFLOW_DSCP_TEST  RULE_1        9999  MIRROR INGRESS: mirror_session_dscp_test  DSCP: 5

    admin@vlab-01:~/everflow$ show policer everflow_static_policer
    Name                     Type    Mode         CIR       CBS
    -----------------------  ------  ------  --------  --------
    everflow_policer_test    bytes   sr_tcm  12500000  12500000

    admin@vlab-01:~$ show mirror_session mirror_session_dscp_test
    ERSPAN Sessions
    Name                      Status    SRC IP    DST IP    GRE      DSCP    TTL  Queue    Policer                  Monitor Port    SRC Port    Direction
    ------------------------  --------  --------  --------  -----  ------  -----  -------  -----------------------  --------------  ----------  -----------
    mirror_session_dscp_test  active    1.1.1.1   2.2.2.2               5     32           everflow_policer_test
    ...
    """
    table = duthost.shell("show acl table {}".format(MONITOR_CONFIG_ACL_TABLE))
    expect_res_success(duthost, table, [MONITOR_CONFIG_ACL_TABLE], [])

    rule = duthost.shell("show acl rule {} {}".format(MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE))
    expect_res_success(duthost, rule, [
        MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE, MONITOR_CONFIG_MIRROR_SESSION], [])

    policer = duthost.shell("show policer {}".format(MONITOR_CONFIG_POLICER))
    expect_res_success(duthost, policer, [MONITOR_CONFIG_POLICER], [])

    mirror_session = duthost.shell("show mirror_session {}".format(MONITOR_CONFIG_MIRROR_SESSION))
    expect_res_success(duthost, mirror_session, [
        MONITOR_CONFIG_MIRROR_SESSION, MONITOR_CONFIG_POLICER], [])


def verify_no_monitor_config(duthost):
    """
    Clean up monitor config in ACL_TABLE, ACL_RULE, POLICER, MIRROR_SESSION
    """
    table = duthost.shell("show acl table {}".format(MONITOR_CONFIG_ACL_TABLE))
    expect_res_success(duthost, table, [], [MONITOR_CONFIG_ACL_TABLE])

    rule = duthost.shell("show acl rule {} {}".format(MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE))
    expect_res_success(duthost, rule, [], [
        MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE, MONITOR_CONFIG_MIRROR_SESSION])

    policer = duthost.shell("show policer {}".format(MONITOR_CONFIG_POLICER))
    expect_res_success(duthost, policer, [], [MONITOR_CONFIG_POLICER])

    mirror_session = duthost.shell("show mirror_session {}".format(MONITOR_CONFIG_MIRROR_SESSION))
    expect_res_success(duthost, mirror_session, [], [
        MONITOR_CONFIG_MIRROR_SESSION, MONITOR_CONFIG_POLICER])


def monitor_config_add_config(duthost, get_valid_acl_ports):
    """ Test to add everflow always on config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/{}".format(MONITOR_CONFIG_ACL_TABLE),
            "value": {
                "policy_desc": "{}".format(MONITOR_CONFIG_ACL_TABLE),
                "ports": get_valid_acl_ports,
                "stage": "ingress",
                "type": "MIRROR_DSCP"
            }
        },
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "{}|{}".format(MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE): {
                    "DSCP": "5",
                    "MIRROR_INGRESS_ACTION": "{}".format(MONITOR_CONFIG_MIRROR_SESSION),
                    "PRIORITY": "9999"
                }
            }
        },
        {
            "op": "add",
            "path": "/MIRROR_SESSION",
            "value": {
               "{}".format(MONITOR_CONFIG_MIRROR_SESSION): {
                    "dscp": "5",
                    "dst_ip": "2.2.2.2",
                    "policer": "{}".format(MONITOR_CONFIG_POLICER),
                    "src_ip": "1.1.1.1",
                    "ttl": "32",
                    "type": "ERSPAN"
               }
            }
        },
        {
            "op": "add",
            "path": "/POLICER",
            "value": {
                "{}".format(MONITOR_CONFIG_POLICER): {
                    "meter_type": "bytes",
                    "mode": "sr_tcm",
                    "cir": "12500000",
                    "cbs": "12500000",
                    "red_packet_action": "drop"
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        verify_monitor_config(duthost)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_monitor_config_tc1_suite(rand_selected_dut, get_valid_acl_ports):
    """ Test enable/disable EverflowAlwaysOn config
    """
    # Step 1: Create checkpoint at initial state where no monitor config exist
    bgp_monitor_config_cleanup(rand_selected_dut)
    create_checkpoint(rand_selected_dut, MONITOR_CONFIG_INITIAL_CP)

    # Step 2: Add EverflowAlwaysOn config to rand_selected_dut
    monitor_config_add_config(rand_selected_dut, get_valid_acl_ports)

    # Step 3: Create checkpoint that containing desired EverflowAlwaysOn config
    create_checkpoint(rand_selected_dut, MONITOR_CONFIG_TEST_CP)

    try:
    # Step 4: Rollback to initial state disabling monitor config
        output = rollback(rand_selected_dut, MONITOR_CONFIG_INITIAL_CP)
        pytest_assert(
            not output['rc'] and "Config rolled back successfull" in output['stdout'],
            "config rollback to {} failed.".format(MONITOR_CONFIG_INITIAL_CP)
        )
        verify_no_monitor_config(rand_selected_dut)

    # Step 5: Rollback to EverflowAlwaysOn config and verify
        output = rollback(rand_selected_dut, MONITOR_CONFIG_TEST_CP)
        pytest_assert(
            not output['rc'] and "Config rolled back successfull" in output['stdout'],
            "config rollback to {} failed.".format(MONITOR_CONFIG_TEST_CP)
        )
        verify_monitor_config(rand_selected_dut)

    finally:
        delete_checkpoint(rand_selected_dut, MONITOR_CONFIG_INITIAL_CP)
        delete_checkpoint(rand_selected_dut, MONITOR_CONFIG_TEST_CP)
