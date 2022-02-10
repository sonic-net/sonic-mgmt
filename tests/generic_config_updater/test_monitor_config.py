import logging
import pytest

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

logger = logging.getLogger(__name__)

MONITOR_CONFIG_ACL_TABLE = "EVERFLOW_DSCP_TEST"
MONITOR_CONFIG_ACL_RULE = "RULE_1"
MONITOR_CONFIG_MIRROR_SESSION = "mirror_session_dscp_test"

@pytest.fixture(scope='module')
def get_valid_acl_ports(cfg_facts):
    """ Get valid acl ports
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

def test_monitor_config_tc1_add_config(duthost):
    """ Test to add everflow always on config
    This config contains 3 parts: ACL_TABLE, ACL_RULE, MIRROR_SESSION

    admin@vlab-01:~$ show acl table EVERFLOW_DSCP_TEST
    Name                Type         Binding    Description         Stage
    ------------------  -----------  ---------  ------------------  -------
    EVERFLOW_DSCP_TEST  MIRROR_DSCP  Ethernet0  EVERFLOW_DSCP_TEST  ingress
                                     ...
    
    admin@vlab-01:~$ show acl rule EVERFLOW_DSCP_TEST RULE_1
    Table               Rule      Priority  Action                                    Match
    ------------------  ------  ----------  ----------------------------------------  -------
    EVERFLOW_DSCP_TEST  RULE_1        9999  MIRROR INGRESS: mirror_session_dscp_test  DSCP: 5

    admin@vlab-01:~$ show mirror_session mirror_session_dscp_test
    ERSPAN Sessions
    Name                      Status    SRC IP    DST IP    GRE      DSCP    TTL  Queue    Policer    Monitor Port    SRC Port    Direction
    ------------------------  --------  --------  --------  -----  ------  -----  -------  ---------  --------------  ----------  -----------
    mirror_session_dscp_test  active    1.1.1.1   2.2.2.2               5     32                      Ethernet112
    ...

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
                    "src_ip": "1.1.1.1",
                    "ttl": "32",
                    "type": "ERSPAN"
               }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        table = duthost.shell("show acl table {}".format(MONITOR_CONFIG_ACL_TABLE))
        expect_res_success(duthost, table, [MONITOR_CONFIG_ACL_TABLE], [])

        rule = duthost.shell("show acl rule {} {}".format(MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE))
        expect_res_success(duthost, rule, 
            [MONITOR_CONFIG_ACL_TABLE, MONITOR_CONFIG_ACL_RULE, MONITOR_CONFIG_MIRROR_SESSION], [])

        mirror_session = duthost.shell("show mirror_session {}".format(MONITOR_CONFIG_MIRROR_SESSION))
        expect_res_success(duthost, mirror_session, [MONITOR_CONFIG_MIRROR_SESSION], [])

    finally:
        delete_tmpfile(duthost, tmpfile)
