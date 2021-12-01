import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module", autouse=True)
def setup_env(duthosts, rand_one_dut_hostname, cfg_facts):
    """
    Setup/teardown fixture for acl config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
        cfg_facts: config facts for selected DUT
    """
    duthost = duthosts[rand_one_dut_hostname]

    config_tmpfile = generate_tmpfile(duthost)
    logger.info("config_tmpfile {} Backing up config_db.json".format(config_tmpfile))
    duthost.shell("sudo cp /etc/sonic/config_db.json {}".format(config_tmpfile))

    # Cleanup acl config
    duthost.shell('sonic-db-cli CONFIG_DB keys "ACL_RULE|*" | xargs --no-run-if-empty sonic-db-cli CONFIG_DB del')
    duthost.shell('sonic-db-cli CONFIG_DB keys "ACL_TABLE|*" | xargs --no-run-if-empty sonic-db-cli CONFIG_DB del')

    yield

    logger.info("Restoring config_db.json")
    duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(config_tmpfile))
    delete_tmpfile(duthost, config_tmpfile)

     # Cleanup acl config
    config_reload(duthost)

def expect_res_success_acl_table(duthost, expected_content_list, unexpected_content_list):
    """Check if acl table show as expected
    """
    cmds = "show acl table"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)

def expect_res_success_acl_rule(duthost, expected_content_list, unexpected_content_list):
    """Check if acl rule added as expected
    """
    cmds = "sudo iptables -S"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)

def test_cacl_tc1_add_init_table(duthost):
    """ Add acl table for test

    Sample output
    admin@vlab-01:~$ show acl table
    Name    Type       Binding    Description    Stage
    ------  ---------  ---------  -------------  -------
    TEST_1  CTRLPLANE  SNMP       Test Table 1   ingress
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE",
            "value": {
                "TEST_1": {
                    "policy_desc": "Test Table 1",
                    "services": [
                     "SNMP"
                    ],
                    "stage": "ingress",
                    "type": "CTRLPLANE"
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    expected_content_list = ["TEST_1", "SNMP"]
    expect_res_success_acl_table(duthost, expected_content_list, [])

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc2_add_duplicate_table(duthost):
    """ Add duplicate acl table
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/TEST_1",
            "value": {
                "policy_desc": "Test Table 1",
                "services": [
                 "SNMP"
                ],
                "stage": "ingress",
                "type": "CTRLPLANE"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc3_replace_table(duthost):
    """ Replace acl table with SSH service
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/ACL_TABLE/TEST_1/services/0",
            "value": "SSH"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    expected_content_list = ["TEST_1", "SSH"]
    expect_res_success_acl_table(duthost, expected_content_list, [])

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc4_add_invalid_table(duthost):
    """ Add invalid acl table with wrong type
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/TEST_2",
            "value": {
                "policy_desc": "Test Table 2",
                "services": [
                 "SSH"
                ],
                "stage": "ingress",
                "type": "CONTROLLING PLANE"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc5_add_init_rule(duthost):
    """ Add acl rule for test
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "TEST_1|TEST_DROP": {
                 "L4_DST_PORT": "22",
                 "IP_PROTOCOL": "6",
                 "IP_TYPE": "IP",
                 "PACKET_ACTION": "DROP",
                 "PRIORITY": "9998",
                 "SRC_IP": "9.9.9.9/32"
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    expected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 22 -j DROP"]
    expect_res_success_acl_rule(duthost, expected_content_list, [])

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc6_add_duplicate_rule(duthost):
    """ Add duplicate acl rule for test
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE/TEST_1|TEST_DROP",
            "value": {
                "L4_DST_PORT": "22",
                "IP_PROTOCOL": "6",
                "IP_TYPE": "IP",
                "PACKET_ACTION": "DROP",
                "PRIORITY": "9998",
                "SRC_IP": "9.9.9.9/32"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc7_replace_rule(duthost):
    """ Replace a value from acl rule test
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/ACL_RULE/TEST_1|TEST_DROP/SRC_IP",
            "value": "8.8.8.8/32"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    expected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j DROP"]
    unexpected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 22 -j DROP"]
    expect_res_success_acl_rule(duthost, expected_content_list, unexpected_content_list)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc8_add_invalid_rule(duthost):
    """ Add invalid acl rule for test
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE/TEST_2|TEST_DROP",
            "value": {
                "L4_DST_PORT": "22",
                "IP_PROTOCOL": "6",
                "IP_TYPE": "IP",
                "PACKET_ACTION": "DROP",
                "PRIORITY": "9998",
                "SRC_IP": "9.9.9.9/32"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc9_remove_table_before_rule(duthost):
    """ Remove acl table before removing acl rule
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("unexist_rule_or_table", [
    ("/ACL_RULE/TEST_2|TEST_DROP"),
    ("/ACL_TABLE/TEST_2")
])
def test_cacl_tc10_remove_unexist_rule_or_table(duthost, unexist_rule_or_table):
    """ Remove unexisted acl rule or acl table
    """
    json_patch = [
        {
            "op": "remove",
            "path": "{}".format(unexist_rule_or_table)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc11_remove_rule(duthost):
    """ Remove acl rule test
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_RULE"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    unexpected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j DROP"]
    expect_res_success_acl_rule(duthost, [], unexpected_content_list)

    delete_tmpfile(duthost, tmpfile)

def test_cacl_tc12_remove_table(duthost):
    """ Remove acl table test
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    unexpected_content_list = ["TEST_1"]
    expect_res_success_acl_table(duthost, [], unexpected_content_list)

    delete_tmpfile(duthost, tmpfile)
