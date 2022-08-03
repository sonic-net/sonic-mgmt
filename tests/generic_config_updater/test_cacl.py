import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

# Test on t0 topo to verify functionality and to choose predefined variable
# admin@vlab-01:~$ show acl table
# Name        Type       Binding          Description    Stage
# ----------  ---------  ---------------  -------------  -------
# ...
# NTP_ACL     CTRLPLANE  NTP              NTP_ACL        ingress
# SNMP_ACL    CTRLPLANE  SNMP             SNMP_ACL       ingress
# SSH_ONLY    CTRLPLANE  SSH              SSH_ONLY       ingress

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)

T0_CACL_TABLE = ["NTP_ACL", "SNMP_ACL", "SSH_ONLY"]


def get_cacl_tables(duthost):
    """Get acl control palne tables
    """
    cmds = "show acl table | grep -w CTRLPLANE | awk '{print $1}'"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "'{}' failed with rc={}".format(cmds, output['rc'])
    )
    cacl_tables = output['stdout'].splitlines()
    return cacl_tables


def get_iptable_rules(duthost):
    cmds = "iptables -S"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "'{}' failed with rc={}".format(cmds, output['rc'])
    )
    rules_chain = output['stdout'].splitlines()
    return rules_chain


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for acl config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    original_iptable_rules = get_iptable_rules(duthost)
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

        current_iptable_rules = get_iptable_rules(duthost)
        pytest_assert(set(original_iptable_rules) == set(current_iptable_rules),
            "iptable rules are not suppose to change after test"
        )

        current_cacl_tables = get_cacl_tables(duthost)
        pytest_assert(set(T0_CACL_TABLE) == set(current_cacl_tables),
            "iptable rules are not suppose to change after test"
        )
    finally:
        delete_checkpoint(duthost)


def expect_acl_table_match(duthost, table_name, expected_content_list):
    """Check if acl table show as expected
    """
    cmds = "show acl table {}".format(table_name)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "'{}' failed with rc={}".format(cmds, output['rc'])
    )

    # Ignore first two lines display. lines less than 3 means no output
    # Use empty list if no output
    lines = output['stdout'].splitlines()
    actual_list = [] if len(lines) < 3 else lines[2].split()

    pytest_assert(set(expected_content_list) == set(actual_list),
        "ACL table doesn't match"
    )


def expect_res_success_acl_rule(duthost, expected_content_list, unexpected_content_list):
    """Check if acl rule added as expected
    """
    time.sleep(1) # Sleep 1 sec to ensure caclmgrd does update in case of its UPDATE_DELAY_SECS 0.5s
    cmds = "iptables -S"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "'{}' failed with rc={}".format(cmds, output['rc'])
    )

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)


def cacl_tc1_add_new_table(duthost):
    """ Add acl table for test

    Sample output
    admin@vlab-01:~$ show acl table
    Name    Type       Binding    Description    Stage
    ------  ---------  ---------  -------------  -------
    ...
    TEST_1  CTRLPLANE  SNMP       Test_Table_1   ingress
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/TEST_1",
            "value": {
                "policy_desc": "Test_Table_1",
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

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["TEST_1", "CTRLPLANE","SNMP", "Test_Table_1", "ingress"]
        expect_acl_table_match(duthost, "TEST_1", expected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc1_add_duplicate_table(duthost):
    """ Add duplicate acl table
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/SNMP_ACL",
            "value": {
                "policy_desc": "SNMP_ACL",
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

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc1_replace_table_variable(duthost):
    """ Replace acl table with SSH service

    Expected output
    admin@vlab-01:~$ show acl table
    Name        Type       Binding          Description    Stage
    ----------  ---------  ---------------  -------------  -------
    SNMP_ACL    CTRLPLANE  SSH              SNMP_TO_SSH    egress
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/ACL_TABLE/SNMP_ACL/stage",
            "value": "egress"
        },
        {
            "op": "replace",
            "path": "/ACL_TABLE/SNMP_ACL/services/0",
            "value": "SSH"
        },
        {
            "op": "replace",
            "path": "/ACL_TABLE/SNMP_ACL/policy_desc",
            "value": "SNMP_TO_SSH"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["SNMP_ACL", "CTRLPLANE", "SSH",
                                 "SNMP_TO_SSH", "egress"]
        expect_acl_table_match(duthost, "SNMP_ACL", expected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc1_add_invalid_table(duthost):
    """ Add invalid acl table

    {"service": "SSH", "stage": "ogress", "type": "CTRLPLANE"}, # wrong stage
    {"service": "SSH", "stage": "ingress", "type": "TRLPLANE"}  # wrong type
    """
    invalid_table = [
        {"service": "SSH", "stage": "ogress", "type": "CTRLPLANE"},
        {"service": "SSH", "stage": "ingress", "type": "TRLPLANE"}
    ]

    for ele in invalid_table:
        json_patch = [
            {
                "op": "add",
                "path": "/ACL_TABLE/TEST_2",
                "value": {
                    "policy_desc": "Test_Table_2",
                    "services": [
                     "{}".format(ele["service"])
                    ],
                    "stage": "{}".format(ele["stage"]),
                    "type": "{}".format(ele["type"])
                }
            }
        ]

        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_failure(output)
        finally:
            delete_tmpfile(duthost, tmpfile)


def cacl_tc1_remove_unexisted_table(duthost):
    """ Remove unexisted acl table
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_RULE/SSH_ONLY_UNEXISTED"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc1_remove_table(duthost):
    """ Remove acl table test
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE/SSH_ONLY"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_table_match(duthost, "SSH_ONLY", [])
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_cacl_tc1_acl_table_suite(rand_selected_dut):
    cacl_tc1_add_new_table(rand_selected_dut)
    cacl_tc1_add_duplicate_table(rand_selected_dut)
    cacl_tc1_replace_table_variable(rand_selected_dut)
    cacl_tc1_add_invalid_table(rand_selected_dut)
    cacl_tc1_remove_unexisted_table(rand_selected_dut)
    cacl_tc1_remove_table(rand_selected_dut)


def cacl_tc2_add_init_rule(duthost):
    """ Add acl rule for test

    Check 'ip tables' to make sure rule is actually being applied
    show command as below:
    admin@vlab-01:~/test$ show acl rule
    Table       Rule       Priority    Action    Match
    -------     ---------  ----------  --------  ------------------
    SSH_ONLY    TEST_DROP  9998        DROP      IP_PROTOCOL: 6
                                                 IP_TYPE: IP
                                                 L4_DST_PORT: 22
                                                 SRC_IP: 9.9.9.9/32

    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "SSH_ONLY|TEST_DROP": {
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

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 22 -j DROP"]
        expect_res_success_acl_rule(duthost, expected_content_list, [])
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_add_duplicate_rule(duthost):
    """ Add duplicate acl rule for test
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "SSH_ONLY|TEST_DROP": {
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

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_replace_rule(duthost):
    """ Replace a value from acl rule test

    Check 'ip tables' to make sure rule is actually being applied
    show command:
    admin@vlab-01:~/test$ show acl rule
    Table       Rule       Priority    Action    Match
    -------     ---------  ----------  --------  ------------------
    SSH_ONLY    TEST_DROP  9998        DROP      IP_PROTOCOL: 6
                                                 IP_TYPE: IP
                                                 L4_DST_PORT: 22
                                                 SRC_IP: 8.8.8.8/32
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/ACL_RULE/SSH_ONLY|TEST_DROP/SRC_IP",
            "value": "8.8.8.8/32"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j DROP"]
        unexpected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 22 -j DROP"]
        expect_res_success_acl_rule(duthost, expected_content_list, unexpected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_add_rule_to_unexisted_table(duthost):
    """ Add acl rule to unexisted table
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

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_remove_table_before_rule(duthost):
    """ Remove acl table before removing acl rule
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_TABLE/SSH_ONLY"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_remove_unexist_rule(duthost):
    """ Remove unexisted acl rule
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/ACL_RULE/SSH_ONLY|TEST_DROP2"
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_remove_rule(duthost):
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

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        unexpected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j DROP"]
        expect_res_success_acl_rule(duthost, [], unexpected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)


# ACL_RULE tests are related. So group them into one test.
def test_cacl_tc2_acl_rule_test(rand_selected_dut):
    cacl_tc2_add_init_rule(rand_selected_dut)
    cacl_tc2_add_duplicate_rule(rand_selected_dut)
    cacl_tc2_replace_rule(rand_selected_dut)
    cacl_tc2_add_rule_to_unexisted_table(rand_selected_dut)
    cacl_tc2_remove_table_before_rule(rand_selected_dut)
    cacl_tc2_remove_unexist_rule(rand_selected_dut)
    cacl_tc2_remove_rule(rand_selected_dut)
