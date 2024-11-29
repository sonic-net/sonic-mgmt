import logging
import pytest
import time
import difflib

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.utilities import wait_until

# Test on t0 topo to verify functionality and to choose predefined variable
# admin@vlab-01:~$ show acl table
# Name        Type       Binding          Description    Stage
# ----------  ---------  ---------------  -------------  -------
# ...
# NTP_ACL     CTRLPLANE  NTP              NTP_ACL        ingress
# SNMP_ACL    CTRLPLANE  SNMP             SNMP_ACL       ingress
# SSH_ONLY    CTRLPLANE  SSH              SSH_ONLY       ingress

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx', 't1', 't2'),
]

logger = logging.getLogger(__name__)


def get_cacl_tables(duthost, namespace=None):
    """Get acl control plane tables
    """
    namespace_prefix = '' if namespace is None else 'sudo ip netns exec ' + namespace
    cmds = "{} show acl table | grep -w CTRLPLANE | awk '{{print $1}}'".format(namespace_prefix)

    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))
    cacl_tables = output['stdout'].splitlines()
    return cacl_tables


def get_iptable_rules(duthost, namespace=None):
    namespace_prefix = '' if namespace is None else 'sudo ip netns exec ' + namespace
    cmds = "{} iptables -S".format(namespace_prefix)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))
    rules_chain = output['stdout'].splitlines()
    return rules_chain


@pytest.fixture(scope="module", autouse=True)
def disable_port_toggle(duthosts, tbinfo):
    # set mux mode to manual on both TORs to avoid port state change during test
    if "dualtor" in tbinfo['topo']['name']:
        for dut in duthosts:
            dut.shell("sudo config mux mode manual all")
    yield
    if "dualtor" in tbinfo['topo']['name']:
        for dut in duthosts:
            dut.shell("sudo config mux mode auto all")


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_front_end_hostname, rand_front_end_asic_namespace):
    """
    Setup/teardown fixture for acl config
    Args:
        duthosts: list of DUTs.
        rand_one_dut_front_end_hostname: The fixture returns a randomly selected DuT.
        rand_front_end_asic_namespace: The fixture returns a randomly selected asic namespace.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    namespace, _asic_id = rand_front_end_asic_namespace
    original_iptable_rules = get_iptable_rules(duthost, namespace)
    original_cacl_tables = get_cacl_tables(duthost, namespace)
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

        pytest_assert(wait_until(5, 1, 0, check_original_and_current_iptable_rule,
                                 duthost, original_iptable_rules, namespace),
                      "The current iptable rules doesn't match the original one")

        current_cacl_tables = get_cacl_tables(duthost, namespace)
        logger.info("original cacl tables: {}, current cacl tables: {}".format(
            original_cacl_tables, current_cacl_tables)
        )
        cacl_tables_diff = [
            li for li in difflib.ndiff(original_cacl_tables, current_cacl_tables) if li[0] != ' '
        ]
        logger.info("cacl_tables_diff {}".format(cacl_tables_diff))
        pytest_assert(
            set(original_cacl_tables) == set(current_cacl_tables),
            "cacl tables are not suppose to change after test. diff: {}".format(
                cacl_tables_diff)
        )
    finally:
        delete_checkpoint(duthost)


def check_original_and_current_iptable_rule(duthost, original_iptable_rules, namespace=None):
    current_iptable_rules = get_iptable_rules(duthost, namespace)
    logger.info("original iptable rules: {}, current iptable rules: {}".format(
        original_iptable_rules, current_iptable_rules)
    )
    iptable_rules_diff = [
        li for li in difflib.ndiff(original_iptable_rules, current_iptable_rules) if li[0] != ' '
    ]
    logger.info("iptable_rules_diff {}".format(iptable_rules_diff))

    if set(original_iptable_rules) == set(current_iptable_rules):
        return True
    else:
        logger.error(f"iptable rules are not suppose to change after test. diff: {iptable_rules_diff}")
        return False


def expect_acl_table_match(duthost, table_name, expected_content_list, namespace=None):
    """Check if acl table show as expected
    """
    namespace_prefix = '' if namespace is None else 'sudo ip netns exec ' + namespace
    cmds = "{} show acl table {}".format(namespace_prefix, table_name)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # Ignore first two lines display. lines less than 3 means no output
    # Use empty list if no output
    lines = output['stdout'].splitlines()
    actual_list = [] if len(lines) < 3 else lines[2].split()
    # Ignore the status column
    expected_len = len(expected_content_list)
    if len(actual_list) >= expected_len:
        actual_list = actual_list[0:expected_len]

    pytest_assert(set(expected_content_list) == set(actual_list), "ACL table doesn't match")


def expect_res_success_acl_rule(duthost, expected_content_list, unexpected_content_list, namespace=None):
    """Check if acl rule added as expected
    """
    time.sleep(1)   # Sleep 1 sec to ensure caclmgrd does update in case of its UPDATE_DELAY_SECS 0.5s
    namespace_prefix = '' if namespace is None else 'sudo ip netns exec ' + namespace
    cmds = "{} iptables -S".format(namespace_prefix)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)


def cacl_tc1_add_new_table(duthost, protocol, namespace=None):
    """ Add acl table for test

    Sample output
    admin@vlab-01:~$ show acl table
    Name                    Type       Binding          Description                   Stage    Status
    ----------------------  ---------  ---------------  ----------------------------  -------  --------
    SNMP_TEST_1             CTRLPLANE  SNMP             SNMP_Test_Table_1             ingress  Active
    """
    table = "{}_TEST_1".format(protocol)
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/ACL_TABLE/{}".format(json_namespace, table),
            "value": {
                "policy_desc": "{}_Test_Table_1".format(protocol),
                "services": [
                    protocol
                ],
                "stage": "ingress",
                "type": "CTRLPLANE"
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = [table, "CTRLPLANE", protocol, "{}_Test_Table_1".format(protocol), "ingress"]
        expect_acl_table_match(duthost, table, expected_content_list, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc1_add_duplicate_table(duthost, protocol, namespace=None):
    """ Add duplicate acl table
    """
    if protocol == 'SSH':
        table_name = "SSH_ONLY"
    else:
        table_name = "{}_ACL".format(protocol)
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/ACL_TABLE/{}".format(json_namespace, table_name),
            "value": {
                "policy_desc": table_name,
                "services": [
                    protocol
                ],
                "stage": "ingress",
                "type": "CTRLPLANE"
            }
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


def cacl_tc1_replace_table_variable(duthost, protocol, namespace=None):
    """ Replace acl table with SSH service

    Expected output
    admin@vlab-01:~$ show acl table
    Name        Type       Binding          Description    Stage
    ----------  ---------  ---------------  -------------  -------
    SNMP_ACL    CTRLPLANE  SNMP             SNMP_TO_SSH    egress
    """
    json_namespace = '' if namespace is None else '/' + namespace
    if protocol == 'SSH':
        table_name = "SSH_ONLY"
        json_patch = [
            {
                "op": "replace",
                "path": "{}/ACL_TABLE/{}/stage".format(json_namespace, table_name),
                "value": "egress"
            },
            {
                "op": "replace",
                "path": "{}/ACL_TABLE/{}/services/0".format(json_namespace, table_name),
                "value": "NTP"
            },
            {
                "op": "replace",
                "path": "{}/ACL_TABLE/{}/policy_desc".format(json_namespace, table_name),
                "value": "{}_TO_NTP".format(protocol)
            }
        ]
    else:
        table_name = "{}_ACL".format(protocol)
        json_patch = [
            {
                "op": "replace",
                "path": "{}/ACL_TABLE/{}/stage".format(json_namespace, table_name),
                "value": "egress"
            },
            {
                "op": "replace",
                "path": "{}/ACL_TABLE/{}/services/0".format(json_namespace, table_name),
                "value": "SSH"
            },
            {
                "op": "replace",
                "path": "{}/ACL_TABLE/{}/policy_desc".format(json_namespace, table_name),
                "value": "{}_TO_SSH".format(protocol)
            }
        ]

    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if protocol == 'SSH':
            expected_content_list = [table_name, "CTRLPLANE", "NTP",
                                     "{}_TO_NTP".format(protocol), "egress"]
        else:
            expected_content_list = [table_name, "CTRLPLANE", "SSH",
                                     "{}_TO_SSH".format(protocol), "egress"]
        expect_acl_table_match(duthost, table_name, expected_content_list, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc1_add_invalid_table(duthost, protocol, namespace=None):
    """ Add invalid acl table

    {"service": "SSH", "stage": "ogress", "type": "CTRLPLANE"}, # wrong stage
    {"service": "SSH", "stage": "ingress", "type": "TRLPLANE"}  # wrong type
    """
    invalid_table = [
        {"service": protocol, "stage": "ogress", "type": "CTRLPLANE"},
        {"service": protocol, "stage": "ingress", "type": "TRLPLANE"}
    ]
    json_namespace = '' if namespace is None else '/' + namespace
    for ele in invalid_table:
        json_patch = [
            {
                "op": "add",
                "path": "{}/ACL_TABLE/TEST_2".format(json_namespace),
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
        json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_failure(output)
        finally:
            delete_tmpfile(duthost, tmpfile)


def cacl_tc1_remove_unexisted_table(duthost, namespace=None):
    """ Remove unexisted acl table
    """
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/ACL_RULE/SSH_ONLY_UNEXISTED".format(json_namespace)
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


def cacl_tc1_remove_table(duthost, protocol, namespace=None):
    """ Remove acl table test
    """
    if protocol == 'SSH':
        table_name = "SSH_ONLY"
    else:
        table_name = "{}_ACL".format(protocol)
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/ACL_TABLE/{}".format(json_namespace, table_name)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_table_match(duthost, table_name, [], namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_add_init_rule(duthost, protocol, namespace=None):
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
    params_dict = {}

    if protocol == 'SSH':
        params_dict["table"] = "SSH_ONLY"
        params_dict["IP_PROTOCOL"] = "6"
        params_dict["L4_DST_PORT"] = "22"
    elif protocol == 'SNMP':
        params_dict["table"] = "SNMP_ACL"
        params_dict["IP_PROTOCOL"] = "17"
        params_dict["L4_DST_PORT"] = "161"
    elif protocol == 'NTP':
        params_dict["table"] = "NTP_ACL"
        params_dict["IP_PROTOCOL"] = "17"
        params_dict["L4_DST_PORT"] = "123"
    elif protocol == 'EXTERNAL_CLIENT':
        params_dict["table"] = "EXTERNAL_CLIENT_ACL"
        params_dict["IP_PROTOCOL"] = "6"
        params_dict["L4_DST_PORT"] = "8081"
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/ACL_RULE".format(json_namespace),
            "value": {
                "{}|TEST_DROP".format(params_dict["table"]): {
                    "IP_PROTOCOL": "{}".format(params_dict["IP_PROTOCOL"]),
                    "L4_DST_PORT": "{}".format(params_dict["L4_DST_PORT"]),
                    "IP_TYPE": "IP",
                    "PACKET_ACTION": "DROP",
                    "PRIORITY": "9998",
                    "SRC_IP": "9.9.9.9/32"
                }
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if protocol == 'SSH':
            expected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 22 -j DROP"]
        if protocol == 'NTP':
            expected_content_list = ["-A INPUT -s 9.9.9.9/32 -p udp -m udp --dport 123 -j DROP"]
        elif protocol == 'SNMP':
            expected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 161 -j DROP",
                                     "-A INPUT -s 9.9.9.9/32 -p udp -m udp --dport 161 -j DROP"]
        elif protocol == 'EXTERNAL_CLIENT':
            expected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 8081 -j DROP"]
        expect_res_success_acl_rule(duthost, expected_content_list, [], namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_add_duplicate_rule(duthost, protocol, namespace=None):
    """ Add duplicate acl rule for test
    """
    params_dict = {}

    if protocol == 'SSH':
        params_dict["table"] = "SSH_ONLY"
        params_dict["IP_PROTOCOL"] = "6"
        params_dict["L4_DST_PORT"] = "22"
    elif protocol == 'SNMP':
        params_dict["table"] = "SNMP_ACL"
        params_dict["IP_PROTOCOL"] = "17"
        params_dict["L4_DST_PORT"] = "161"
    elif protocol == 'NTP':
        params_dict["table"] = "NTP_ACL"
        params_dict["IP_PROTOCOL"] = "6"
        params_dict["L4_DST_PORT"] = "123"
    elif protocol == 'EXTERNAL_CLIENT':
        params_dict["table"] = "EXTERNAL_CLIENT_ACL"
        params_dict["IP_PROTOCOL"] = "6"
        params_dict["L4_DST_PORT"] = "8081"
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/ACL_RULE".format(json_namespace),
            "value": {
                "{}|TEST_DROP".format(params_dict["table"]): {
                    "IP_PROTOCOL": "{}".format(params_dict["IP_PROTOCOL"]),
                    "L4_DST_PORT": "{}".format(params_dict["L4_DST_PORT"]),
                    "IP_TYPE": "IP",
                    "PACKET_ACTION": "DROP",
                    "PRIORITY": "9998",
                    "SRC_IP": "9.9.9.9/32"
                }
            }
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


def cacl_tc2_replace_rule(duthost, protocol, namespace=None):
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
    if protocol == 'SSH':
        table = 'SSH_ONLY'
    elif protocol == 'SNMP':
        table = 'SNMP_ACL'
    elif protocol == 'NTP':
        table = 'NTP_ACL'
    elif protocol == 'EXTERNAL_CLIENT':
        table = 'EXTERNAL_CLIENT_ACL'
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "replace",
            "path": "{}/ACL_RULE/{}|TEST_DROP/SRC_IP".format(json_namespace, table),
            "value": "8.8.8.8/32"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if protocol == 'SSH':
            expected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j DROP"]
            unexpected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 22 -j DROP"]
        if protocol == 'NTP':
            expected_content_list = ["-A INPUT -s 8.8.8.8/32 -p udp -m udp --dport 123 -j DROP"]
            unexpected_content_list = ["-A INPUT -s 9.9.9.9/32 -p udp -m udp --dport 123 -j DROP"]
        elif protocol == 'SNMP':
            expected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 161 -j DROP",
                                     "-A INPUT -s 8.8.8.8/32 -p udp -m udp --dport 161 -j DROP"]
            unexpected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 161 -j DROP",
                                       "-A INPUT -s 9.9.9.9/32 -p udp -m udp --dport 161 -j DROP"]
        elif protocol == 'EXTERNAL_CLIENT':
            expected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 8081 -j DROP"]
            unexpected_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 8081 -j DROP"]
        expect_res_success_acl_rule(duthost, expected_content_list, unexpected_content_list, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_add_rule_to_unexisted_table(duthost, namespace=None):
    """ Add acl rule to unexisted table
    """
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/ACL_RULE/TEST_2|TEST_DROP".format(json_namespace),
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
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc2_remove_table_before_rule(duthost, protocol, namespace=None):
    """ Remove acl table before removing acl rule
    """
    if protocol == 'SSH':
        table = 'SSH_ONLY'
    elif protocol == 'SNMP':
        table = 'SNMP_ACL'
    elif protocol == 'NTP':
        table = 'NTP_ACL'
    elif protocol == 'EXTERNAL_CLIENT':
        table = 'EXTERNAL_CLIENT_ACL'
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/ACL_TABLE/{}".format(json_namespace, table)
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


def cacl_tc2_remove_unexist_rule(duthost, protocol, namespace=None):
    """ Remove unexisted acl rule
    """
    if protocol == 'SSH':
        table = 'SSH_ONLY'
    elif protocol == 'SNMP':
        table = 'SNMP_ACL'
    elif protocol == 'NTP':
        table = 'NTP_ACL'
    elif protocol == 'EXTERNAL_CLIENT':
        table = 'EXTERNAL_CLIENT_ACL'
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/ACL_RULE/{}|TEST_DROP2".format(json_namespace, table)
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


def cacl_tc2_remove_rule(duthost, namespace=None):
    """ Remove acl rule test
    """
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/ACL_RULE".format(json_namespace)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        unexpected_content_list = ["-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 22 -j DROP",
                                   "-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 161 -j DROP",
                                   "-A INPUT -s 8.8.8.8/32 -p udp -m udp --dport 161 -j DROP",
                                   "-A INPUT -s 8.8.8.8/32 -p tcp -m udp --dport 123 -j DROP",
                                   "-A INPUT -s 8.8.8.8/32 -p tcp -m tcp --dport 8081 -j DROP"]
        expect_res_success_acl_rule(duthost, [], unexpected_content_list, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_external_client_add_new_table(duthost, namespace=None):
    """ Add acl table for test
    Sample output
    admin@vlab-01:~$ show acl table
    Name                    Type       Binding          Description                   Stage    Status
    ----------------------  ---------  ---------------  ----------------------------  -------  --------
    EXTERNAL_CLIENT_ACL     CTRLPLANE  EXTERNAL_CLIENT  EXTERNAL_CLIENT_ACL           ingress  Active
    """
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/ACL_TABLE/EXTERNAL_CLIENT_ACL".format(json_namespace),
            "value": {
                "policy_desc": "EXTERNAL_CLIENT_ACL",
                "services": [
                    "EXTERNAL_CLIENT"
                ],
                "stage": "ingress",
                "type": "CTRLPLANE"
            }
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["EXTERNAL_CLIENT_ACL", "CTRLPLANE", "EXTERNAL_CLIENT",
                                 "EXTERNAL_CLIENT_ACL", "ingress"]
        expect_acl_table_match(duthost, "EXTERNAL_CLIENT_ACL", expected_content_list, namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)


def cacl_tc3_acl_table_and_acl_rule(duthost):
    """ Add acl table and acl rule in single patch for test
    """
    json_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/EXTERNAL_CLIENT_ACL",
            "value": {
                "type": "CTRLPLANE",
                "stage": "ingress",
                "policy_desc": "EXTERNAL_CLIENT_ACL",
                "services": [
                    "EXTERNAL_CLIENT"
                ]
            }
        },
        {
            "op": "add",
            "path": "/ACL_RULE",
            "value": {
                "EXTERNAL_CLIENT_ACL|RULE_1": {
                    "PRIORITY": "9999",
                    "SRC_IP": "9.9.9.9/32",
                    "IP_PROTOCOL": "6",
                    "PACKET_ACTION": "DROP",
                    "L4_DST_PORT": "8081"
                }
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_table_content_list = ["EXTERNAL_CLIENT_ACL", "CTRLPLANE", "EXTERNAL_CLIENT",
                                       "EXTERNAL_CLIENT_ACL", "ingress"]
        expect_acl_table_match(duthost, "EXTERNAL_CLIENT_ACL", expected_table_content_list)
        expected_rule_content_list = ["-A INPUT -s 9.9.9.9/32 -p tcp -m tcp --dport 8081 -j DROP"]
        expect_res_success_acl_rule(duthost, expected_rule_content_list, [])
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.fixture(scope="module", params=["SSH", "NTP", "SNMP", "EXTERNAL_CLIENT"])
def cacl_protocol(request):       # noqa F811
    """
    Return the protocol to be tested
    """
    return request.param


def test_cacl_tc1_acl_table_suite(cacl_protocol, rand_selected_dut, rand_front_end_asic_namespace):
    namespace, _asic_id = rand_front_end_asic_namespace
    logger.info("Test acl table for protocol {}".format(cacl_protocol))
    cacl_tc1_add_new_table(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc1_add_duplicate_table(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc1_replace_table_variable(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc1_add_invalid_table(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc1_remove_unexisted_table(rand_selected_dut, namespace)
    cacl_tc1_remove_table(rand_selected_dut, cacl_protocol, namespace)


# ACL_RULE tests are related. So group them into one test.
def test_cacl_tc2_acl_rule_test(cacl_protocol, rand_selected_dut, rand_front_end_asic_namespace):
    namespace, _asic_id = rand_front_end_asic_namespace
    logger.info("Test acl table for protocol {}".format(cacl_protocol))
    if cacl_protocol == 'EXTERNAL_CLIENT':
<<<<<<< HEAD
        cacl_external_client_add_new_table(rand_selected_dut, namespace)
    cacl_tc2_add_init_rule(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc2_add_duplicate_rule(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc2_replace_rule(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc2_add_rule_to_unexisted_table(rand_selected_dut, namespace)
    cacl_tc2_remove_table_before_rule(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc2_remove_unexist_rule(rand_selected_dut, cacl_protocol, namespace)
    cacl_tc2_remove_rule(rand_selected_dut, namespace)
=======
        cacl_external_client_add_new_table(rand_selected_dut)
    cacl_tc2_add_init_rule(rand_selected_dut, cacl_protocol)
    cacl_tc2_add_duplicate_rule(rand_selected_dut, cacl_protocol)
    cacl_tc2_replace_rule(rand_selected_dut, cacl_protocol)
    cacl_tc2_add_rule_to_unexisted_table(rand_selected_dut)
    cacl_tc2_remove_table_before_rule(rand_selected_dut, cacl_protocol)
    cacl_tc2_remove_unexist_rule(rand_selected_dut, cacl_protocol)
    cacl_tc2_remove_rule(rand_selected_dut)


def test_cacl_tc3_acl_all(rand_selected_dut):
    cacl_tc3_acl_table_and_acl_rule(rand_selected_dut)
>>>>>>> origin/master
