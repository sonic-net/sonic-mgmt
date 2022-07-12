import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

AAA_CATEGORY = ["authentication", "authorization", "accounting"]
DEFAULT_TACACS_SERVER = "100.127.20.21"
TACACS_ADD_CONFIG = {
    "auth_type": "login",
    "passkey": "testing123",
    "timeout": "10"
}
TACACS_SERVER_OPTION = {
    "auth_type": "login",
    "passkey": "testing123",
    "priority": "10",
    "tcp_port": "50",
    "timeout": "10"
}


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for each loopback interface test.
    rollback to check if it goes back to starting config

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


def get_aaa_sub_options_value(duthost, aaa_type, option):
    """ Verify if AAA sub type's options match with expected value

    Sample output:
    admin@vlab-01:~$ show aaa | grep -Po "AAA authentication login \K.*"
    local (default)
    """
    output = duthost.shell('show aaa | grep -Po "AAA {} {} \K.*"'.format(aaa_type, option))

    pytest_assert(not output['rc'],
        "Failed to grep AAA {}".format(option)
    )
    return output['stdout']


def aaa_add_init_config_without_table(duthost):
    """ Add initial config not containing AAA table

    Configure to default setting which doesn't contain AAA table
    Sample configDB without table:
    admin@vlab-01:~$ show run all | grep AAA
    admin@vlab-01:~$
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "AAA|*" | xargs -r sonic-db-cli CONFIG_DB del'

    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "AAA init config failed"
    )


def get_tacacs_global_type_value(duthost, tacacs_global_type):
    """ Get tacacs global config by type

    Sample output in t0:
    admin@vlab-01:~$ show tacacs | grep -Po "TACPLUS global auth_type \K.*"
    pap (default)
    """
    output = duthost.shell('show tacacs | grep -Po "TACPLUS global {} \K.*"'.format(tacacs_global_type))

    pytest_assert(not output['rc'],
        "Failed to grep TACACS {}".format(tacacs_global_type)
    )
    return output['stdout']


def tacacs_add_init_config_without_table(duthost):
    """ Add initial config not containing tacacs table

    Sample configDB without table:
    admin@vlab-01:~/cacl$ show run all | grep -w TACPLUS
    admin@vlab-01:~$
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "TACPLUS|*" | xargs -r sonic-db-cli CONFIG_DB del'

    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "TACACS init config failed"
    )


def cleanup_tacacs_server(duthost):
    """ Clean up tacacs server
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "TACPLUS_SERVER|*" | xargs -r sonic-db-cli CONFIG_DB del'

    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "Cleanup TACPLUS_SERVER failed"
    )


def parse_tacacs_server(duthost):
    """ Parse tacacs server

    Sample output in kvm t0:
    {u'10.0.0.9': {u'priority': u'1', u'tcp_port': u'49'}, 
    u'10.0.0.8': {u'priority': u'1', u'tcp_port': u'49'}}
    """
    output = duthost.shell("show tacacs")
    pytest_assert(not output['rc'])
    lines = output['stdout']

    tacacs_servers = {}
    tacacs_server = {}
    address = ""
    tacacs_server_found = False

    for line in lines.splitlines():

        if line.startswith("TACPLUS_SERVER"):
            address = line.split(" ")[-1]
            tacacs_server_found = True
        else:
            if not tacacs_server_found:
                continue

            if not line:
                tacacs_servers[address] = tacacs_server
                tacacs_server = {}
                address = ""
            else:
                fields = line.strip().split(" ")
                pytest_assert(len(fields) == 2)
                k, v = fields[0], fields[1]
                tacacs_server[k] = v

    if address:
        tacacs_servers[address] = tacacs_server

    return tacacs_servers


def aaa_tc1_add_config(duthost):
    """ Test AAA add initial config for its sub type
    """
    aaa_config = {
        "accounting": {
            "login": "tacacs+,local"
        },
        "authentication": {
            "debug": "True",
            "failthrough": "True",
            "fallback": "True",
            "login": "tacacs+",
            "trace": "True"
        },
        "authorization": {
            "login": "tacacs+,local"
        }
    }

    json_patch = [
        {
            "op": "add",
            "path": "/AAA",
            "value": aaa_config
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for aaa_type, aaa_sub_options in aaa_config.items():
            for option, value in aaa_sub_options.items():
                pytest_assert(
                    get_aaa_sub_options_value(duthost, aaa_type, option) == value,
                    "Failed to verify AAA {} {}".format(aaa_type, option)
                )
    finally:
        delete_tmpfile(duthost, tmpfile)


def aaa_tc1_replace(duthost):
    """ Test replace option value in each AAA sub type
    """
    json_patch = [
        {
            "op": "replace",
            "path": "/AAA/authorization/login",
            "value": "tacacs+"
        },
        {
            "op": "replace",
            "path": "/AAA/authentication/login",
            "value": "tacacs+"
        },
        {
            "op": "replace",
            "path": "/AAA/accounting/login",
            "value": "tacacs+"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for aaa_type in AAA_CATEGORY:
            pytest_assert(
                get_aaa_sub_options_value(duthost, aaa_type, "login") == "tacacs+",
                "Failed to verify AAA {} {}".format(aaa_type, "login")
            )
    finally:
        delete_tmpfile(duthost, tmpfile)


def aaa_tc1_add_duplicate(duthost):
    """ Test add duplicate config in AAA sub type
    """
    json_patch = [
        {
            "op": "add",
            "path": "/AAA/authorization/login",
            "value": "tacacs+"
        },
        {
            "op": "add",
            "path": "/AAA/authentication/login",
            "value": "tacacs+"
        },
        {
            "op": "add",
            "path": "/AAA/accounting/login",
            "value": "tacacs+"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for aaa_type in AAA_CATEGORY:
            pytest_assert(
                get_aaa_sub_options_value(duthost, aaa_type, "login") == "tacacs+",
                "Failed to verify AAA {} {}".format(aaa_type, "login")
            )
    finally:
        delete_tmpfile(duthost, tmpfile)


def aaa_tc1_remove(duthost):
    """ Test remove AAA config check if it returns to default setup
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/AAA"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        output = duthost.shell('show aaa')
        pytest_assert(not output['rc'],
            "AAA show command failed"
        )

        for line in output['stdout'].splitlines():
            logger.info(line)
            pytest_assert(line.endswith("(default)"),
                "AAA config deletion failed!"
            )
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_tc1_aaa_suite(rand_selected_dut):
    """ This test is for default setting when configDB doesn't
        contian AAA table. So we remove AAA config at first.
    """
    aaa_add_init_config_without_table(rand_selected_dut)
    aaa_tc1_add_config(rand_selected_dut)
    aaa_tc1_replace(rand_selected_dut)
    aaa_tc1_add_duplicate(rand_selected_dut)
    aaa_tc1_remove(rand_selected_dut)


def tacacs_global_tc2_add_config(duthost):
    """ Test add tacacs global config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS",
            "value": {
                "global": TACACS_ADD_CONFIG
            }
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for tacacs_global_type, value in TACACS_ADD_CONFIG.items():
            pytest_assert(
                get_tacacs_global_type_value(duthost, tacacs_global_type) == value,
                "TACACS global {} failed to apply".format(tacacs_global_type)
            )
    finally:
        delete_tmpfile(duthost, tmpfile)


def tacacs_global_tc2_invalid_input(duthost):
    """ Test tacacs global invalid input

    option restriction:
        auth_type:[chap, pap, mschap, login]
        passkey: cannot contain space, "#" and ","
        timeout: range[1, 60]
    """
    xfail_input = [
        ("auth_type", "logout"),
        ("passkey", " 123"),
        ("timeout", "0")
    ]
    for tacacs_global_type, invalid_input in xfail_input:
        json_patch = [
            {
                "op": "add",
                "path": "/TACPLUS",
                "value": {
                    "global": {
                        tacacs_global_type: invalid_input
                    }
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


def tacacs_global_tc2_duplicate_input(duthost):
    """ Test tacacs global duplicate input
    """
    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS",
            "value": {
                "global": TACACS_ADD_CONFIG
            }
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for tacacs_global_type, value in TACACS_ADD_CONFIG.items():
            pytest_assert(
                get_tacacs_global_type_value(duthost, tacacs_global_type) == value,
                "TACACS global {} failed to apply".format(tacacs_global_type)
            )
    finally:
        delete_tmpfile(duthost, tmpfile)


def tacacs_global_tc2_remove(duthost):
    """ Test tacacs global config removal
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/TACPLUS"
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        output = duthost.shell('show tacacs | grep "TACPLUS global"')
        pytest_assert(not output['rc'],
            "AAA show command failed"
        )
        for line in output['stdout'].splitlines():
            pytest_assert(line.endswith("(default)"),
                "AAA config deletion failed!"
            )
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_tc2_tacacs_global_suite(rand_selected_dut):
    """ This test is for default setting when configDB doesn't
        contian TACACS table. So we remove TACACS config at first.
    """
    tacacs_add_init_config_without_table(rand_selected_dut)
    tacacs_global_tc2_add_config(rand_selected_dut)
    tacacs_global_tc2_invalid_input(rand_selected_dut)
    tacacs_global_tc2_duplicate_input(rand_selected_dut)
    tacacs_global_tc2_remove(rand_selected_dut)


def tacacs_server_tc3_add_init(duthost):
    """ Test tacacs server addition
    """
    ip_address, ipv6_address = DEFAULT_TACACS_SERVER, "fc10::21"
    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS_SERVER",
            "value": {
                ip_address:
                    TACACS_SERVER_OPTION,
                ipv6_address:
                    TACACS_SERVER_OPTION
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        tacacs_servers = parse_tacacs_server(duthost)
        pytest_assert(
            ip_address in tacacs_servers and
            ipv6_address in tacacs_servers,
            "tacacs server failed to add to config."
        )
        for tacacs_server in tacacs_servers:
            options = tacacs_servers[tacacs_server]
            for opt, value in TACACS_SERVER_OPTION.items():
                pytest_assert(opt in options and options[opt] == value,
                    "tacacs server failed to add to config completely."
                )
    finally:
        delete_tmpfile(duthost, tmpfile)


def tacacs_server_tc3_add_max(duthost):
    """ Test tacacs server reach maximum 8 servers
    """
    # 2 servers exist. Add another 7 servers to exceed max.
    servers = ["10.0.0.{}".format(i) for i in range(10, 17)]

    json_patch = []
    for server in servers:
        patch = {
            "op": "add",
            "path": "/TACPLUS_SERVER/{}".format(server),
            "value": {}
        }
        json_patch.append(patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)

    finally:
        delete_tmpfile(duthost, tmpfile)


def tacacs_server_tc3_replace_invalid(duthost):
    """ Test invalid input for tacacs server

    valid input restriction:
        auth_type:[chap, pap, mschap, login]
        passkey: cannot contain space, "#" and ","
        priority: range[1, 64]
        tcp_port: [0, 65535]
        timeout: range[1, 60]
    """
    xfail_input = [
        ("auth_type", "logout"),
        ("passkey", " 123"),
        ("priority", "0"),
        ("tcp_port", "65536"),
        ("timeout", "0")
    ]
    for tacacs_server_options, invalid_input in xfail_input:
        json_patch = [
            {
                "op": "replace",
                "path": "/TACPLUS_SERVER",
                "value": {
                    DEFAULT_TACACS_SERVER: {
                        tacacs_server_options: invalid_input
                    }
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

def tacacs_server_tc3_add_duplicate(duthost):
    """ Test tacacs server add duplicate server
    """
    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS_SERVER/{}".format(DEFAULT_TACACS_SERVER),
            "value": TACACS_SERVER_OPTION
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        tacacs_servers = parse_tacacs_server(duthost)
        pytest_assert(DEFAULT_TACACS_SERVER in tacacs_servers,
            "tacacs server add duplicate failed."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)

def tacacs_server_tc3_remove(duthost):
    """ Test tacasc server removal
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/TACPLUS_SERVER"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        tacacs_servers = parse_tacacs_server(duthost)
        pytest_assert(not tacacs_servers,
            "tacacs server failed to remove."
        )
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_tacacs_server_tc3_suite(rand_selected_dut):
    """ Due to kvm t0 and testbed t0 has different tacacs server predefined,
        so we cleanup tacacs servers then test on mannual setup.
    """
    cleanup_tacacs_server(rand_selected_dut)
    tacacs_server_tc3_add_init(rand_selected_dut)
    tacacs_server_tc3_add_max(rand_selected_dut)
    tacacs_server_tc3_replace_invalid(rand_selected_dut)
    tacacs_server_tc3_add_duplicate(rand_selected_dut)
    tacacs_server_tc3_remove(rand_selected_dut)
