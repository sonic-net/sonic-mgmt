import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.skip(reason="Test costs too much time. Temp skip for now."),
]

logger = logging.getLogger(__name__)

AAA_CATEGORY = ["authentication", "authorization", "accounting"]
DEFAULT_TACACS_SERVER = "100.127.20.21"


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

def aaa_add_init_config_with_table(duthost):
    """ Add initial config containing AAA table

    Though AAA has default value in setup. But the config does not
    included in configDB. So to make change on AAA table, the init
    config need to be added to config first.
    Sample configDB table:
    "AAA": {
        "accounting": {
            "login": "local"
        },
        "authentication": {
            "login": "local"
        },
        "authorization": {
            "login": "local"
        }
    }
    """
    cmds = []
    cmds.append("config aaa authentication login local")
    cmds.append("config aaa authorization local")
    cmds.append("config aaa accounting local")

    output = duthost.shell_cmds(cmds=cmds)['results']
    logger.info(output)
    for res in output:
        pytest_assert(not res['rc'],
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

def tacacs_add_init_config_with_table(duthost):
    """ Add initial config containing tacacs table

    Same with AAA config. The default tacacs config does not
    included in configDB. So to make change, the initial
    config need to be added to config first.
    Sample configDB table:
    "TACPLUS": {
        "global": {
            "auth_type": "pap",
            "passkey": "testing123",
            "timeout": "5"
        }
    }
    """
    cmds = []
    cmds.append("config tacacs authtype pap")
    cmds.append("config tacacs passkey testing123")
    cmds.append("config tacacs timeout 5")

    output = duthost.shell_cmds(cmds=cmds)['results']
    logger.info(output)
    for res in output:
        pytest_assert(not res['rc'],
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

def add_tacacs_server(duthost, server_ip):
    """ tc13 requires at least one existed server to do the removal

    Even the server added is existed, it won't be treated as error.
    Sample output:
    admin@vlab-01:~$ sudo config tacacs add 100.127.20.21
    server 100.127.20.21 already exists
    eadmin@vlab-01:~$ echo $?
    0
    """
    cmds = 'config tacacs add {}'.format(server_ip)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "Add tacacs server failed"
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

@pytest.mark.parametrize("aaa_type, aaa_sub_options", [
    (
        "authentication",
        {
            "debug": "True",
            "failthrough": "True",
            "fallback": "True",
            "login": "tacacs+",
            "trace": "True"
        }
    ),
    (
        "authorization",
        {
            "login": "tacacs+,local"
        }
    ),
    (
        "accounting",
        {
            "login": "tacacs+,local"
        }
    )
])
def test_aaa_tc1_add_config(duthost, aaa_type, aaa_sub_options):
    """ Test AAA add initial config for its sub type

    This test is for default setting when configDB doesn't
    contian AAA table. So we remove AAA config at first.
    """
    aaa_add_init_config_without_table(duthost)
    json_patch = [
        {
            "op": "add",
            "path": "/AAA",
            "value": {
                "{}".format(aaa_type): aaa_sub_options
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for option, value in aaa_sub_options.items():
            pytest_assert(
                get_aaa_sub_options_value(duthost, aaa_type, option) == value,
                "Failed to verify AAA {} {}".format(aaa_type, option)
            )
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_aaa_tc2_replace(duthost):
    """ Test replace option value in each AAA sub type
    """
    aaa_add_init_config_with_table(duthost)
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

def test_aaa_tc3_add_duplicate(duthost):
    """ Test add duplicate config in AAA sub type
    """
    aaa_add_init_config_with_table(duthost)
    json_patch = [
        {
            "op": "add",
            "path": "/AAA/authorization/login",
            "value": "local"
        },
        {
            "op": "add",
            "path": "/AAA/authentication/login",
            "value": "local"
        },
        {
            "op": "add",
            "path": "/AAA/accounting/login",
            "value": "local"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        for aaa_type in AAA_CATEGORY:
            pytest_assert(
                get_aaa_sub_options_value(duthost, aaa_type, "login") == "local",
                "Failed to verify AAA {} {}".format(aaa_type, "login")
            )
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_aaa_tc4_remove(duthost):
    """ Test remove AAA config check if it returns to default setup
    """
    aaa_add_init_config_with_table(duthost)
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
        logger.info("output {}".format(output))
        for line in output['stdout'].splitlines():
            logger.info(line)
            pytest_assert(line.endswith("(default)"),
                "AAA config deletion failed!"
            )
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_tacacs_global_tc5_add_config(duthost):
    """ Test add tacacs global config

    This test is for default setting when configDB doesn't
    contian TACACS table. So we remove TACACS config at first.
    """
    tacacs_add_init_config_without_table(duthost)
    TACACS_ADD_CONFIG = {
        "auth_type": "login",
        "passkey": "testing123",
        "timeout": "10"
    }
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

@pytest.mark.parametrize("tacacs_global_type, invalid_input", [
    ("auth_type", "logout"),
    ("passkey", " 123"), ("passkey", "#123"), ("passkey", ",123"), ("passkey", "1"*66),
    ("timeout", "61"), ("timeout", "0")
])
def test_tacacs_global_tc6_invalid_input(duthost, tacacs_global_type, invalid_input):
    """ Test tacacs global invalid input

    option restriction:
        auth_type:[chap, pap, mschap, login]
        passkey: cannot contain space, "#" and ","
        timeout: range[1, 60]
    """
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

def test_tacacs_global_tc7_duplicate_input(duthost):
    """ Test tacacs global duplicate input
    """
    tacacs_add_init_config_with_table(duthost)

    TACACS_ADD_CONFIG = {
        "auth_type": "pap",
        "passkey": "testing123",
        "timeout": "5"
    }
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

def test_tacacs_global_tc8_remove(duthost):
    """ Test tacacs global config removal
    """
    tacacs_add_init_config_with_table(duthost)

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

@pytest.mark.parametrize("ip_address", ["100.127.20.21", "fc10::21"])
def test_tacacs_server_tc9_add_init(duthost, ip_address):
    """ Test tacacs server addition

    Due to kvm t0 and testbed t0 has different tacacs server predefined,
    so we cleanup tacacs servers then test on mannual setup.
    """
    cleanup_tacacs_server(duthost)

    TACACS_SERVER_OPTION = {
        "auth_type": "login",
        "passkey": "testing123",
        "priority": "10",
        "tcp_port": "50",
        "timeout": "10"
    }
    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS_SERVER",
            "value": {
                ip_address:
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
        pytest_assert(ip_address in tacacs_servers,
            "tacacs server failed to add to config."
        )
        tacacs_server = tacacs_servers[ip_address]
        for opt, value in TACACS_SERVER_OPTION.items():
            pytest_assert(opt in tacacs_server and tacacs_server[opt] == value,
                "tacacs server failed to add to config completely."
            )
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_tacacs_server_tc10_add_max(duthost):
    """ Test tacacs server reach maximum 8 servers
    """
    cleanup_tacacs_server(duthost)

    servers = {}
    for i in range(10, 19): # Add 9 servers
        servers["10.0.0.{}".format(i)] = {}
    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS_SERVER",
            "value": servers
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)

    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("tacacs_server_options, invalid_input", [
    ("auth_type", "logout"),
    ("passkey", " 123"), ("passkey", "#123"), ("passkey", ",123"), ("passkey", "1"*66),
    ("priority", "0"), ("priority", "65"),
    ("tcp_port", "65536"),
    ("timeout", "61"), ("timeout", "0")
])
def test_tacacs_server_tc11_add_invalid(duthost, tacacs_server_options, invalid_input):
    """ Test invalid input for tacacs server

    valid input restriction:
        auth_type:[chap, pap, mschap, login]
        passkey: cannot contain space, "#" and ","
        priority: range[1, 64]
        tcp_port: [0, 65535]
        timeout: range[1, 60]
    """
    cleanup_tacacs_server(duthost)

    json_patch = [
        {
            "op": "add",
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

def test_tacacs_server_tc12_add_duplicate(duthost):
    """ Test tacacs server add duplicate server

    Mannually add DEFAULT_TACACS_SERVER, then add duplicate for test.
    """
    add_tacacs_server(duthost, DEFAULT_TACACS_SERVER)

    json_patch = [
        {
            "op": "add",
            "path": "/TACPLUS_SERVER/{}".format(DEFAULT_TACACS_SERVER),
            "value": {
                "priority": "1",
                "tcp_port": "49"
            }
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

def test_tacacs_server_tc13_remove(duthost):
    """ Test tacasc server removal
    """
    add_tacacs_server(duthost, DEFAULT_TACACS_SERVER)

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
