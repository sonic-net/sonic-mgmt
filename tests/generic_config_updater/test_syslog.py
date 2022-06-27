import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_res_success, expect_op_failure, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload, rollback

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.skip(reason="Test costs too much time. Temp skip for now."),
]

logger = logging.getLogger(__name__)

SYSLOG_DUMMY_IPV4_SERVER    = "10.0.0.5"
SYSLOG_DUMMY_IPV6_SERVER    = "cc98:2008::1"
SETUP_ENV_CP                = "test_setup_checkpoint"
CONFIG_CLEANUP              = "config_cleanup"
CONFIG_ADD_DEFAULT          = "config_add_default"


@pytest.fixture(scope="module", params=[CONFIG_CLEANUP, CONFIG_ADD_DEFAULT])
def init_syslog_config(request):
    return request.param

def syslog_config_cleanup(duthost, cfg_facts):
    """ Cleanup syslog server

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    """
    syslog_servers = cfg_facts.get('SYSLOG_SERVER', {})
    for syslog_server in syslog_servers:
        del_syslog_server = duthost.shell("config syslog del {}".format(syslog_server),
            module_ignore_errors=True)
        pytest_assert(not del_syslog_server['rc'],
            "syslog server '{}' is not deleted successfully".format(syslog_server))


def syslog_config_add_default(duthost):
    """ Add default v4 and v6 syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.5]
    [cc98:2008::1]
    """
    for syslog_server in [SYSLOG_DUMMY_IPV4_SERVER, SYSLOG_DUMMY_IPV6_SERVER]:
        add_syslog_server = duthost.shell("config syslog add {}".format(syslog_server),
            module_ignore_errors=True)
        pytest_assert(not add_syslog_server['rc'],
            "syslog server '{}' is not added successfully".format(syslog_server))

@pytest.fixture(scope="module")
def original_syslog_servers(duthost, tbinfo):
    """A module level fixture to store original syslog servers info
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    original_syslog_servers = []
    for syslog_server in mg_facts['syslog_servers']:
        original_syslog_servers.append(syslog_server)

    return original_syslog_servers

def get_current_syslog_servers(duthost):
    """Get current syslog servers from running host
    """
    cmds = "show runningconfiguration syslog"
    output = duthost.shell(cmds)

    pytest_assert(not output['rc'],
        "'{}' is not running successfully".format(cmds)
    )

    # If len less than 3 means not syslog output
    lines = output['stdout'].splitlines()
    if len(lines) < 3:
        return []
    # Jump over introductory printout
    current_syslog_servers = []
    for line in lines[2:]:
        # remove enclosed sqaure bracket
        current_syslog_servers.append(line[1:-1])
    return current_syslog_servers

def check_syslog_after_rollback(duthost, output, init_syslog_config):
    pytest_assert(
        not output['rc'] and "Config rolled back successfull" in output['stdout'],
        "Rollback to previous setup env failed."
    )
    if init_syslog_config == CONFIG_CLEANUP:
        pytest_assert(not get_current_syslog_servers(duthost),
            "Failed to rollback to {}".format(init_syslog_config)
        )
    elif init_syslog_config == CONFIG_ADD_DEFAULT:
        pytest_assert(
            set(get_current_syslog_servers(duthost)) == set([SYSLOG_DUMMY_IPV4_SERVER, SYSLOG_DUMMY_IPV6_SERVER]),
            "Failed to rollback to {}".format(init_syslog_config)
        )

@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname, cfg_facts, init_syslog_config, original_syslog_servers):
    """
    Setup/teardown fixture for syslog config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
        cfg_facts: config facts for selected DUT
        init_syslog_config: set up the initial syslog config for test
        original_syslog_servers: original syslog servers stored in config
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    if init_syslog_config == CONFIG_CLEANUP:
        syslog_config_cleanup(duthost, cfg_facts)
    elif init_syslog_config == CONFIG_ADD_DEFAULT:
        syslog_config_cleanup(duthost, cfg_facts)
        syslog_config_add_default(duthost)
    else:
        pytest.fail("Not supported initial syslog config: {}".format(init_syslog_config))

    create_checkpoint(duthost, SETUP_ENV_CP)

    yield

    # Rollback twice. First rollback to checkpoint just before 'yield'
    # Second rollback is to back to original setup
    try:
        output = rollback(duthost, SETUP_ENV_CP)
        check_syslog_after_rollback(duthost, output, init_syslog_config)

        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

        current_syslog_servers = get_current_syslog_servers(duthost)
        pytest_assert(set(current_syslog_servers) == set(original_syslog_servers),
            "Syslog servers are not rollback_or_reload to initial config setup"
        )
    finally:
        delete_checkpoint(duthost, SETUP_ENV_CP)
        delete_checkpoint(duthost)

def expect_res_success_syslog(duthost, expected_content_list, unexpected_content_list):
    """Check if syslog server show as expected
    """
    cmds = "show runningconfiguration syslog"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'],
        "'{}' is not running successfully".format(cmds)
    )

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("add", SYSLOG_DUMMY_IPV4_SERVER, SYSLOG_DUMMY_IPV6_SERVER)
])
def test_syslog_server_tc1_add_init(duthost, init_syslog_config, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
    """ Add v4 and v6 syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.5]
    [cc98:2008::1]
    """
    if init_syslog_config != CONFIG_CLEANUP:
        pytest.skip("Unsupported initial config")

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER",
            "value": {
                "{}".format(dummy_syslog_server_v4): {},
                "{}".format(dummy_syslog_server_v6): {}
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["[{}]".format(dummy_syslog_server_v4), "[{}]".format(dummy_syslog_server_v6)]
        expect_res_success_syslog(duthost, expected_content_list, [])
    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("add", SYSLOG_DUMMY_IPV4_SERVER, SYSLOG_DUMMY_IPV6_SERVER)
])
def test_syslog_server_tc2_add_duplicate(duthost, init_syslog_config, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
    """ Add v4 and v6 duplicate syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.5]
    [cc98:2008::1]
    """
    if init_syslog_config != CONFIG_ADD_DEFAULT:
        pytest.skip("Unsupported initial config")

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER/{}".format(dummy_syslog_server_v4),
            "value": {}
        },
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER/{}".format(dummy_syslog_server_v6),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["[{}]".format(dummy_syslog_server_v4), "[{}]".format(dummy_syslog_server_v6)]
        expect_res_success_syslog(duthost, expected_content_list, [])
    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("add", "10.0.0.587", "cc98:2008::1"),
    ("add", "10.0.0.5", "cc98:2008::xyz"),
    ("remove", "10.0.0.6", "cc98:2008:1"),
    ("remove", "10.0.0.5", "cc98:2008::2")
])
def test_syslog_server_tc3_xfail(duthost, init_syslog_config, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
    """ Test expect fail testcase

    ("add", "10.0.0.587", "cc98:2008::1"), ADD Invalid IPv4 address
    ("add", "10.0.0.5", "cc98:2008::xyz"), ADD Invalid IPv6 address
    ("remove", "10.0.0.6", "cc98:2008:1"), REMOVE Unexist IPv4 address
    ("remove", "10.0.0.5", "cc98:2008::2") REMOVE Unexist IPv6 address
    """
    if init_syslog_config != CONFIG_ADD_DEFAULT:
        pytest.skip("Unsupported initial config")

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER/{}".format(dummy_syslog_server_v4),
            "value": {}
        },
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER/{}".format(dummy_syslog_server_v6),
            "value": {}
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("remove", SYSLOG_DUMMY_IPV4_SERVER, SYSLOG_DUMMY_IPV6_SERVER)
])
def test_syslog_server_tc4_remove(duthost, init_syslog_config, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
    """ Remove v4 and v6 syslog server

    admin@vlab-01:~$ show runningconfiguration syslog
    Sample output:
    Syslog Servers
    ----------------
    """
    if init_syslog_config != CONFIG_ADD_DEFAULT:
        pytest.skip("Unsupported initial config")

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        unexpected_content_list = ["[{}]".format(dummy_syslog_server_v4), "[{}]".format(dummy_syslog_server_v6)]
        expect_res_success_syslog(duthost, [], unexpected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, replace_syslog_server_v4, replace_syslog_server_v6", [
    ("add", "10.0.0.6", "cc98:2008::2")
])
def test_syslog_server_tc5_replace(duthost, init_syslog_config, op,
        replace_syslog_server_v4, replace_syslog_server_v6):
    """ Add v4 and v6 duplicate syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.5]
    [cc98:2008::1]
    """
    if init_syslog_config != CONFIG_ADD_DEFAULT:
        pytest.skip("Unsupported initial config")

    json_patch = [
        {
            "op": "remove",
            "path": "/SYSLOG_SERVER/{}".format(SYSLOG_DUMMY_IPV6_SERVER)
        },
        {
            "op": "remove",
            "path": "/SYSLOG_SERVER/{}".format(SYSLOG_DUMMY_IPV4_SERVER)
        },
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER/{}".format(replace_syslog_server_v4),
            "value": {}
        },
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER/{}".format(replace_syslog_server_v6),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["[{}]".format(replace_syslog_server_v4), "[{}]".format(replace_syslog_server_v6)]
        unexpected_content_list = ["[{}]".format(SYSLOG_DUMMY_IPV4_SERVER), "[{}]".format(SYSLOG_DUMMY_IPV6_SERVER)]
        expect_res_success_syslog(duthost, expected_content_list, unexpected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)
