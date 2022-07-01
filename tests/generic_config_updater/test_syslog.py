import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_res_success, expect_op_failure, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

SYSLOG_DUMMY_IPV4_SERVER = "10.0.0.5"
SYSLOG_DUMMY_IPV6_SERVER = "cc98:2008::1"
REPLACE_SYSLOG_SERVER_v4 = "10.0.0.6"
REPLACE_SYSLOG_SERVER_v6 = "cc98:2008::2"


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
        pytest_assert(
            not del_syslog_server['rc'],
            "syslog server '{}' is not deleted successfully".format(syslog_server)
        )


@pytest.fixture(scope="module")
def original_syslog_servers(rand_selected_dut, tbinfo):
    """A module level fixture to store original syslog servers info
    """
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

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


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname, original_syslog_servers):
    """
    Setup/teardown fixture for syslog config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
        original_syslog_servers: original syslog servers stored in config
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

        current_syslog_servers = get_current_syslog_servers(duthost)
        pytest_assert(
            set(current_syslog_servers) == set(original_syslog_servers),
            "Syslog servers are not rollback_or_reload to initial config setup"
        )
    finally:
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


def syslog_server_tc1_add_init(duthost):
    """ Add v4 and v6 syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.5]
    [cc98:2008::1]
    """
    json_patch = [
        {
            "op": "add",
            "path": "/SYSLOG_SERVER",
            "value": {
                SYSLOG_DUMMY_IPV4_SERVER: {},
                SYSLOG_DUMMY_IPV6_SERVER: {}
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["[{}]".format(SYSLOG_DUMMY_IPV4_SERVER),
                                 "[{}]".format(SYSLOG_DUMMY_IPV6_SERVER)]
        expect_res_success_syslog(duthost, expected_content_list, [])
    finally:
        delete_tmpfile(duthost, tmpfile)


def syslog_server_tc1_add_duplicate(duthost):
    """ Add v4 and v6 duplicate syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.5]
    [cc98:2008::1]
    """
    json_patch = [
        {
            "op": "add",
            "path": "/SYSLOG_SERVER/{}".format(SYSLOG_DUMMY_IPV4_SERVER),
            "value": {}
        },
        {
            "op": "add",
            "path": "/SYSLOG_SERVER/{}".format(SYSLOG_DUMMY_IPV6_SERVER),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["[{}]".format(SYSLOG_DUMMY_IPV4_SERVER),
                                 "[{}]".format(SYSLOG_DUMMY_IPV6_SERVER)]
        expect_res_success_syslog(duthost, expected_content_list, [])
    finally:
        delete_tmpfile(duthost, tmpfile)


def syslog_server_tc1_xfail(duthost):
    """ Test expect fail testcase

    ("add", "10.0.0.587", "cc98:2008::1"), ADD Invalid IPv4 address
    ("add", "10.0.0.5", "cc98:2008::xyz"), ADD Invalid IPv6 address
    ("remove", "10.0.0.6", "cc98:2008:1"), REMOVE Unexist IPv4 address
    ("remove", "10.0.0.5", "cc98:2008::2") REMOVE Unexist IPv6 address
    """
    xfail_input = [
        ("add", "10.0.0.587", "cc98:2008::1"),
        ("add", "10.0.0.5", "cc98:2008::xyz"),
        ("remove", "10.0.0.6", "cc98:2008:1"),
        ("remove", "10.0.0.5", "cc98:2008::2")
    ]

    for op, dummy_syslog_server_v4, dummy_syslog_server_v6 in xfail_input:
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


def syslog_server_tc1_replace(duthost):
    """ replace v4 and v6 syslog server to config

    Sample output
    admin@vlab-01:~$ show runningconfiguration syslog
    Syslog Servers
    ----------------
    [10.0.0.6]
    [cc98:2008::2]
    """
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
            "op": "add",
            "path": "/SYSLOG_SERVER/{}".format(REPLACE_SYSLOG_SERVER_v4),
            "value": {}
        },
        {
            "op": "add",
            "path": "/SYSLOG_SERVER/{}".format(REPLACE_SYSLOG_SERVER_v6),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expected_content_list = ["[{}]".format(REPLACE_SYSLOG_SERVER_v4),
                                 "[{}]".format(REPLACE_SYSLOG_SERVER_v6)]
        unexpected_content_list = ["[{}]".format(SYSLOG_DUMMY_IPV4_SERVER),
                                   "[{}]".format(SYSLOG_DUMMY_IPV6_SERVER)]
        expect_res_success_syslog(duthost, expected_content_list, unexpected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)


def syslog_server_tc1_remove(duthost):
    """ Remove v4 and v6 syslog server

    admin@vlab-01:~$ show runningconfiguration syslog
    Sample output:
    Syslog Servers
    ----------------
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/SYSLOG_SERVER"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        unexpected_content_list = ["[{}]".format(REPLACE_SYSLOG_SERVER_v4),
                                   "[{}]".format(REPLACE_SYSLOG_SERVER_v6)]
        expect_res_success_syslog(duthost, [], unexpected_content_list)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_syslog_server_tc1_suite(rand_selected_dut, cfg_facts):
    """ Test syslog server config from clean config
    """
    syslog_config_cleanup(rand_selected_dut, cfg_facts)
    syslog_server_tc1_add_init(rand_selected_dut)
    syslog_server_tc1_add_duplicate(rand_selected_dut)
    syslog_server_tc1_xfail(rand_selected_dut)
    syslog_server_tc1_replace(rand_selected_dut)
    syslog_server_tc1_remove(rand_selected_dut)

