import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success_and_reset_check, expect_res_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

SYSLOG_TIMEOUT              = 10
SYSLOG_INTERVAL             = 1
# This is restricted by sonic-syslog.yang. Use '-1' to indicate no max is set
SYSLOG_MAX_SERVER           = -1
# The max server test only support SYSLOG_MAX_SERVER that is equal or lower than 254.
SYSLOG_TEST_MAX_UPPER_LIMIT = 254

@pytest.fixture(scope="module")
def setup_env(duthosts, rand_one_dut_hostname, cfg_facts):
    """
    Setup/teardown fixture for syslog config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
        cfg_facts: config facts for selected DUT
    """
    duthost = duthosts[rand_one_dut_hostname]

    config_tmpfile = generate_tmpfile(duthost)
    logger.info("config_tmpfile {} Backing up config_db.json".format(config_tmpfile))
    duthost.shell("sudo cp /etc/sonic/config_db.json {}".format(config_tmpfile))

    # Cleanup syslog server config
    syslog_servers = cfg_facts.get('SYSLOG_SERVER', {})
    for syslog_server in syslog_servers:
        del_syslog_server = duthost.shell("sudo config syslog del {}".format(syslog_server),
            module_ignore_errors=True)
        pytest_assert(not del_syslog_server['rc'],
            "syslog server '{}' is not deleted successfully".format(syslog_server))

    yield

    logger.info("Restoring config_db.json")
    duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(config_tmpfile))
    delete_tmpfile(duthost, config_tmpfile)
    config_reload(duthost)

def expect_res_success_syslog(duthost, expected_content_list, unexpected_content_list):
    """Check if syslog server show as expected
    """
    cmds = "show runningconfiguration syslog"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' is not running successfully".format(cmds))

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("add", "10.0.0.5", "cc98:2008::1")
])
def test_syslog_server_tc1_add_init(duthost, setup_env, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
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

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success_and_reset_check(duthost, output, 'rsyslog-config', SYSLOG_TIMEOUT, SYSLOG_INTERVAL, 0)

    expected_content_list = ["[{}]".format(dummy_syslog_server_v4), "[{}]".format(dummy_syslog_server_v6)]
    expect_res_success_syslog(duthost, expected_content_list, [])

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("add", "10.0.0.5", "cc98:2008::1")
])
def test_syslog_server_tc2_add_duplicate(duthost, setup_env, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
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

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success_and_reset_check(duthost, output, 'rsyslog-config', SYSLOG_TIMEOUT, SYSLOG_INTERVAL, 0)

    expected_content_list = ["[{}]".format(dummy_syslog_server_v4), "[{}]".format(dummy_syslog_server_v6)]
    expect_res_success_syslog(duthost, expected_content_list, [])

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("add", "10.0.0.587", "cc98:2008::1"),
    ("add", "10.0.0.5", "cc98:2008::xyz"),
    ("remove", "10.0.0.6", "cc98:2008:1"),
    ("remove", "10.0.0.5", "cc98:2008::2")
])
def test_syslog_server_tc3_xfail(duthost, setup_env, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
    """ Test expect fail testcase

    ("add", "10.0.0.587", "cc98:2008::1"), ADD Invalid IPv4 address
    ("add", "10.0.0.5", "cc98:2008::xyz"), ADD Invalid IPv6 address
    ("remove", "10.0.0.6", "cc98:2008:1"), REMOVE Unexist IPv4 address
    ("remove", "10.0.0.5", "cc98:2008::2") REMOVE Unexist IPv6 address
    """
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

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, dummy_syslog_server_v4, dummy_syslog_server_v6", [
    ("remove", "10.0.0.5", "cc98:2008::1")
])
def test_syslog_server_tc4_remove(duthost, setup_env, op,
        dummy_syslog_server_v4, dummy_syslog_server_v6):
    """ Remove v4 and v6 syslog server

    admin@vlab-01:~$ show runningconfiguration syslog
    Sample output:
    Syslog Servers
    ----------------
    """
    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/SYSLOG_SERVER"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success_and_reset_check(duthost, output, 'rsyslog-config', SYSLOG_TIMEOUT, SYSLOG_INTERVAL, 0)

    unexpected_content_list = ["[{}]".format(dummy_syslog_server_v4), "[{}]".format(dummy_syslog_server_v6)]
    expect_res_success_syslog(duthost, [], unexpected_content_list)

    delete_tmpfile(duthost, tmpfile)

def test_syslog_server_tc5_add_to_max(duthost, setup_env):
    """ Test syslog server max

    admin@vlab-01:~$ show runningconfiguration syslog
    Sample output:
    Syslog Servers
    ----------------
    [10.0.0.1]
    ...
    [10.0.0.SYSLOG_MAX_SERVER]
    """
    if SYSLOG_MAX_SERVER == -1 or SYSLOG_MAX_SERVER > SYSLOG_TEST_MAX_UPPER_LIMIT:
        pytest.skip("SYSLOG_MAX_SERVER is not set or is over the test max upper limit")

    syslog_servers = ["10.0.0.{}".format(i) for i in range(1, SYSLOG_MAX_SERVER+1)]

    json_patch = [
        {
            "op": "add",
            "path": "/SYSLOG_SERVER",
            "value": {
                "{}".format(syslog_server) : {} for syslog_server in syslog_servers
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success_and_reset_check(duthost, output, 'rsyslog-config', SYSLOG_TIMEOUT, SYSLOG_INTERVAL, 0)

    status = duthost.get_service_props('rsyslog-config')["ActiveState"]
    logger.info("rsyslog-config status {}".format(status))
    pytest_assert(
        duthost.get_service_props('rsyslog-config')["ActiveState"] == "active",
        "rsyslog-config service is not active"
    )

    expected_content_list = ["[{}]".format(syslog_server) for syslog_server in syslog_servers]
    expect_res_success_syslog(duthost, expected_content_list, [])

    delete_tmpfile(duthost, tmpfile)

def test_syslog_server_tc6_exceed_max(duthost, setup_env):
    """ Exceed syslog server maximum test
    """
    if SYSLOG_MAX_SERVER == -1 or SYSLOG_MAX_SERVER > SYSLOG_TEST_MAX_UPPER_LIMIT:
        pytest.skip("SYSLOG_MAX_SERVER is not set or is over the test max upper limit")

    json_patch = [
        {
            "op": "add",
            "path": "/SYSLOG_SERVER/10.0.0.{}".format(SYSLOG_MAX_SERVER+1),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)
