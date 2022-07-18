import datetime
import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_failure, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

NTP_CONF         = "/etc/ntp.conf"
NTP_SERVER_INIT  = "10.0.0.1"
NTP_SERVER_DUMMY = "10.0.0.2"
NTP_SERVER_RE    = "server {} iburst"

@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for ntp server config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    init_ntp_servers = running_ntp_servers(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

        cur_ntp_servers = running_ntp_servers(duthost)
        pytest_assert(cur_ntp_servers == init_ntp_servers,
            "ntp servers {} do not match {}.".format(cur_ntp_servers, init_ntp_servers)
        )
    finally:
        delete_checkpoint(duthost)


def running_ntp_servers(duthost):
    """ Ger running ntp servers
    """
    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']
    ntp_servers = config_facts.get('NTP_SERVER', {})
    return ntp_servers


def ntp_server_test_setup(duthost):
    """ Clean up ntp server before test
    """
    ntp_servers = running_ntp_servers(duthost)
    for ntp_server in ntp_servers:
        duthost.command("config ntp del %s" % ntp_server)


def server_exist_in_conf(duthost, server_pattern):
    """ Check if ntp server take effect in ntp.conf
    """
    content = duthost.command("cat {}".format(NTP_CONF))
    for line in content['stdout_lines']:
        if re.search(server_pattern, line):
            return True
    return False


def ntp_service_restarted(duthost, start_time):
    """ Check if ntp.service is just restarted after start_time
    """
    output = duthost.shell("systemctl show ntp.service --property ActiveState --value")
    if output["stdout"] != "active":
        return False
    output = duthost.shell("ps -o etimes -p $(systemctl show ntp.service --property ExecMainPID --value) | sed '1d'")
    if int(output['stdout'].strip()) < (datetime.datetime.now() - start_time).seconds:
        return True
    return False


def ntp_server_tc1_add_config(duthost):
    """ Test to add NTP_SERVER config
    """
    json_patch = [
        {
            "op": "add",
            "path": "/NTP_SERVER",
            "value": {
                NTP_SERVER_INIT: {}
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        start_time = datetime.datetime.now()
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(
            ntp_service_restarted(duthost, start_time),
            "ntp.service is not restarted after change"
        )
        pytest_assert(
            server_exist_in_conf(duthost, NTP_SERVER_RE.format(NTP_SERVER_INIT)),
            "Failed to add {} in {}".format(NTP_SERVER_INIT, NTP_CONF)
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def ntp_server_tc1_xfail(duthost):
    """ Test input with invalid ntp server

    Note: Add invalid server cannot be tested. sonic-ntp accpet patterns
    matching inet:host. It could be either inet:ip-address or
    inet:domain-name. Invalid ip such as 256.256.256.256 can pass YANG's
    domain-name regex pattern.
    """
    xfail_input = [
        # ("add", "10.0.0.256"),       # Add invalid server
        ("remove", NTP_SERVER_DUMMY),  # Remove unexisted ntp server
    ]
    for op, ntp_server in xfail_input:
        json_patch = [
            {
                "op": op,
                "path": "/NTP_SERVER/{}".format(ntp_server),
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


def ntp_server_tc1_replace(duthost):
    """ Test to replace ntp server
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/NTP_SERVER/{}".format(NTP_SERVER_INIT)
        },
        {
            "op": "add",
            "path": "/NTP_SERVER/{}".format(NTP_SERVER_DUMMY),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        start_time = datetime.datetime.now()
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(
            ntp_service_restarted(duthost, start_time),
            "ntp.service is not restarted after change"
        )
        pytest_assert(
            not server_exist_in_conf(duthost, NTP_SERVER_RE.format(NTP_SERVER_INIT)) and
            server_exist_in_conf(duthost, NTP_SERVER_RE.format(NTP_SERVER_DUMMY)),
            "Failed to replace ntp server."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def ntp_server_tc1_remove(duthost):
    """ Test to remove ntp server
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/NTP_SERVER"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        start_time = datetime.datetime.now()
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(
            ntp_service_restarted(duthost, start_time),
            "ntp.service is not restarted after change"
        )
        pytest_assert(
            not server_exist_in_conf(duthost, NTP_SERVER_RE.format(NTP_SERVER_DUMMY)),
            "Failed to remove ntp server."
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def test_ntp_server_tc1_suite(rand_selected_dut):
    """ Test suite for ntp server
    """

    ntp_server_test_setup(rand_selected_dut)
    ntp_server_tc1_add_config(rand_selected_dut)
    ntp_server_tc1_xfail(rand_selected_dut)
    ntp_server_tc1_replace(rand_selected_dut)
    ntp_server_tc1_remove(rand_selected_dut)
