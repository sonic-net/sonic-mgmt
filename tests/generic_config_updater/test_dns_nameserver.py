import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

DNS_SERVER_RE = "nameserver {}"


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):  # noqa: F811
    """
    Setup/teardown fixture for dns nameserver config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    init_dns_nameservers = current_dns_nameservers(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

        cur_dns_nameservers = current_dns_nameservers(duthost)
        pytest_assert(cur_dns_nameservers == init_dns_nameservers,
                      "DNS nameservers {} do not match {}.".format(
                          cur_dns_nameservers, init_dns_nameservers))
    finally:
        delete_checkpoint(duthost)


def current_dns_nameservers(duthost):
    """ Ger running dns nameservers
    """
    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']
    dns_nameservers = config_facts.get('DNS_NAMESERVER', {})
    return dns_nameservers


def dns_nameserver_test_setup(duthost):
    """ Clean up dns nameservers before test
    """
    dns_nameservers = current_dns_nameservers(duthost)
    for dns_nameserver in dns_nameservers:
        duthost.command("config dns nameserver del %s" % dns_nameserver)


def server_exist_in_conf(duthost, server_pattern):
    """ Check if dns nameserver take effect in resolv.conf
    """
    content = duthost.command("cat /etc/resolv.conf")
    for line in content['stdout_lines']:
        if re.search(server_pattern, line):
            return True
    return False


def add_dns_nameserver(duthost, dns_nameserver):
    json_patch = [
        {
            "op": "add",
            "path": f"/DNS_NAMESERVER/{dns_nameserver}",
            "value": {}
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost,
                                                 json_data=json_patch,
                                                 is_host_specific=True)

    json_patch_bc = [
        {
            "op": "remove",
            "path": f"/DNS_NAMESERVER/{dns_nameserver}",
            "value": {}
        }
    ]
    json_patch_bc = format_json_patch_for_multiasic(duthost=duthost,
                                                    json_data=json_patch_bc,
                                                    is_host_specific=True)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if output['rc'] != 0:
            logger.error(f"Failed to apply patch, rolling back: {output['stdout']}")
            apply_patch(duthost, json_data=json_patch_bc, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(
            server_exist_in_conf(duthost, DNS_SERVER_RE.format(dns_nameserver)),
            "Failed to add {} in /etc/resolv.conf".format(dns_nameserver)
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def remove_dns_nameserver(duthost, dns_nameserver):
    json_patch = [
        {
            "op": "remove",
            "path": f"/DNS_NAMESERVER/{dns_nameserver}",
            "value": {}
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost,
                                                 json_data=json_patch,
                                                 is_host_specific=True)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        pytest_assert(
            not server_exist_in_conf(duthost, DNS_SERVER_RE.format(dns_nameserver)),
            "Failed to remove {} from /etc/resolv.conf".format(dns_nameserver)
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def test_dns_server_add_and_remove(rand_selected_dut):
    """ Test suite for dns nameserver
    """

    dns_nameserver_test_setup(rand_selected_dut)
    add_dns_nameserver(rand_selected_dut, "10.6.3.1")
    add_dns_nameserver(rand_selected_dut, "10.6.3.2")
    remove_dns_nameserver(rand_selected_dut, "10.6.3.1")

    # Removing the last DNS server isn't supported under GCU, so let config
    # rollback take care of it
    # remove_dns_nameserver(rand_selected_dut, "10.6.3.2")
