import logging
import pytest
import ipaddress
import re

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]


@pytest.fixture(autouse=True)
def ensure_dut_readiness(duthost):
    """
    Setup/teardown fixture for each ipv6 test
    rollback to check if it goes back to starting config

    Args:
        duthost: DUT host object under test
    """

    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def get_ipv6_neighbor(duthost):
    """
    Returns ipv6 BGP neighbor address, properties of BGP neighbor

    Args:
        duthost: DUT host object
    """

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors_data = config_facts['BGP_NEIGHBOR']
    for neighbor_address in bgp_neighbors_data.keys():
        if ipaddress.ip_address(unicode(neighbor_address)).version == 6:
            return neighbor_address, bgp_neighbors_data[neighbor_address]
    pytest_assert(True, "No existing ipv6 neighbor")


def check_neighbor_existence(duthost, neighbor_address):
    ipv6_bgp_su = duthost.shell('show ipv6 bgp su')['stdout']
    return re.search(r'\b{}\b'.format(neighbor_address), ipv6_bgp_su)


def add_deleted_ipv6_neighbor(duthost):
    ipv6_neighbor_address, ipv6_neighbor_config = get_ipv6_neighbor(duthost)
    neighbor_exists = check_neighbor_existence(duthost, ipv6_neighbor_address)
    pytest_assert(neighbor_exists, "Nonexistent ipv6 BGP neighbor")

    duthost.shell('config bgp remove neighbor {}'.format(ipv6_neighbor_address))
    neighbor_exists = check_neighbor_existence(duthost, ipv6_neighbor_address)
    pytest_assert(not neighbor_exists,
                  "Failed to remove ipv6 BGP neighbor under test")

    json_patch = [
        {
            "op": "add",
            "path": "/BGP_NEIGHBOR/{}".format(ipv6_neighbor_address),
            "value": ipv6_neighbor_config
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        neighbor_exists = check_neighbor_existence(duthost, ipv6_neighbor_address)
        pytest_assert(neighbor_exists,
                      "GCU failed to add back deleted ipv6 BGP neighbor")
    finally:
        delete_tmpfile(duthost, tmpfile)


def add_duplicate_ipv6_neighbor(duthost):
    ipv6_neighbor_address, ipv6_neighbor_config = get_ipv6_neighbor(duthost)

    json_patch = [
        {
            "op": "add",
            "path": "/BGP_NEIGHBOR/{}".format(ipv6_neighbor_address),
            "value": ipv6_neighbor_config
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        neighbor_exists = check_neighbor_existence(duthost, ipv6_neighbor_address)
        pytest_assert(neighbor_exists,
                      "Expected ipv6 BGP neighbor does not exist")
    finally:
        delete_tmpfile(duthost, tmpfile)


def invalid_ipv6_neighbor(duthost):
    xfail_input = [
        ("add", "FC00::xyz/126"),
        ("remove", "FC00::01/126")
    ]
    for op, dummy_neighbor_ipv6_address in xfail_input:
        json_patch = [
            {
                "op": "{}".format(op),
                "path": "/BGP_NEIGHBOR/{}".format(dummy_neighbor_ipv6_address),
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


def ipv6_neighbor_admin_change(duthost):
    ipv6_neighbor_address, ipv6_neighbor_config = get_ipv6_neighbor(duthost)
    json_patch = [
        {
            "op": "add",
            "path": "/BGP_NEIGHBOR/{}/admin_status".format(ipv6_neighbor_address),
            "value": "up"
        },
        {
            "op": "replace",
            "path": "/BGP_NEIGHBOR/{}/admin_status".format(ipv6_neighbor_address),
            "value": "down"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        cmds = "show ipv6 bgp su | grep -w {}".format(ipv6_neighbor_address)
        output = duthost.shell(cmds)
        pytest_assert(not output['rc'] and "Idle (Admin)" in output['stdout'],
            "BGP Neighbor with addr {} failed to admin down.".format(ipv6_neighbor_address)
        )
    finally:
        delete_tmpfile(duthost, tmpfile)


def delete_ipv6_neighbor(duthost):
    ipv6_neighbor_address, ipv6_neighbor_config = get_ipv6_neighbor(duthost)

    json_patch = [
        {
            "op": "remove",
            "path": "/BGP_NEIGHBOR/{}".format(ipv6_neighbor_address)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        neighbor_exists = check_neighbor_existence(duthost, ipv6_neighbor_address)
        pytest_assert(not neighbor_exists,
                      "Failed to remove ipv6 BGP neighbor under test")
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_ipv6_suite(duthost, ensure_dut_readiness):
    add_deleted_ipv6_neighbor(duthost)
    add_duplicate_ipv6_neighbor(duthost)
    invalid_ipv6_neighbor(duthost)
    ipv6_neighbor_admin_change(duthost)
    delete_ipv6_neighbor(duthost)
