import logging
import pytest
import ipaddress
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'm0', 'mx'),
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


def get_ip_neighbor(duthost, namespace=None, ip_version=6):
    """
    Returns ip BGP neighbor address, properties of BGP neighbor

    Args:
        duthost: DUT host object
        namespace: DUT asic namespace. asic0, asic1, None
        ip_version: IP version. 4, 6
    """

    config_facts = duthost.config_facts(host=duthost.hostname, source="running",
                                        verbose=False, namespace=namespace)['ansible_facts']

    bgp_neighbors_data = config_facts['BGP_NEIGHBOR']
    for neighbor_address in list(bgp_neighbors_data.keys()):
        if ipaddress.ip_address((neighbor_address.encode().decode())).version == ip_version:
            return neighbor_address, bgp_neighbors_data[neighbor_address]
    pytest_assert(True, "No existing ipv{} neighbor".format(ip_version))


def check_neighbor_existence(duthost, neighbor_address, ip_version=6):
    cmd = 'show ip bgp su' if ip_version == 4 else 'show ipv6 bgp su'
    ip_bgp_su = duthost.shell(cmd)['stdout']
    return re.search(r'\b{}\b'.format(neighbor_address), ip_bgp_su)


def add_deleted_ip_neighbor(duthost, namespace=None, ip_version=6):
    ip_neighbor_address, ip_neighbor_config = get_ip_neighbor(duthost, namespace, ip_version)
    neighbor_exists = check_neighbor_existence(duthost, ip_neighbor_address, ip_version)
    pytest_assert(neighbor_exists, "Nonexistent ipv{} BGP neighbor".format(ip_version))

    duthost.shell('config bgp remove neighbor {}'.format(ip_neighbor_address))
    neighbor_exists = check_neighbor_existence(duthost, ip_neighbor_address, ip_version)
    pytest_assert(not neighbor_exists,
                  "Failed to remove ipv{} BGP neighbor under test".format(ip_version))

    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/BGP_NEIGHBOR/{}".format(json_namespace, ip_neighbor_address),
            "value": ip_neighbor_config
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        neighbor_exists = check_neighbor_existence(duthost, ip_neighbor_address, ip_version)
        pytest_assert(neighbor_exists,
                      "GCU failed to add back deleted ipv{} BGP neighbor".format(ip_version))
    finally:
        delete_tmpfile(duthost, tmpfile)


def add_duplicate_ip_neighbor(duthost, namespace=None, ip_version=6):
    ip_neighbor_address, ip_neighbor_config = get_ip_neighbor(duthost, namespace, ip_version)

    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/BGP_NEIGHBOR/{}".format(json_namespace, ip_neighbor_address),
            "value": ip_neighbor_config
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        neighbor_exists = check_neighbor_existence(duthost, ip_neighbor_address, ip_version)
        pytest_assert(neighbor_exists,
                      "Expected ipv{} BGP neighbor does not exist".format(ip_version))
    finally:
        delete_tmpfile(duthost, tmpfile)


def invalid_ip_neighbor(duthost, namespace=None, ip_version=6):
    xfailv6_input = [
        ("add", "FC00::xyz/126"),
        ("remove", "FC00::01/126")
    ]
    xfailv4_input = [
        ("add", "10.0.0.256/31"),
        ("remove", "10.0.0.0/31")
    ]

    xfail_input = xfailv4_input if ip_version == 4 else xfailv6_input
    json_namespace = '' if namespace is None else '/' + namespace
    for op, dummy_neighbor_ip_address in xfail_input:
        json_patch = [
            {
                "op": "{}".format(op),
                "path": "{}/BGP_NEIGHBOR/{}".format(json_namespace, dummy_neighbor_ip_address),
                "value": {}
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


def ip_neighbor_admin_change(duthost, namespace=None, ip_version=6):
    ip_neighbor_address, ip_neighbor_config = get_ip_neighbor(duthost, namespace, ip_version)
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "add",
            "path": "{}/BGP_NEIGHBOR/{}/admin_status".format(json_namespace, ip_neighbor_address),
            "value": "up"
        },
        {
            "op": "replace",
            "path": "{}/BGP_NEIGHBOR/{}/admin_status".format(json_namespace, ip_neighbor_address),
            "value": "down"
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        ip_type = 'ip' if ip_version == 4 else 'ipv6'
        cmds = "show {} bgp su | grep -w {}".format(ip_type, ip_neighbor_address)
        output = duthost.shell(cmds)
        pytest_assert(not output['rc'] and "Idle (Admin)" in output['stdout'],
                      "BGP Neighbor with addr {} failed to admin down.".format(ip_neighbor_address))
    finally:
        delete_tmpfile(duthost, tmpfile)


def delete_ip_neighbor(duthost, namespace=None, ip_version=6):
    ipv6_neighbor_address, ipv6_neighbor_config = get_ip_neighbor(duthost, namespace, ip_version)
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = [
        {
            "op": "remove",
            "path": "{}/BGP_NEIGHBOR/{}".format(json_namespace, ipv6_neighbor_address)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        neighbor_exists = check_neighbor_existence(duthost, ipv6_neighbor_address, ip_version)
        pytest_assert(not neighbor_exists,
                      "Failed to remove ipv{} BGP neighbor under test".format(ip_version))
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("ip_version", [6, 4])
def test_ip_suite(duthost, ensure_dut_readiness, rand_front_end_asic_namespace, ip_version):
    asic_namespace, asic_id = rand_front_end_asic_namespace
    add_deleted_ip_neighbor(duthost, asic_namespace, ip_version)
    add_duplicate_ip_neighbor(duthost, asic_namespace, ip_version)
    invalid_ip_neighbor(duthost, asic_namespace, ip_version)
    ip_neighbor_admin_change(duthost, asic_namespace, ip_version)
    delete_ip_neighbor(duthost, asic_namespace, ip_version)
