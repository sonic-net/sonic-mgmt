import logging
import pytest

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import create_path, check_show_ip_intf

# Test on t0 topo to verify functionality and to choose predefined variable
# "VLAN_INTERFACE": {
#     "Vlan1000": {},
#     "Vlan1000|192.168.0.1/21": {},
#     "Vlan1000|fc02:1000::1/64": {}
# }

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def cleanup_test_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for VLAN interface config
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
        check_show_ip_intf(duthost, "Vlan1000", ["192.168.0.1/21"],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan1000", ["fc02:1000::1/64"],
                           [], is_ipv4=False)
    finally:
        delete_checkpoint(duthost)


def vlan_interface_tc1_add_duplicate(duthost):
    """ Add duplicate v4 and v6 lo intf to config

    Sample output
        "VLAN_INTERFACE": {
        "Vlan1000": {},
        "Vlan1000|192.168.0.1/21": {},
        "Vlan1000|fc02:1000::1/64": {}
    }
    """
    json_patch = [
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan1000|192.168.0.1/21"]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan1000|fc02:1000::1/64"]),
            "value": {}
        }
    ]

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "Vlan1000", ["192.168.0.1/21"],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan1000", ["fc02:1000::1/64"],
                           [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def vlan_interface_tc1_xfail(duthost):
    """ Test expect fail testcase

    ("add", "Vlan1000", "587.168.0.1/21", "fc02:1000::1/64"), ADD Invalid IPv4 address
    ("add", "Vlan1000", "192.168.0.1/21", "fc02:1000::xyz/64"), ADD Invalid IPv6 address
    ("remove", "Vlan1000", "192.168.0.2/21", "fc02:1000::1/64"), REMOVE Unexist IPv4 address
    ("remove", "Vlan1000", "192.168.0.1/21", "fc02:1000::2/64") REMOVE Unexist IPv6 address
    """
    xfail_input = [
        ("add", "Vlan1000", "587.168.0.1/21", "fc02:1000::1/64"),
        ("add", "Vlan1000", "192.168.0.1/21", "fc02:1000::xyz/64"),
        ("remove", "Vlan1000", "192.168.0.2/21", "fc02:1000::1/64"),
        ("remove", "Vlan1000", "192.168.0.1/21", "fc02:1000::2/64")
    ]
    for op, name, ip, ipv6 in xfail_input:
        dummy_vlan_interface_v4 = name + "|" + ip
        dummy_vlan_interface_v6 = name + "|" + ipv6

        json_patch = [
            {
                "op": "{}".format(op),
                "path": create_path(["VLAN_INTERFACE",
                                     dummy_vlan_interface_v4]),
                "value": {}
            },
            {
                "op": "{}".format(op),
                "path": create_path(["VLAN_INTERFACE",
                                     dummy_vlan_interface_v6]),
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


def vlan_interface_tc1_add_new(duthost):
    """ Add an brand new vlan interface Vlan2000

    Sample output:
    "VLAN": {
        "Vlan1000": {
            "dhcp_servers": [
                "192.0.0.1",
                "192.0.0.2",
                "192.0.0.3",
                "192.0.0.4"
            ],
            "vlanid": "1000"
        },
        "Vlan2000": {
            "vlanid": "2000"
        }
    },
    "VLAN_INTERFACE": {
        "Vlan1000": {},
        "Vlan2000": {},
        "Vlan1000|192.168.0.1/21": {},
        "Vlan1000|fc02:1000::1/64": {},
        "Vlan2000|192.168.8.1/21": {},
        "Vlan2000|fc02:2000::1/64": {}
    }

    admin@vlab-01:~/vlan$ show ip interfaces | grep -w Vlan2000
    Vlan2000                   192.168.8.1/21       up/up         N/A             N/A
    admin@vlab-01:~/vlan$ show ipv6 interfaces | grep -w Vlan2000
    Vlan2000                          fc02:2000::1/64                             up/up         N/A             N/A
                                      fe80::5054:ff:feda:c6af%Vlan2000/64                       N/A             N/A

    """
    json_patch = [
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan2000",
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan2000|192.168.8.1/21"]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan2000|fc02:2000::1/64"]),
            "value": {}
        },
        {
            "op": "add",
            "path": "/VLAN/Vlan2000",
            "value": {
                "vlanid": "2000"
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "Vlan2000", ["192.168.8.1/21"],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan2000", ["fc02:2000::1/64"],
                           [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def vlan_interface_tc1_replace(duthost):
    """ Test replace testcase

    Expected output
        "VLAN_INTERFACE": {
        "Vlan1000": {},
        "Vlan1000|192.168.0.2/21": {},
        "Vlan1000|fc02:1000::2/64": {}
    }
    """
    json_patch = [
        {
            "op": "remove",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan1000|fc02:1000::1/64"]),
        },
        {
            "op": "remove",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan1000|192.168.0.1/21"]),
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan1000|192.168.0.2/21"]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan1000|fc02:1000::2/64"]),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "Vlan1000", ["192.168.0.2/21"],
                           ["192.168.0.1/21"], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan1000", ["fc02:1000::2/64"],
                           ["fc02:1000::1/64"], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def vlan_interface_tc1_remove(duthost):
    """ Remove all VLAN intf
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/VLAN_INTERFACE"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "Vlan1000", [],
                           ["192.168.0.2/21", ], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan1000", [],
                           ["fc02:1000::2/64"], is_ipv4=False)
        check_show_ip_intf(duthost, "Vlan2000", [],
                           ["192.168.8.1/21"], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan2000", [],
                           ["fc02:2000::1/64"], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_vlan_interface_tc1_suite(rand_selected_dut):
    vlan_interface_tc1_add_duplicate(rand_selected_dut)
    vlan_interface_tc1_xfail(rand_selected_dut)
    vlan_interface_tc1_add_new(rand_selected_dut)
    vlan_interface_tc1_replace(rand_selected_dut)
    vlan_interface_tc1_remove(rand_selected_dut)


def test_vlan_interface_tc2_incremental_change(rand_selected_dut):
    """ Incremental test for VLAN interface

    Note: Current topo doesn't contain those change.
    MTU and admin_status incremental change is not support as of 12/10/2021
    """
    json_patch = [
        {
            "op": "add",
            "path": "/VLAN/Vlan1000/description",
            "value": "incremental test for Vlan1000"
        }
    ]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)
