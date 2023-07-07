import ipaddress
import logging
import sys
import re
import pytest

from tests.common.helpers.assertions import pytest_assert
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
# Test on m0 topo to verify functionality and to choose predefined variable
# "VLAN_INTERFACE": {
#     "Vlan1000": {},
#     "Vlan1000|192.168.0.1/24": {},
#     "Vlan1000|fc02:1000::1/64": {}
# }

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx'),
]

logger = logging.getLogger(__name__)
EXIST_VLAN_ID = 1000
NEW_VLAN_ID = 1001

if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode


def get_vlan_info(intf):
    """
    Sample output
    {
        "name": "Vlan1000",
        "prefix": "192.168.0.1/24"
    }
    """
    info = {
        "name": intf["attachto"],
        "prefix": "{}/{}".format(intf["addr"], intf["prefixlen"])
    }
    return info


@pytest.fixture()
def vlan_info(duthost, tbinfo):
    """
    Fixture of getting ipv4/ipv6 vlan info
    Args:
        duthost: DUT host
        tbinfo: fixture provides information about testbed
    Return:
        Name and prefix of ipv4/ipv6 vlans
        Sample output
        {
            "v4": {
                "name": "Vlan1000",
                "prefix": "192.168.0.1/24"
            },
            "v6": {
                "name": "Vlan1000",
                "prefix": "fc02:1000::1/64"
            }
        }
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vlan_intf = mg_facts['minigraph_vlan_interfaces']
    vlan_v4_info = None
    vlan_v6_info = None
    for intf in vlan_intf:
        if vlan_v4_info is None and ipaddress.ip_address(intf["addr"]).version == 4:
            vlan_v4_info = get_vlan_info(intf)

        if vlan_v6_info is None and ipaddress.ip_address(intf["addr"]).version == 6:
            vlan_v6_info = get_vlan_info(intf)

    pytest_assert(vlan_v4_info is not None, "Not ipv4 vlan")
    pytest_assert(vlan_v6_info is not None, "Not ipv6 vlan")

    yield {
        "v4": vlan_v4_info,
        "v6": vlan_v6_info
    }


@pytest.fixture(autouse=True)
def cleanup_test_env(duthosts, rand_one_dut_hostname, vlan_info):
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
        check_show_ip_intf(duthost, vlan_info["v4"]["name"], [vlan_info["v4"]["prefix"]],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, vlan_info["v6"]["name"], [vlan_info["v6"]["prefix"]],
                           [], is_ipv4=False)
    finally:
        delete_checkpoint(duthost)


def vlan_interface_tc1_add_duplicate(duthost, vlan_info):
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
                                 "{}|{}".format(vlan_info["v4"]["name"], vlan_info["v4"]["prefix"])]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "{}|{}".format(vlan_info["v6"]["name"], vlan_info["v6"]["prefix"])]),
            "value": {}
        }
    ]

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, vlan_info["v4"]["name"], [vlan_info["v4"]["prefix"]],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, vlan_info["v6"]["name"], [vlan_info["v6"]["prefix"]],
                           [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def reg_replace(str, reg, replace_str):
    """
    Replace str by regex
    """
    regex = re.compile(reg)
    return regex.sub(replace_str, str)


def vlan_interface_tc1_xfail(duthost, vlan_info):
    """
    Get invalid IPv4/IPv6 address and unexist IPv4/IPv6 address by vlan_info and then add/remove them.

    For example:
    vlan_info = {
                    "v4": {
                        "name": "Vlan1000",
                        "prefix": "192.168.0.1/24"
                    },
                    "v6": {
                        "name": "Vlan1000",
                        "prefix": "fc02:1000::1/64"
                    }
                }

    then we can get:
        invalid_ipv4_address = "587.168.0.1/24" (Replace "192" with "587" in "192.168.0.1/24")
        invalid_ipv6_address = "fc02:1000::xyz/64" (Replace last "1" with "xyz" in "fc02:1000::1/64")
        unexist_ipv4_address = "192.168.0.2/24" (Next ip address behind 192.168.0.1/24)
        unexist_ipv6_address = "fc02:1000::2/64" (Next ip address behind fc02:1000::1/64)

    and then construct xfail_input:
        xfail_input = [
            ("add", "Vlan1000", "587.168.0.1/24", "fc02:1000::1/64"), # Add invalid IPv4 address
            ("add", "Vlan1000", "192.168.0.1/24", "fc02:1000::xyz/64"), # Add invalid IPv6 address
            ("remove", "Vlan1000", "192.168.0.2/24", "fc02:1000::1/64"), # Remove unexist IPv4 address
            ("remove", "Vlan1000", "192.168.0.1/24", "fc02:1000::2/64") # Remove unexist IPv6 address
        ]
    """
    invalid_ipv4_address = reg_replace(vlan_info["v4"]["prefix"], r"^\d*", "587")
    invalid_ipv6_address = reg_replace(vlan_info["v6"]["prefix"], r":\d*/", ":xyz/")
    unexist_ipv4_address = ipaddr_plus(vlan_info["v4"]["prefix"])
    unexist_ipv6_address = ipaddr_plus(vlan_info["v6"]["prefix"])

    xfail_input = [
        ("add", vlan_info["v4"]["name"], invalid_ipv4_address, vlan_info["v6"]["prefix"]),
        ("add", vlan_info["v4"]["name"], vlan_info["v4"]["prefix"], invalid_ipv6_address),
        ("remove", vlan_info["v4"]["name"], unexist_ipv4_address, vlan_info["v6"]["prefix"]),
        ("remove", vlan_info["v4"]["name"], vlan_info["v4"]["prefix"], unexist_ipv6_address)
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
    """ Add an brand new vlan interface Vlan1001

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
        "Vlan1001": {
            "vlanid": "1001"
        }
    },
    "VLAN_INTERFACE": {
        "Vlan1000": {},
        "Vlan1001": {},
        "Vlan1000|192.168.0.1/21": {},
        "Vlan1000|fc02:1000::1/64": {},
        "Vlan1001|192.168.8.1/21": {},
        "Vlan1001|fc02:2000::1/64": {}
    }

    admin@vlab-01:~/vlan$ show ip interfaces | grep -w Vlan1001
    Vlan1001                   192.168.8.1/21       up/up         N/A             N/A
    admin@vlab-01:~/vlan$ show ipv6 interfaces | grep -w Vlan1001
    Vlan1001                          fc02:2000::1/64                             up/up         N/A             N/A
                                      fe80::5054:ff:feda:c6af%Vlan1001/64                       N/A             N/A

    """
    json_patch = [
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan{}".format(NEW_VLAN_ID),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan{}|192.168.8.1/21".format(NEW_VLAN_ID)]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "Vlan{}|fc02:2000::1/64".format(NEW_VLAN_ID)]),
            "value": {}
        },
        {
            "op": "add",
            "path": "/VLAN/Vlan{}".format(NEW_VLAN_ID),
            "value": {
                "vlanid": "{}".format(NEW_VLAN_ID)
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "Vlan{}".format(NEW_VLAN_ID), ["192.168.8.1/21"],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan{}".format(NEW_VLAN_ID), ["fc02:2000::1/64"],
                           [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def ipaddr_plus(ipaddr):
    """
    Get next ip address of ipaddr
    """
    splits = ipaddr.split("/")
    return "{}/{}".format(ipaddress.ip_address(UNICODE_TYPE(splits[0])) + 1, splits[1])


def vlan_interface_tc1_replace(duthost, vlan_info):
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
                                 "{}|{}".format(vlan_info["v6"]["name"], vlan_info["v6"]["prefix"])]),
        },
        {
            "op": "remove",
            "path": create_path(["VLAN_INTERFACE",
                                 "{}|{}".format(vlan_info["v4"]["name"], vlan_info["v4"]["prefix"])]),
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "{}|{}".format(vlan_info["v4"]["name"], ipaddr_plus(vlan_info["v4"]["prefix"]))]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["VLAN_INTERFACE",
                                 "{}|{}".format(vlan_info["v6"]["name"], ipaddr_plus(vlan_info["v6"]["prefix"]))]),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, vlan_info["v4"]["name"], [ipaddr_plus(vlan_info["v4"]["prefix"])],
                           [], is_ipv4=True)
        check_show_ip_intf(duthost, vlan_info["v6"]["name"], [ipaddr_plus(vlan_info["v6"]["prefix"])],
                           [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def vlan_interface_tc1_remove(duthost, vlan_info):
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

        check_show_ip_intf(duthost, vlan_info["v4"]["name"], [],
                           [ipaddr_plus(vlan_info["v4"]["prefix"])], is_ipv4=True)
        check_show_ip_intf(duthost, vlan_info["v6"]["name"], [],
                           [ipaddr_plus(vlan_info["v6"]["prefix"])], is_ipv4=False)
        check_show_ip_intf(duthost, "Vlan{}".format(NEW_VLAN_ID), [],
                           ["192.168.8.1/21"], is_ipv4=True)
        check_show_ip_intf(duthost, "Vlan{}".format(NEW_VLAN_ID), [],
                           ["fc02:2000::1/64"], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_vlan_interface_tc1_suite(rand_selected_dut, vlan_info):
    vlan_interface_tc1_add_duplicate(rand_selected_dut, vlan_info)
    vlan_interface_tc1_xfail(rand_selected_dut, vlan_info)
    vlan_interface_tc1_add_new(rand_selected_dut)
    vlan_interface_tc1_replace(rand_selected_dut, vlan_info)
    vlan_interface_tc1_remove(rand_selected_dut, vlan_info)


def test_vlan_interface_tc2_incremental_change(rand_selected_dut):
    """ Incremental test for VLAN interface

    Note: Current topo doesn't contain those change.
    MTU and admin_status incremental change is not support as of 12/10/2021
    """
    json_patch = [
        {
            "op": "add",
            "path": "/VLAN/Vlan{}/description".format(EXIST_VLAN_ID),
            "value": "incremental test for Vlan{}".format(EXIST_VLAN_ID)
        }
    ]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)
