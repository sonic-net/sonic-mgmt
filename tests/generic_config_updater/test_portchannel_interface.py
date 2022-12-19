import logging
import pytest
import ipaddress

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import create_path, check_show_ip_intf

# Test on t0 topo to verify functionality and to choose predefined variable
# "PORTCHANNEL_INTERFACE": {
#     "PortChannel101": {},
#     "PortChannel101|10.0.0.56/31": {},
#     "PortChannel101|FC00::71/126": {},
#     "PortChannel102": {},
#     "PortChannel102|10.0.0.58/31": {},
#     "PortChannel102|FC00::75/126": {},
#     "PortChannel103": {},
#     "PortChannel103|10.0.0.60/31": {},
#     "PortChannel103|FC00::79/126": {},
#     "PortChannel104": {},
#     "PortChannel104|10.0.0.62/31": {},
#     "PortChannel104|FC00::7D/126": {}
# }

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def portchannel_table(cfg_facts):
    def _is_ipv4_address(ip_addr):
        return ipaddress.ip_address(ip_addr).version == 4

    portchannel_table = {}
    for portchannel, ip_addresses in cfg_facts["PORTCHANNEL_INTERFACE"].items():
        ips = {}
        for ip_address in ip_addresses:
            if _is_ipv4_address(ip_address.split("/")[0]):
                ips["ip"] = ip_address
            else:
                ips["ipv6"] = ip_address.lower()
        portchannel_table[portchannel] = ips

    return portchannel_table


def check_portchannel_table(duthost, portchannel_table):
    """This is to check if portchannel interfaces are the same as t0 initial setup
    """
    for portchannel_name, ips in portchannel_table.items():
        check_show_ip_intf(duthost, portchannel_name, [ips['ip']], [], is_ipv4=True)
        check_show_ip_intf(duthost, portchannel_name, [ips['ipv6']], [], is_ipv4=False)


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname, portchannel_table):
    """
    Setup/teardown fixture for portchannel interface config
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
        check_portchannel_table(duthost, portchannel_table)
    finally:
        delete_checkpoint(duthost)


def portchannel_interface_tc1_add_duplicate(duthost, portchannel_table):
    """ Test adding duplicate portchannel interface
    """
    dup_ip = portchannel_table["PortChannel101"]["ip"]
    dup_ipv6 = portchannel_table["PortChannel101"]["ipv6"]
    json_patch = [
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "PortChannel101|{}".format(dup_ip)]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "PortChannel101|{}".format(dup_ipv6.upper())]),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "PortChannel101", [dup_ip], [], is_ipv4=True)
        check_show_ip_intf(duthost, "PortChannel101", [dup_ipv6], [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def portchannel_interface_tc1_xfail(duthost):
    """ Test invalid ip address and remove unexited interface

    ("add", "PortChannel101", "10.0.0.256/31", "FC00::71/126"), ADD Invalid IPv4 address
    ("add", "PortChannel101", "10.0.0.56/31", "FC00::xyz/126"), ADD Invalid IPv6 address
    ("remove", "PortChannel101", "10.0.0.57/31", "FC00::71/126"), REMOVE Unexist IPv4 address
    ("remove", "PortChannel101", "10.0.0.56/31", "FC00::72/126"), REMOVE Unexist IPv6 address
    """
    xfail_input = [
        ("add", "PortChannel101", "10.0.0.256/31", "FC00::71/126"),
        ("add", "PortChannel101", "10.0.0.56/31", "FC00::xyz/126"),
        ("remove", "PortChannel101", "10.0.0.57/31", "FC00::71/126"),
        ("remove", "PortChannel101", "10.0.0.56/31", "FC00::72/126")
    ]

    for op, po_name, ip, ipv6 in xfail_input:
        po_ip = po_name + "|" + ip
        po_ipv6 = po_name + "|" + ipv6
        json_patch = [
            {
                "op": "{}".format(op),
                "path": create_path(["PORTCHANNEL_INTERFACE", po_ip]),
                "value": {}
            },
            {
                "op": "{}".format(op),
                "path": create_path(["PORTCHANNEL_INTERFACE", po_ipv6]),
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


def portchannel_interface_tc1_add_and_rm(duthost, portchannel_table):
    """ Test portchannel interface replace ip address
    """
    org_ip = portchannel_table["PortChannel101"]["ip"]
    org_ipv6 = portchannel_table["PortChannel101"]["ipv6"]
    rep_ip = "10.0.0.156/31"
    rep_ipv6 = "fc00::171/126"
    json_patch = [
        {
            "op": "remove",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "PortChannel101|{}".format(org_ip)])
        },
        {
            "op": "remove",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "PortChannel101|{}".format(org_ipv6.upper())])
        },
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "PortChannel101|{}".format(rep_ip)]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "PortChannel101|{}".format(rep_ipv6)]),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, "PortChannel101", [rep_ip], [org_ip], is_ipv4=True)
        check_show_ip_intf(duthost, "PortChannel101", [rep_ipv6], [org_ipv6], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_portchannel_interface_tc1_suite(rand_selected_dut, portchannel_table):
    portchannel_interface_tc1_add_duplicate(rand_selected_dut, portchannel_table)
    portchannel_interface_tc1_xfail(rand_selected_dut)
    portchannel_interface_tc1_add_and_rm(rand_selected_dut, portchannel_table)


def verify_po_running(duthost, portchannel_table):
    for portchannel_name in portchannel_table:
        cmds = 'teamdctl {} state dump | python -c "import sys, json; print(json.load(sys.stdin)[\'runner\'][\'active\'])"'.format(portchannel_name)
        output = duthost.shell(cmds, module_ignore_errors=True)

        pytest_assert(
            not output['rc'] or output['stdout'] != 'True',
            "{} is not running correctly."
        )


def verify_attr_change(duthost, po_name, attr, value):
    """
    attr:
        mtu: check if "mtu 3324" exists
            admin@vlab-01:~$ show interfaces status | grep -w ^PortChannel101
            PortChannel101              N/A      40G   3324    N/A             N/A           routed      up       up     N/A         N/A
        min_links:
            TODO: further check
        admin_status: check if 3rd column start with "down"
            admin@vlab-01:~/lag$ show ip interfaces
            Interface        Master    IPv4 address/mask    Admin/Oper    BGP Neighbor    Neighbor IP
            ---------------  --------  -------------------  ------------  --------------  -------------
            ...
            PortChannel101            10.0.0.56/31         up/up         ARISTA01T1      10.0.0.57
            ...
    """
    if attr == "mtu":
        output = duthost.shell("show interfaces status | grep -w '^{}' | awk '{{print $4}}'".format(po_name))

        pytest_assert(output['stdout'] == value,
            "{} attribute {} failed to change to {}".format(po_name, attr, value)
        )
    elif attr == "min_links":
        pass
    elif attr == "admin_status":
        output = duthost.shell("show ip interfaces | grep -w '{}' | awk '{{print $3}}'".format(po_name))

        pytest_assert(output['stdout'].startswith(value),
            "{} {} change failed".format(po_name, attr)
        )


def portchannel_interface_tc2_replace(duthost):
    """Test PortChannelXXXX attribute change
    """
    attributes = [
        ("mtu", "3324"),
        ("min_links", "2"),
        ("admin_status", "down")
    ]

    json_patch = []
    for attr, value in attributes:
        patch = {
            "op": "replace",
            "path": "/PORTCHANNEL/PortChannel101/{}".format(attr),
            "value": value
        }
        json_patch.append(patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        verify_po_running(duthost, ["PortChannel101"])
        for attr, value in attributes:
            verify_attr_change(duthost, "PortChannel101", attr, value)
    finally:
        delete_tmpfile(duthost, tmpfile)


def portchannel_interface_tc2_incremental(duthost):
    """Test PortChannelXXXX incremental change
    """
    json_patch = [
        {
         "op": "add",
         "path": "/PORTCHANNEL/PortChannel101/description",
         "value": "Description for PortChannel101"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_portchannel_interface_tc2_attributes(rand_selected_dut):
    portchannel_interface_tc2_replace(rand_selected_dut)
    portchannel_interface_tc2_incremental(rand_selected_dut)
