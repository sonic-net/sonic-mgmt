import logging
import pytest
import ipaddress

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import create_path, check_show_ip_intf, check_vrf_route_for_intf

# Test on t0 topo to verify functionality and to choose predefined variable
# "LOOPBACK_INTERFACE": {
#     "Loopback0": {},
#     "Loopback0|10.1.0.32/32": {},
#     "Loopback0|FC00:1::32/128": {}
# }
# admin@vlab-01:~$ show ip interfaces | grep Loopback0
# Loopback0                  10.1.0.32/32         up/up         N/A             N/A
# admin@vlab-01:~$ show ipv6 interfaces | grep Loopback0
# Loopback0                         fc00:1::32/128                              up/up         N/A             N/A
#                                   fe80::4a3:18ff:fec2:f9e3%Loopback0/64                     N/A             N/A

DEFAULT_LOOPBACK = "Loopback0"
REPLACE_IP = "10.1.0.210/32"
REPLACE_IPV6 = "FC00:1::210/128"

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def lo_intf(cfg_facts):
    def _is_ipv4_address(ip_addr):
        return ipaddress.ip_address(ip_addr).version == 4

    loopback = cfg_facts["LOOPBACK_INTERFACE"].get(DEFAULT_LOOPBACK, {})
    if not loopback:
        pytest.skip("Skipping as Loopback0 does not existed...")
    lo_intf = {}
    for ip_address in loopback:
        if _is_ipv4_address(ip_address.split("/")[0]):
            lo_intf["ip"] = ip_address
        else:
            lo_intf["ipv6"] = ip_address
    return lo_intf


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname, lo_intf):
    """
    Setup/teardown fixture for each loopback interface test.
    rollback to check if it goes back to starting config without vrf set

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
        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ip"]], ["Vrf"], is_ipv4=True)
        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ipv6"].lower()], ["Vrf"], is_ipv4=False)
    finally:
        delete_checkpoint(duthost)


def cleanup_lo_interface_config(duthost, cfg_facts):
    lo_interfaces = cfg_facts.get('LOOPBACK_INTERFACE', {})
    for lo_interface in lo_interfaces:
        del_loopback_interface = duthost.shell(
            "sudo config loopback del {}".format(lo_interface),
            module_ignore_errors=True)
        pytest_assert(
            not del_loopback_interface['rc'],
            "Loopback interface '{}' is not deleted successfully".format(lo_interface)
        )


def lo_interface_tc1_add_init(duthost, lo_intf):
    """ test initial addition of v4 and v6 lo intf

    Expected output
    "LOOPBACK_INTERFACE": {
        "Loopback0": {},
        "Loopback0|10.1.0.32/32": {},
        "Loopback0|FC00:1::32/128": {}
    }
    """
    lo_ip = "{}|{}".format(DEFAULT_LOOPBACK, lo_intf["ip"])
    lo_ipv6 = "{}|{}".format(DEFAULT_LOOPBACK, lo_intf["ipv6"])
    json_patch = [
        {
            "op": "add",
            "path": "/LOOPBACK_INTERFACE",
            "value": {
                DEFAULT_LOOPBACK: {},
                lo_ip: {},
                lo_ipv6: {}
            }
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ip"]], [], is_ipv4=True)
        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ipv6"].lower()], [], is_ipv4=False)

    finally:
        delete_tmpfile(duthost, tmpfile)


def lo_interface_tc1_add_duplicate(duthost, lo_intf):
    """ Add v4 and v6 duplicate lo intf to config

    Initial Loopback setup in t0
    "LOOPBACK_INTERFACE": {
        "Loopback0": {},
        "Loopback0|10.1.0.32/32": {},
        "Loopback0|FC00:1::32/128": {}
    }
    """
    lo_ip = "{}|{}".format(DEFAULT_LOOPBACK, lo_intf["ip"])
    lo_ipv6 = "{}|{}".format(DEFAULT_LOOPBACK, lo_intf["ipv6"])
    json_patch = [
        {
            "op": "add",
            "path": create_path(["LOOPBACK_INTERFACE",
                                lo_ip]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["LOOPBACK_INTERFACE",
                                lo_ipv6]),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ip"]], [], is_ipv4=True)
        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ipv6"].lower()], [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def lo_interface_tc1_xfail(duthost, lo_intf):
    """ Test expect fail testcase

    ("add", "Loopback0", "587.1.0.32~132", "FC00:1::32~1128"), ADD Invalid IPv4 address
    ("add", "Loopback0", "10.1.0.32~132", "FC00:1::xyz~1128"), ADD Invalid IPv6 address
    ("remove", "Loopback0", "10.1.0.210~132", "FC00:1::32~1128"), REMOVE Unexist IPv4 address
    ("remove", "Loopback0", "10.1.0.32~132", "FC00:1::210~1128") REMOVE Unexist IPv6 address
    """
    xfail_input = [
        ("add", DEFAULT_LOOPBACK, "587.1.0.32/32", lo_intf["ipv6"]),
        ("add", DEFAULT_LOOPBACK, lo_intf["ip"], "FC00:1::xyz/128"),
        ("remove", DEFAULT_LOOPBACK, "10.1.0.210/32", lo_intf["ipv6"]),
        ("remove", DEFAULT_LOOPBACK, lo_intf["ip"], "FC00:1::210/128")
    ]
    for op, name, dummy_lo_interface_v4, dummy_lo_interface_v6 in xfail_input:
        dummy_lo_interface_v4 = name + "|" + dummy_lo_interface_v4
        dummy_lo_interface_v6 = name + "|" + dummy_lo_interface_v6
        json_patch = [
            {
                "op": "{}".format(op),
                "path": create_path(["LOOPBACK_INTERFACE",
                                    dummy_lo_interface_v4]),
                "value": {}
            },
            {
                "op": "{}".format(op),
                "path": create_path(["LOOPBACK_INTERFACE",
                                    dummy_lo_interface_v6]),
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


def lo_interface_tc1_replace(duthost, lo_intf):
    """ Replace v4 and v6 loopback intf ip
    Expected output
    "LOOPBACK_INTERFACE": {
        "Loopback0": {},
        "Loopback0|10.1.0.210/32": {},
        "Loopback0|FC00:1::210/128": {}
    }
    admin@vlab-01:~$ show ip interfaces | grep Loopback0
    Loopback0                  10.1.0.210/32         up/up         N/A             N/A
    admin@vlab-01:~$ show ipv6 interfaces | grep Loopback0
    Loopback0                         fc00:1::210/128                              up/up         N/A             N/A
                                      fe80::a8cb:e8ff:fe6e:df6e%Loopback0/64                    N/A             N/A
    """
    lo_ip = "{}|{}".format(DEFAULT_LOOPBACK, lo_intf["ip"])
    lo_ipv6 = "{}|{}".format(DEFAULT_LOOPBACK, lo_intf["ipv6"])
    replaced_ip = "{}|{}".format(DEFAULT_LOOPBACK, REPLACE_IP)
    replaced_ipv6 = "{}|{}".format(DEFAULT_LOOPBACK, REPLACE_IPV6)
    json_patch = [
        {
            "op": "remove",
            "path": create_path(["LOOPBACK_INTERFACE",
                                lo_ip])
        },
        {
            "op": "remove",
            "path": create_path(["LOOPBACK_INTERFACE",
                                lo_ipv6])
        },
        {
            "op": "add",
            "path": create_path(["LOOPBACK_INTERFACE",
                                replaced_ip]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["LOOPBACK_INTERFACE",
                                replaced_ipv6]),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, DEFAULT_LOOPBACK, [REPLACE_IP],
                           [lo_intf["ip"]], is_ipv4=True)
        check_show_ip_intf(duthost, DEFAULT_LOOPBACK, [REPLACE_IPV6.lower()],
                           [lo_intf["ipv6"].lower()], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def lo_interface_tc1_remove(duthost, lo_intf):
    """ Remove v4 and v6 loopback intf config
    """
    json_patch = [
        {
            "op": "remove",
            "path": "/LOOPBACK_INTERFACE"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, DEFAULT_LOOPBACK, [],
                           [REPLACE_IP], is_ipv4=True)
        check_show_ip_intf(duthost, DEFAULT_LOOPBACK, [],
                           [REPLACE_IPV6.lower()], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def setup_vrf_config(duthost, lo_intf):
    """Create two vrf and bind Loopback0 to Vrf_01

    admin@vlab-01:~$ show ip interfaces | grep Loopback0
    Loopback0        Vrf_01    10.1.0.32/32         up/up         N/A             N/A
    admin@vlab-01:~$ show ipv6 interfaces | grep Loopback0
    Loopback0        Vrf_01           fc00:1::32/128                              up/up         N/A             N/A
                                      fe80::a8cb:e8ff:fe6e:df6e%Loopback0/64                    N/A             N/A
    admin@vlab-01:~$ show ip route vrf Vrf_01
    VRF Vrf_01:
    C>* 10.1.0.32/32 is directly connected, Loopback0, 00:00:13

    """
    cmds = []
    cmds.append("config vrf add Vrf_01")
    cmds.append("config vrf add Vrf_02")

    output = duthost.shell_cmds(cmds=cmds)

    json_patch = [
        {
            "op": "add",
            "path": "/LOOPBACK_INTERFACE/Loopback0/vrf_name",
            "value": "Vrf_01"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ip"], "Vrf_01"], [], is_ipv4=True)
        check_show_ip_intf(
            duthost, DEFAULT_LOOPBACK,
            [lo_intf["ipv6"].lower(), "Vrf_01"], [], is_ipv4=False)

        check_vrf_route_for_intf(duthost, "Vrf_01",
                                 DEFAULT_LOOPBACK, is_ipv4=True)
        check_vrf_route_for_intf(duthost, "Vrf_01",
                                 DEFAULT_LOOPBACK, is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_lo_interface_tc1_suite(rand_selected_dut, cfg_facts, lo_intf):
    cleanup_lo_interface_config(rand_selected_dut, cfg_facts)
    lo_interface_tc1_add_init(rand_selected_dut, lo_intf)
    lo_interface_tc1_add_duplicate(rand_selected_dut, lo_intf)
    lo_interface_tc1_xfail(rand_selected_dut, lo_intf)
    lo_interface_tc1_replace(rand_selected_dut, lo_intf)
    lo_interface_tc1_remove(rand_selected_dut, lo_intf)


def test_lo_interface_tc2_vrf_change(rand_selected_dut, lo_intf):
    """ Replace lo interface vrf

    admin@vlab-01:~$ show ip interfaces | grep Loopback0
    Loopback0        Vrf_02    10.1.0.32/32         up/up         N/A             N/A
    admin@vlab-01:~$ show ipv6 interfaces | grep Loopback0
    Loopback0        Vrf_02           fc00:1::32/128                              up/up         N/A             N/A
                                      fe80::a8cb:e8ff:fe6e:df6e%Loopback0/64                    N/A             N/A
    admin@vlab-01:~$ show ip route vrf Vrf_02
    VRF Vrf_02:
    C>* 10.1.0.32/32 is directly connected, Loopback0, 00:00:17
    """
    setup_vrf_config(rand_selected_dut, lo_intf)
    json_patch = [
        {
            "op": "replace",
            "path": "/LOOPBACK_INTERFACE/Loopback0/vrf_name",
            "value": "Vrf_02"
        }
    ]

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)

        check_show_ip_intf(
            rand_selected_dut, DEFAULT_LOOPBACK,
            [lo_intf["ip"], "Vrf_02"], [], is_ipv4=True)
        check_show_ip_intf(
            rand_selected_dut, DEFAULT_LOOPBACK,
            [lo_intf["ipv6"].lower(), "Vrf_02"], [], is_ipv4=False)

        check_vrf_route_for_intf(
            rand_selected_dut, "Vrf_02", DEFAULT_LOOPBACK, is_ipv4=True)
        check_vrf_route_for_intf(
            rand_selected_dut, "Vrf_02", DEFAULT_LOOPBACK, is_ipv4=False)
    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)
