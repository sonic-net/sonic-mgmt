import logging
import pytest
import ipaddress

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import create_path, check_show_ip_intf

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
    pytest.mark.topology('t0', 'm0', 'm1', 't2'),
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def cfg_facts(duthosts, enum_rand_one_per_hwsku_frontend_hostname, frontend_asic_index_with_portchannel):
    """
    Override cfg_facts to use the ASIC with portchannels.
    This ensures portchannel tests get config from an ASIC that has portchannels.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_id = frontend_asic_index_with_portchannel
    asic_namespace = duthost.get_namespace_from_asic_id(asic_id)
    return duthost.config_facts(host=duthost.hostname, source="persistent", namespace=asic_namespace)['ansible_facts']


@pytest.fixture(scope="module")
def rand_portchannel_name(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, cfg_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    portchannel_dict = cfg_facts.get('PORTCHANNEL', {})
    pytest_require(portchannel_dict, "Portchannel table is empty")

    # Filter out backend/internal portchannels
    for portchannel_key in portchannel_dict:
        if not duthost.is_backend_portchannel(portchannel_key, mg_facts):
            logger.info(f"Selected external portchannel: {portchannel_key}")
            return portchannel_key

    pytest_require(False, "No external portchannels found")


@pytest.fixture(scope="module")
def portchannel_table(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, cfg_facts):
    def _is_ipv4_address(ip_addr):
        return ipaddress.ip_address(ip_addr).version == 4

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    pytest_require("PORTCHANNEL_INTERFACE" in cfg_facts, "Unsupported without port_channel")
    portchannel_table = {}
    for portchannel, ip_addresses in list(cfg_facts["PORTCHANNEL_INTERFACE"].items()):
        # Skip backend/internal portchannels
        if duthost.is_backend_portchannel(portchannel, mg_facts):
            logger.info(f"Skipping backend portchannel: {portchannel}")
            continue

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
    for portchannel_name, ips in list(portchannel_table.items()):
        check_show_ip_intf(duthost, portchannel_name, [ips['ip']], [], is_ipv4=True)
        check_show_ip_intf(duthost, portchannel_name, [ips['ipv6']], [], is_ipv4=False)


@pytest.fixture(autouse=True)
def setup_env(duthosts, enum_rand_one_per_hwsku_frontend_hostname, portchannel_table):
    """
    Setup/teardown fixture for portchannel interface config
    Args:
        duthosts: list of DUTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture returns a randomly selected frontend DuT per HwSKU
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
        check_portchannel_table(duthost, portchannel_table)
    finally:
        delete_checkpoint(duthost)


def portchannel_interface_tc1_add_duplicate(duthost, portchannel_table, frontend_asic_index_with_portchannel,
                                            rand_portchannel_name):
    """ Test adding duplicate portchannel interface
    """
    asic_namespace = None if frontend_asic_index_with_portchannel is None else \
        'asic{}'.format(frontend_asic_index_with_portchannel)
    dup_ip = portchannel_table[rand_portchannel_name]["ip"]
    dup_ipv6 = portchannel_table[rand_portchannel_name]["ipv6"]
    json_patch = [
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "{}|{}".format(rand_portchannel_name, dup_ip)]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "{}|{}".format(rand_portchannel_name, dup_ipv6.upper())]),
            "value": {}
        }
    ]
    # change is applied to specific asic namespace
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, rand_portchannel_name, [dup_ip], [], is_ipv4=True)
        check_show_ip_intf(duthost, rand_portchannel_name, [dup_ipv6], [], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def portchannel_interface_tc1_xfail(duthost, frontend_asic_index_with_portchannel, rand_portchannel_name):
    """ Test invalid ip address and remove unexited interface

    ("add", "PortChannel101", "10.0.0.256/31", "FC00::71/126"), ADD Invalid IPv4 address
    ("add", "PortChannel101", "10.0.0.56/31", "FC00::xyz/126"), ADD Invalid IPv6 address
    ("remove", "PortChannel101", "10.0.0.57/31", "FC00::71/126"), REMOVE Unexist IPv4 address
    ("remove", "PortChannel101", "10.0.0.56/31", "FC00::72/126"), REMOVE Unexist IPv6 address
    """
    asic_namespace = None if frontend_asic_index_with_portchannel is None else \
        'asic{}'.format(frontend_asic_index_with_portchannel)
    xfail_input = [
        ("add", rand_portchannel_name, "10.0.0.256/31", "FC00::71/126"),
        ("add", rand_portchannel_name, "10.0.0.56/31", "FC00::xyz/126"),
        ("remove", rand_portchannel_name, "10.0.0.57/31", "FC00::71/126"),
        ("remove", rand_portchannel_name, "10.0.0.56/31", "FC00::72/126")
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
        json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                     is_asic_specific=True, asic_namespaces=[asic_namespace])

        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_failure(output)
        finally:
            delete_tmpfile(duthost, tmpfile)


def portchannel_interface_tc1_add_and_rm(duthost, portchannel_table,
                                         frontend_asic_index_with_portchannel,
                                         rand_portchannel_name):
    """ Test portchannel interface replace ip address
    """
    asic_namespace = None if frontend_asic_index_with_portchannel is None else \
        'asic{}'.format(frontend_asic_index_with_portchannel)
    org_ip = portchannel_table[rand_portchannel_name]["ip"]
    org_ipv6 = portchannel_table[rand_portchannel_name]["ipv6"]
    rep_ip = "10.0.0.156/31"
    rep_ipv6 = "fc00::171/126"
    json_patch = [
        {
            "op": "remove",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "{}|{}".format(rand_portchannel_name, org_ip)])
        },
        {
            "op": "remove",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "{}|{}".format(rand_portchannel_name, org_ipv6.upper())])
        },
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "{}|{}".format(rand_portchannel_name, rep_ip)]),
            "value": {}
        },
        {
            "op": "add",
            "path": create_path(["PORTCHANNEL_INTERFACE",
                                 "{}|{}".format(rand_portchannel_name, rep_ipv6)]),
            "value": {}
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        check_show_ip_intf(duthost, rand_portchannel_name, [rep_ip], [org_ip], is_ipv4=True)
        check_show_ip_intf(duthost, rand_portchannel_name, [rep_ipv6], [org_ipv6], is_ipv4=False)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_portchannel_interface_tc1_suite(duthosts, enum_rand_one_per_hwsku_frontend_hostname, portchannel_table,
                                         frontend_asic_index_with_portchannel, rand_portchannel_name):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    portchannel_interface_tc1_add_duplicate(duthost, portchannel_table,
                                            frontend_asic_index_with_portchannel, rand_portchannel_name)
    portchannel_interface_tc1_xfail(duthost,
                                    frontend_asic_index_with_portchannel, rand_portchannel_name)
    portchannel_interface_tc1_add_and_rm(duthost, portchannel_table,
                                         frontend_asic_index_with_portchannel, rand_portchannel_name)


def verify_po_running(duthost, portchannel_table):
    for portchannel_name in portchannel_table:
        cmds = 'teamdctl {} state dump | python -c \
            "import sys, json; print(json.load(sys.stdin)[\'runner\'][\'active\'])"'.format(portchannel_name)
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
            PortChannel101      N/A      40G   3324    N/A      N/A     routed      up       up     N/A         N/A
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
        cmd = (
            "show interfaces status | "
            "grep -w '^[[:space:]]*{}' | "
            "awk '{{print $4}}'"
        ).format(po_name)
        output = duthost.shell(cmd)

        pytest_assert(output['stdout'] == value, "{} attribute {} failed to change to {}".format(po_name, attr, value))
    elif attr == "min_links":
        pass
    elif attr == "admin_status":
        output = duthost.shell("show ip interfaces | grep -w '{}' | awk '{{print $3}}'".format(po_name))

        pytest_assert(output['stdout'].startswith(value), "{} {} change failed".format(po_name, attr))


def portchannel_interface_tc2_replace(duthost,
                                      frontend_asic_index_with_portchannel,
                                      rand_portchannel_name):
    """Test PortChannelXXXX attribute change
    """
    asic_namespace = None if frontend_asic_index_with_portchannel is None else \
        'asic{}'.format(frontend_asic_index_with_portchannel)
    attributes = [
        ("mtu", "3324"),
        ("min_links", "2"),
        ("admin_status", "down")
    ]

    json_patch = []
    for attr, value in attributes:
        patch = {
            "op": "replace",
            "path": "/PORTCHANNEL/{}/{}".format(rand_portchannel_name, attr),
            "value": value
        }
        json_patch.append(patch)

    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        verify_po_running(duthost, [rand_portchannel_name])
        for attr, value in attributes:
            verify_attr_change(duthost, rand_portchannel_name, attr, value)
    finally:
        delete_tmpfile(duthost, tmpfile)


def portchannel_interface_tc2_incremental(duthost,
                                          frontend_asic_index_with_portchannel,
                                          rand_portchannel_name):
    """Test PortChannelXXXX incremental change
    """
    asic_namespace = None if frontend_asic_index_with_portchannel is None else \
        'asic{}'.format(frontend_asic_index_with_portchannel)
    json_patch = [
        {
         "op": "add",
         "path": "/PORTCHANNEL/{}/description".format(rand_portchannel_name),
         "value": "Description for {}".format(rand_portchannel_name)
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch,
                                                 is_asic_specific=True, asic_namespaces=[asic_namespace])

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_portchannel_interface_tc2_attributes(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                              frontend_asic_index_with_portchannel,
                                              rand_portchannel_name):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    portchannel_interface_tc2_replace(duthost,
                                      frontend_asic_index_with_portchannel,
                                      rand_portchannel_name)
    portchannel_interface_tc2_incremental(duthost,
                                          frontend_asic_index_with_portchannel,
                                          rand_portchannel_name)
