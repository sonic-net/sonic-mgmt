import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

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

    yield

    logger.info("Restoring config_db.json")
    config_reload(duthost)

def test_vlan_interface_tc1_add_duplicate(duthost):
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
            "path": "/VLAN_INTERFACE/Vlan1000|192.168.0.1~121",
            "value": {}
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan1000|fc02:1000::1~164",
            "value": {}
        }
    ]

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, name, dummy_vlan_interface_v4, dummy_vlan_interface_v6", [
    ("add", "Vlan1000", "587.168.0.1~121", "fc02:1000::1~164"),
    ("add", "Vlan1000", "192.168.0.1~121", "fc02:1000::xyz~164"),
    ("remove", "Vlan1000", "192.168.0.2~121", "fc02:1000::1~164"),
    ("remove", "Vlan1000", "192.168.0.1~121", "fc02:1000::2~164")
])
def test_vlan_interface_tc2_xfail(duthost, op, name,
        dummy_vlan_interface_v4, dummy_vlan_interface_v6):
    """ Test expect fail testcase

    ("add", "Vlan1000", "587.168.0.1~121", "fc02:1000::1~164"), ADD Invalid IPv4 address
    ("add", "Vlan1000", "192.168.0.1~121", "fc02:1000::xyz~164"), ADD Invalid IPv6 address
    ("remove", "Vlan1000", "192.168.0.2~121", "fc02:1000::1~164"), REMOVE Unexist IPv4 address
    ("remove", "Vlan1000", "192.168.0.1~121", "fc02:1000::2~164") REMOVE Unexist IPv6 address
    """
    dummy_vlan_interface_v4 = name + "|" + dummy_vlan_interface_v4
    dummy_vlan_interface_v6 = name + "|" + dummy_vlan_interface_v6

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/VLAN_INTERFACE/{}".format(dummy_vlan_interface_v4),
            "value": {}
        }   ,
        {
            "op": "{}".format(op),
            "path": "/VLAN_INTERFACE/{}".format(dummy_vlan_interface_v6),
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

def test_vlan_interface_tc3_add_new(duthost):
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
    """
    json_patch = [
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan2000",
            "value": {}
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan2000|192.168.8.1~121",
            "value": {}
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan2000|fc02:2000::1~164",
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
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_vlan_interface_tc4_replace(duthost):
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
            "path": "/VLAN_INTERFACE/Vlan1000|fc02:1000::1~164"
        },
        {
            "op": "remove",
            "path": "/VLAN_INTERFACE/Vlan1000|192.168.0.1~121"
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan1000|192.168.0.2~121",
            "value": {}
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/Vlan1000|fc02:1000::2~164",
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_vlan_interface_tc5_remove(duthost):
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
    finally:
        delete_tmpfile(duthost, tmpfile)

def test_vlan_interface_tc6_incremental_change(duthost):
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

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)
