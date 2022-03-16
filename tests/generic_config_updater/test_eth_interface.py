import ipaddress
import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

logger = logging.getLogger(__name__)


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


def check_interface_status(duthost, field):
    """
    Returns current status for Ethernet0 of specified field

    Args:
        duthost: DUT host object under test
        field: interface field under test
    """

    cmds = "show interface status Ethernet0"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'])
    status_data = output["stdout_lines"]
    
    field_index = status_data[0].split().index(field)
    for line in status_data:
        if "Ethernet0" in line:
            ethernet0_status = line.strip()
    pytest_assert(len(ethernet0_status) > 0, "Failed to read Ethernet0 interface properties")
    status = re.split(r" {2,}", ethernet0_status)[field_index]
    return status


def test_remove_lanes(duthost, ensure_dut_readiness):
    json_patch = [
        {
            "op": "remove",
            "path": "/PORT/Ethernet0/lanes"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_replace_lanes(duthost, ensure_dut_readiness):
    cur_lanes = check_interface_status(duthost, "Lanes")
    cur_lanes = cur_lanes.split(",")
    cur_lanes.sort()
    update_lanes = cur_lanes
    update_lanes[-1] = str(int(update_lanes[-1]) + 1)
    update_lanes = ",".join(update_lanes)
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/lanes",
            "value": "{}".format(update_lanes)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_replace_mtu(duthost, ensure_dut_readiness):
    target_mtu = "1514"
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/mtu",
            "value": "{}".format(target_mtu)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        current_status_mtu = check_interface_status(duthost, "MTU")
        pytest_assert(current_status_mtu == target_mtu, "Failed to properly configure interface MTU to requested value {}".format(target_mtu))
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("pfc_asym", ["on", "off"])
def test_toggle_pfc_asym(duthost, ensure_dut_readiness, pfc_asym):
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/pfc_asym",
            "value": "{}".format(pfc_asym)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        current_status_pfc_asym = check_interface_status(duthost, "Asym")
        pytest_assert(current_status_pfc_asym == pfc_asym, "Failed to properly configure interface Asym PFC to requested value off")
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("fec", ["rs", "fc"])
def test_replace_fec(duthost, ensure_dut_readiness, fec):
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/fec",
            "value": "{}".format(fec)
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        current_status_fec = check_interface_status(duthost, "FEC")
        pytest_assert(current_status_fec == fec, "Failed to properly configure interface FEC to requested value {}".format(fec))
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("index, is_valid", [
    ("33", True),
    ("abc1", False)
])
def test_update_valid_invalid_index(duthost, ensure_dut_readiness, index, is_valid):
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/index",
            "value": "{}".format(index)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid:
            expect_op_success(duthost, output)
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("speed, is_valid", [
    ("20000", True),
    ("40000", True),
    ("20a", False)
])
def test_update_speed(duthost, ensure_dut_readiness, speed, is_valid):
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/speed",
            "value": "{}".format(speed)
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if is_valid:
            expect_op_success(duthost, output)
            current_status_speed = check_interface_status(duthost, "Speed").replace("G", "000")
            pytest_assert(current_status_speed == speed, "Failed to properly configure interface speed to requested value {}".format(speed))
        else:
            expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def test_update_description(duthost, ensure_dut_readiness):
    json_patch = [
        {
            "op": "replace",
            "path": "/PORT/Ethernet0/description",
            "value": "Updated description"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.parametrize("admin_status", ["up", "down"])
def test_eth_interface_admin_change(duthost, admin_status):
    json_patch = [
        {
            "op": "add",
            "path": "/PORT/Ethernet0/admin_status",
            "value": "{}".format(admin_status)
        }
    ]
    
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        
        running_status = check_interface_status(duthost, "Admin")
        pytest_assert(admin_status == running_status, "Interface failed to update admin status to {}".format(admin_status))
    finally:
        delete_tmpfile(duthost, tmpfile)
