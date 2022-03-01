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
    status = status_data[2].split()[field_index]
    return status
    

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
