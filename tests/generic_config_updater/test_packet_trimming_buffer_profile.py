import logging
import pytest

from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.helpers.trimming_help import (
    TRIMMING_BUFFER_PROFILE_CONFIG, buffer_profile_exists, buffer_profile_has_field)

pytestmark = [
    pytest.mark.topology("t0", "t1")
]

logger = logging.getLogger(__name__)

LOSSY_BUFFER_PROFILE_NAME = "queue1_downlink_lossy_profile"

GENERIC_BUFFER_PROFILE_NAME = "queue_trim_gcu_test_profile"
GENERIC_BUFFER_PROFILE_CONFIG = TRIMMING_BUFFER_PROFILE_CONFIG

# Packet discard action values
TRIMMING_ACTION_ENABLE = "trim"
TRIMMING_ACTION_DISABLE = "drop"
TRIMMING_ACTION_INVALID = "invalid_action"


@pytest.fixture(autouse=True)
def setup_env(duthost):
    """
    Setup/teardown fixture for buffer profile trimming action test.

    Args:
        duthost: DUT.
    """
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)

    finally:
        delete_checkpoint(duthost)


@pytest.fixture
def trimming_buffer_profile(rand_selected_dut, setup_env, skip_if_packet_trimming_not_supported):
    """
    Resolve the BUFFER_PROFILE used by the packet trimming action tests.

    Reuse the pre-defined profile if it exists; otherwise create a trimming profile via GCU
    (removed by rollback_or_reload during teardown). Returns the buffer profile name to use.
    """
    duthost = rand_selected_dut

    if buffer_profile_exists(duthost, LOSSY_BUFFER_PROFILE_NAME) and \
            buffer_profile_has_field(duthost, LOSSY_BUFFER_PROFILE_NAME, "packet_discard_action"):
        logger.info(f"Using pre-defined buffer profile '{LOSSY_BUFFER_PROFILE_NAME}'")
        return LOSSY_BUFFER_PROFILE_NAME

    logger.info(
        f"Buffer profile '{LOSSY_BUFFER_PROFILE_NAME}' not present; creating "
        f"'{GENERIC_BUFFER_PROFILE_NAME}' for the trimming action test")

    json_patch = [
        {
            "op": "add",
            "path": f"/BUFFER_PROFILE/{GENERIC_BUFFER_PROFILE_NAME}",
            "value": GENERIC_BUFFER_PROFILE_CONFIG
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=duthost, json_data=json_patch)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

    return GENERIC_BUFFER_PROFILE_NAME


@pytest.mark.parametrize("action_value", [TRIMMING_ACTION_DISABLE, TRIMMING_ACTION_ENABLE])
def test_packet_trimming_buffer_profile_action(
    rand_selected_dut, loganalyzer, trimming_buffer_profile, action_value
):
    """
    Test packet trimming buffer profile action configuration.
    """
    json_patch = [
        {
            "op": "replace",
            "path": f"/BUFFER_PROFILE/{trimming_buffer_profile}/packet_discard_action",
            "value": action_value
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=rand_selected_dut, json_data=json_patch)

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(rand_selected_dut, output)

    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)


def test_packet_trimming_buffer_profile_action_xfail(
    rand_selected_dut, loganalyzer, trimming_buffer_profile
):
    """
    Negative test for packet_discard_action with invalid value.
    """
    # Ignore expected error logs during rollback
    if loganalyzer:
        ignoreRegex = [
            r'.*sonic_yang: Data Loading Failed:Invalid value .* in "packet_discard_action" element.*'
        ]
        loganalyzer[rand_selected_dut.hostname].ignore_regex.extend(ignoreRegex)

    json_patch = [
        {
            "op": "replace",
            "path": f"/BUFFER_PROFILE/{trimming_buffer_profile}/packet_discard_action",
            "value": TRIMMING_ACTION_INVALID
        }
    ]
    json_patch = format_json_patch_for_multiasic(duthost=rand_selected_dut, json_data=json_patch)

    tmpfile = generate_tmpfile(rand_selected_dut)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(rand_selected_dut, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)

    finally:
        delete_tmpfile(rand_selected_dut, tmpfile)
