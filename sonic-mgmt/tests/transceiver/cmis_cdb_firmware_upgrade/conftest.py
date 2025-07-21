import logging
import os

import pytest

from tests.transceiver.cmis_cdb_firmware_upgrade.parser import TransceiverFirmwareInfoParser
from tests.transceiver.cmis_cdb_firmware_upgrade.utils.firmware_utils import (
    get_latest_two_firmware_metadata_for_all_transceivers,
    get_dut_firmware_base_url,
    prepare_firmware_base_directory_on_dut,
    download_and_validate_firmware_binaries,
    cleanup_firmware_files,
)

CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT = "/tmp/cmis_cdb_firmware"


logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def transceiver_firmware_info_parser():
    curr_dir = os.path.dirname(os.path.realpath(__file__))
    ansible_path = os.path.join(curr_dir, '../../../ansible')
    if not os.path.exists(ansible_path):
        pytest.fail("Ansible path does not exist, please check the path: {}".format(ansible_path))
    firmware_info_parser = TransceiverFirmwareInfoParser(ansible_path)

    if not firmware_info_parser.transceiver_firmware_info:
        pytest.skip("No transceiver firmware information found, skipping test.")

    if not firmware_info_parser.firmware_base_url_dict:
        pytest.skip("No firmware base URL found, skipping test.")

    return firmware_info_parser


@pytest.fixture(scope="session")
def get_gold_firmware_and_latest_two_firmware_metadata_for_all_transceivers(
    get_dev_transceiver_details,
    transceiver_firmware_info_parser,
    get_transceiver_common_attributes
):
    return get_latest_two_firmware_metadata_for_all_transceivers(
        get_dev_transceiver_details,
        transceiver_firmware_info_parser.transceiver_firmware_info,
        include_gold_firmware=True,
        transceiver_common_attributes=get_transceiver_common_attributes
    )


@pytest.fixture(scope="module", autouse=True)
def download_latest_firmware_binaries_on_dut(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    transceiver_firmware_info_parser,
    get_gold_firmware_and_latest_two_firmware_metadata_for_all_transceivers
):
    logger.info("Downloading latest CMIS CDB firmware binaries on DUT")
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    dut_firmware_base_url = get_dut_firmware_base_url(
        duthost, transceiver_firmware_info_parser.firmware_base_url_dict
    )

    if not get_gold_firmware_and_latest_two_firmware_metadata_for_all_transceivers:
        pytest.skip("No transceiver firmware information found, skipping test.")

    prepare_firmware_base_directory_on_dut(duthost, CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT)
    download_and_validate_firmware_binaries(
        duthost,
        dut_firmware_base_url,
        get_gold_firmware_and_latest_two_firmware_metadata_for_all_transceivers,
        CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT
    )
    logger.info("All latest firmware downloaded to {}".format(CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT))


@pytest.fixture(scope="module", autouse=True)
def firmware_files_cleanup(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname
):
    """
    Module-scoped cleanup fixture that removes firmware files after all tests in the module complete.
    """
    yield  # This is where all tests run

    # Cleanup code runs after all tests complete (success or failure)
    try:
        logger.info("Starting firmware files cleanup...")
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        # Clean up downloaded firmware files
        cleanup_firmware_files(duthost, CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT)

        logger.info("Firmware files cleanup completed successfully")

    except Exception as e:
        logger.error(f"Error during firmware files cleanup: {e}")
        # Don't raise the exception to avoid masking test failures
