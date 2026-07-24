import logging
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
)
from tests.transceiver.attribute_parser.paths import get_repo_root
from tests.transceiver.cdb_firmware_upgrade.parser import TransceiverFirmwareInfoParser
from tests.transceiver.cdb_firmware_upgrade.utils.firmware_utils import (
    get_required_firmware_metadata_for_all_transceivers,
    get_dut_firmware_base_url,
    prepare_firmware_base_directory_on_dut,
    download_and_validate_firmware_binaries,
    stage_prestaged_firmware_binaries,
    cleanup_firmware_files,
)
from tests.transceiver.cdb_firmware_upgrade.port_selection import (
    get_qualifying_ports,
    resolve_ports_under_test,
)
from tests.transceiver.common import cli_helpers

CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT = "/tmp/cmis_cdb_firmware"
CMIS_CDB_FIRMWARE_PRESTAGED_PATH_ON_DUT = "/host/cmis_cdb_firmware"


logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="session")
def _cdb_firmware_session_prerequisites(presence_verified, links_verified):
    """Autouse wrapper that pulls in the session-scoped prerequisite gates
    consumed by CDB firmware-upgrade tests.

    Requesting ``presence_verified`` and ``links_verified`` ensures both gates
    run once per session before any CDB firmware test executes; on failure a
    gate calls ``pytest.skip(...)`` and every CDB firmware test is skipped with
    a clear reason.
    """
    return


@pytest.fixture(scope="session")
def transceiver_firmware_info_parser():
    repo_root = get_repo_root()
    firmware_info_parser = TransceiverFirmwareInfoParser(repo_root)

    if not firmware_info_parser.transceiver_firmware_info:
        pytest.skip("No transceiver firmware information found, skipping test.")

    return firmware_info_parser


@pytest.fixture(scope="session")
def required_firmware_metadata_for_all_transceivers(
    get_dev_transceiver_details,
    transceiver_firmware_info_parser,
    get_transceiver_common_attributes
):
    return get_required_firmware_metadata_for_all_transceivers(
        get_dev_transceiver_details,
        transceiver_firmware_info_parser.transceiver_firmware_info,
        transceiver_common_attributes=get_transceiver_common_attributes
    )


@pytest.fixture(scope="module", autouse=True)
def stage_latest_firmware_binaries_on_dut(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    transceiver_firmware_info_parser,
    required_firmware_metadata_for_all_transceivers
):
    logger.info("Staging latest CMIS CDB firmware binaries on DUT")
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    firmware_metadata = required_firmware_metadata_for_all_transceivers
    if not firmware_metadata:
        pytest.skip("No transceiver firmware information found, skipping test.")

    prepare_firmware_base_directory_on_dut(duthost, CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT)

    # Mode is chosen by whether a firmware base URL is configured for this inventory:
    # download mode when present, otherwise pre-staged mode (binaries already on the DUT).
    firmware_base_url_dict = transceiver_firmware_info_parser.firmware_base_url_dict
    if firmware_base_url_dict:
        dut_firmware_base_url = get_dut_firmware_base_url(duthost, firmware_base_url_dict)
        logger.info("Download mode: staging firmware from %s", dut_firmware_base_url)
        download_and_validate_firmware_binaries(
            duthost,
            dut_firmware_base_url,
            firmware_metadata,
            CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT
        )
    else:
        logger.info("Pre-staged mode: staging firmware from %s", CMIS_CDB_FIRMWARE_PRESTAGED_PATH_ON_DUT)
        stage_prestaged_firmware_binaries(
            duthost,
            CMIS_CDB_FIRMWARE_PRESTAGED_PATH_ON_DUT,
            firmware_metadata,
            CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT
        )
    logger.info("All latest firmware staged to {}".format(CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT))


@pytest.fixture
def dom_polling_disabled(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, get_lport_to_pport_mapping
):
    """Disable DOM polling on the ports under test, restoring it on teardown.

    Scope is intentionally function (the default): upcoming firmware-operation
    tests re-validate DOM values after each test, which requires DOM to be
    re-enabled between tests.  Function scope gives a per-test
    disable -> yield -> re-enable cycle.
    """
    ports_under_test = resolve_ports_under_test(get_lport_to_pport_mapping, port_attributes_dict)
    qualifying_ports = get_qualifying_ports(
        port_attributes_dict, lport_to_first_subport_mapping, ports_under_test
    )

    sleep_sec = 0
    disabled_ports = []
    try:
        for port in qualifying_ports:
            cdb_attrs = port_attributes_dict[port].get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
            sleep_sec = max(sleep_sec, cdb_attrs.get("sleep_after_dom_disable_sec", 0))
            if cli_helpers.get_dom_polling(duthost, port) == "disabled":
                logger.debug("Port %s: DOM polling already disabled", port)
                continue
            err = cli_helpers.set_dom_polling(duthost, port, enable=False)
            if err:
                pytest.fail(f"Failed to disable DOM polling: {err}")
            disabled_ports.append(port)
        if disabled_ports:
            logger.info("Disabled DOM polling on %d port(s); waiting %ds", len(disabled_ports), sleep_sec)
            time.sleep(sleep_sec)
        yield
    finally:
        for port in disabled_ports:
            err = cli_helpers.set_dom_polling(duthost, port, enable=True)
            if err:
                logger.warning("Failed to re-enable DOM polling on %s: %s", port, err)
        if disabled_ports:
            logger.info("Re-enabled DOM polling on %d port(s)", len(disabled_ports))


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
