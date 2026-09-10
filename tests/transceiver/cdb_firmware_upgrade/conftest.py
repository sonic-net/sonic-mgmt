import logging
import time
from contextlib import contextmanager

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.cdb_firmware_upgrade.parser import TransceiverFirmwareInfoParser
from tests.transceiver.cdb_firmware_upgrade.utils.firmware_utils import (
    get_required_firmware_metadata_for_all_transceivers,
    get_dut_firmware_base_url,
    prepare_firmware_base_directory_on_dut,
    download_and_validate_firmware_binaries,
    stage_prestaged_firmware_binaries,
    cleanup_firmware_files,
)
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.db_helpers import get_db_hash_field, resolve_port_namespace
from tests.transceiver.common.eeprom_decode import is_cmis_active_optical
from tests.transceiver.common.port_selectors import (
    resolve_ports_under_test,
    select_attribute_ports,
)
from tests.transceiver.cdb_firmware_upgrade.firmware_operations import (
    execute_on_ports,
    restore_module_to_original,
)

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
def transceiver_firmware_info_parser(ansible_root):
    firmware_info_parser = TransceiverFirmwareInfoParser(ansible_root)

    if not firmware_info_parser.transceiver_firmware_info:
        pytest.skip("No transceiver firmware information found, skipping test.")

    return firmware_info_parser


@pytest.fixture(scope="session")
def required_firmware_metadata_for_all_transceivers(
    port_attributes_dict,
    transceiver_firmware_info_parser,
    cdb_firmware_qualifying_ports,
):
    return get_required_firmware_metadata_for_all_transceivers(
        port_attributes_dict,
        transceiver_firmware_info_parser.transceiver_firmware_info,
        cdb_firmware_qualifying_ports,
    )


@pytest.fixture(scope="package", autouse=True)
def stage_latest_firmware_binaries_on_dut(
    duthost,
    transceiver_firmware_info_parser,
    required_firmware_metadata_for_all_transceivers
):
    logger.info("Staging latest CMIS CDB firmware binaries on DUT")

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


@pytest.fixture(scope="session")
def cdb_firmware_qualifying_ports(
    port_attributes_dict, lport_to_first_subport_mapping, get_lport_to_pport_mapping,
):
    """CMIS active-optical first-subport ports the CDB firmware tests run on.

    Selection is the CDB attribute category gated by the EEPROM ``cmis_active_optical``
    flag and restricted to any configured ``ports_under_test``.
    """
    explicit_ports = resolve_ports_under_test(
        get_lport_to_pport_mapping, port_attributes_dict, CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY
    )
    qualifying_ports = select_attribute_ports(
        port_attributes_dict,
        CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        explicit_ports=explicit_ports,
        predicate=lambda port, attrs: is_cmis_active_optical(attrs.get(EEPROM_ATTRIBUTES_KEY, {})),
    ).primary_ports
    if not qualifying_ports:
        if explicit_ports is not None:
            pytest.fail(
                "ports_under_test configured but resolved to no qualifying "
                "CMIS active-optical ports"
            )
        pytest.skip("No CMIS active-optical first-subport ports found for CDB firmware tests")
    return qualifying_ports


@contextmanager
def dom_polling_disabled_on_ports(duthost, port_attributes_dict, ports):
    """Disable DOM polling on ``ports`` for the duration of the block.

    Ports already disabled are left untouched so their prior state survives.
    """
    sleep_sec = 0
    disabled_ports = []
    try:
        for port in ports:
            cdb_attrs = port_attributes_dict[port].get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
            sleep_sec = max(sleep_sec, cdb_attrs["sleep_after_dom_disable_sec"])
            namespace = resolve_port_namespace(duthost, port)
            dom_polling, err = get_db_hash_field(
                duthost, "CONFIG_DB", "PORT", port, "dom_polling", namespace=namespace
            )
            if err:
                pytest.fail(f"Failed to read dom_polling for {port}: {err}")
            if dom_polling == "disabled":
                logger.debug("Port %s: DOM polling already disabled", port)
                continue
            err = cli_helpers.set_dom_polling(duthost, port, enable=False, namespace=namespace)
            if err:
                pytest.fail(f"Failed to disable DOM polling: {err}")
            disabled_ports.append((port, namespace))
        if disabled_ports:
            logger.info("Disabled DOM polling on %d port(s); waiting %ds", len(disabled_ports), sleep_sec)
            time.sleep(sleep_sec)
        yield
    finally:
        for port, namespace in disabled_ports:
            err = cli_helpers.set_dom_polling(duthost, port, enable=True, namespace=namespace)
            if err:
                logger.warning("Failed to re-enable DOM polling on %s: %s", port, err)
        if disabled_ports:
            logger.info("Re-enabled DOM polling on %d port(s)", len(disabled_ports))


@pytest.fixture
def dom_polling_disabled(duthost, port_attributes_dict, cdb_firmware_qualifying_ports):
    """Disable DOM polling on the ports under test, restoring it on teardown.

    Firmware operation tests re-validate DOM values after each test, which
    requires DOM to be re-enabled between tests.
    """
    with dom_polling_disabled_on_ports(duthost, port_attributes_dict, cdb_firmware_qualifying_ports):
        yield


@pytest.fixture(scope="package", autouse=True)
def restore_original_firmware_baseline(
    stage_latest_firmware_binaries_on_dut, firmware_files_cleanup, duthost, port_attributes_dict,
    cdb_firmware_qualifying_ports, required_firmware_metadata_for_all_transceivers,
    get_lport_to_pport_mapping,
):
    """Restore every qualifying module to its original state before and
    after the package. Depends on ``firmware_files_cleanup`` so the
    post-package restore runs before the staged binaries are removed.
    """
    def _restore(phase):
        with dom_polling_disabled_on_ports(duthost, port_attributes_dict, cdb_firmware_qualifying_ports):
            failures, ports = execute_on_ports(
                duthost, port_attributes_dict, cdb_firmware_qualifying_ports,
                get_lport_to_pport_mapping, required_firmware_metadata_for_all_transceivers,
                restore_module_to_original,
            )
        logger.info("%s original firmware baseline on %d port(s)", phase, ports)
        if failures:
            pytest.fail(f"{phase} firmware restore failures:\n" + "\n".join(failures))

    _restore("Pre-package")
    yield
    _restore("Post-package")


@pytest.fixture(scope="package", autouse=True)
def firmware_files_cleanup(
    duthost
):
    """
    Package-scoped cleanup fixture that removes firmware files after all tests in the package complete.
    """
    yield  # This is where all tests run

    # Cleanup code runs after all tests complete (success or failure)
    try:
        logger.info("Starting firmware files cleanup...")

        # Clean up downloaded firmware files
        cleanup_firmware_files(duthost, CMIS_CDB_FIRMWARE_BASE_PATH_ON_DUT)

        logger.info("Firmware files cleanup completed successfully")

    except Exception as e:
        logger.error(f"Error during firmware files cleanup: {e}")
        # Don't raise the exception to avoid masking test failures
