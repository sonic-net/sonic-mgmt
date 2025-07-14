import os
import logging
from packaging.version import parse as parse_version
import pytest

logger = logging.getLogger(__name__)

NUM_LATEST_FIRMWARE_VERSIONS = 2  # Number of latest firmware versions to retrieve


def get_transceiver_gold_firmware_version(normalized_vendor_pn, transceiver_common_attributes):
    """
    Returns the gold firmware version for the given transceiver
    normalized vendor part number.
    The active_firmware field in transceiver_common_attributes corresponds to the
    gold firmware version.

    @param normalized_vendor_pn: Normalized vendor part number of the transceiver.
    @param transceiver_common_attributes: Dictionary containing common attributes of transceivers.
    @return: Returns the gold firmware version as a string if found, otherwise None.
    """
    if not normalized_vendor_pn:
        pytest.fail("Normalized vendor part number is required to retrieve gold firmware version.")

    transceiver_metadata = transceiver_common_attributes.get(normalized_vendor_pn)
    if transceiver_metadata is None:
        logger.warning(f"No transceiver metadata found for {normalized_vendor_pn}")
        return None

    logger.info(f"Retrieving gold firmware version for {normalized_vendor_pn}")
    return transceiver_metadata.get("active_firmware")


def get_transceiver_gold_firmware_metadata(
        normalized_vendor_name,
        normalized_vendor_pn,
        transceiver_firmware_info,
        transceiver_common_attributes
):
    """
    Returns the gold firmware metadata for a transceiver type based on its normalized vendor name
    and normalized vendor part number.
    @param normalized_vendor_name: Normalized vendor name of the transceiver.
    @param normalized_vendor_pn: Normalized vendor part number of the transceiver.
    @param transceiver_firmware_info: Dictionary that contains transceiver firmware metadata and attributes.
    @param transceiver_common_attributes: Dictionary containing common attributes of transceivers.
    @return: Returns the gold firmware metadata dictionary if found, otherwise an empty dictionary.
    """
    firmware_metadata_list = get_firmware_metadata_list_by_transceiver_type(
        normalized_vendor_name,
        normalized_vendor_pn,
        transceiver_firmware_info,
    )

    if not firmware_metadata_list:
        logger.warning(
            f"No firmware metadata available for transceiver type {normalized_vendor_name} {normalized_vendor_pn}"
        )
        return {}

    transceiver_gold_firmware_version = get_transceiver_gold_firmware_version(
        normalized_vendor_pn,
        transceiver_common_attributes,
    )
    if not transceiver_gold_firmware_version:
        logger.warning(
            f"No gold firmware version found for transceiver type {normalized_vendor_name} {normalized_vendor_pn}"
        )
        return {}

    for firmware_metadata in firmware_metadata_list:
        if firmware_metadata.get("version") == transceiver_gold_firmware_version:
            return firmware_metadata

    logger.error(
        f"No gold firmware metadata found for version {transceiver_gold_firmware_version} "
        f"in {normalized_vendor_name} {normalized_vendor_pn}"
    )
    return {}


def get_firmware_metadata_list_by_transceiver_type(
    normalized_vendor_name,
    normalized_vendor_pn,
    transceiver_firmware_info,
):
    """
    Returns all firmware metadata for a transceiver type based on its normalized vendor name
    and normalized vendor part number.
    @param normalized_vendor_name: Normalized vendor name of the transceiver.
    @param normalized_vendor_pn: Normalized vendor part number of the transceiver.
    @param transceiver_firmware_info: Dictionary that contains transceiver firmware metadata.
    @return: Returns a list of firmware metadata dictionaries if found, otherwise an empty list.
    """
    if not normalized_vendor_name or not normalized_vendor_pn:
        pytest.fail("Normalized vendor name and part number are required to retrieve firmware metadata.")

    key = (normalized_vendor_name, normalized_vendor_pn)
    firmware_metadata_list = transceiver_firmware_info.get(key)
    if firmware_metadata_list is None:
        logger.warning(f"No firmware metadata found for transceiver type {key}")
        return []

    logger.info(f"Found firmware metadata for transceiver type {key}")
    return firmware_metadata_list


def get_latest_two_firmware_metadata_for_all_transceivers(
    get_dev_transceiver_details,
    transceiver_firmware_info,
    include_gold_firmware=False,
    transceiver_common_attributes=None,
):
    """
    Finds all types of transceivers installed on the DUT and returns
    the most recent two firmware versions for each type of transceiver.

    @param get_dev_transceiver_details: Dictionary of port transceiver details
    @param transceiver_firmware_info: Dictionary containing transceiver firmware information
    @param include_gold_firmware: Whether to include gold firmware metadata
    @param transceiver_common_attributes: Dictionary containing common attributes of transceivers
                                          (required if include_gold_firmware is True)
    @return: Dictionary of transceiver types with (normalized vendor name, part number) as keys,
             and a list of the most recent firmware metadata as values.
    @raises: pytest.skip if no transceiver details or firmware versions found
    @raises: pytest.fail if gold firmware is requested but transceiver_common_attributes not provided or
                if not enough firmware versions are available for a transceiver type.
    """
    if not get_dev_transceiver_details:
        pytest.skip("No transceiver details available, skipping test.")

    if include_gold_firmware and not transceiver_common_attributes:
        pytest.fail("Transceiver common attributes are required to include gold firmware.")

    firmware_metadata_by_transceiver_type = {}

    for port, port_transceiver_info in get_dev_transceiver_details.items():
        if not port_transceiver_info:
            logger.warning(f"No transceiver info found for port {port}")
            continue

        # Extract normalized vendor name and part number
        normalized_vendor_name = port_transceiver_info.get('normalized_vendor_name')
        normalized_vendor_pn = port_transceiver_info.get('normalized_vendor_pn')

        # Validate required fields
        if not normalized_vendor_name or not normalized_vendor_pn:
            logger.warning(f"Missing normalized vendor name or part number for port {port}")
            continue

        transceiver_key = (normalized_vendor_name, normalized_vendor_pn)

        # Skip if we've already processed this transceiver type
        if transceiver_key in firmware_metadata_by_transceiver_type:
            continue

        # Get firmware metadata for this transceiver type
        firmware_metadata_list = get_firmware_metadata_list_by_transceiver_type(
            normalized_vendor_name,
            normalized_vendor_pn,
            transceiver_firmware_info
        )
        if not firmware_metadata_list:
            logger.info(f"No firmware metadata found for transceiver type {transceiver_key}")
            continue

        # Sort firmware versions in descending order (newest first)
        try:
            sorted_firmware = sorted(
                firmware_metadata_list,
                key=lambda firmware: parse_version(firmware.get('version')),
                reverse=True
            )
        except Exception as e:
            logger.error(f"Error sorting firmware versions for {transceiver_key}: {e}")
            continue

        # Select the required number of latest firmware versions
        num_available = len(sorted_firmware)
        if num_available < NUM_LATEST_FIRMWARE_VERSIONS:
            pytest.fail(
                f"Only {num_available} firmware versions available for transceiver "
                f"type {transceiver_key}, but {NUM_LATEST_FIRMWARE_VERSIONS} required. "
                f"Available versions: {[fw.get('version') for fw in sorted_firmware]}"
            )
        else:
            selected_firmware = sorted_firmware[:NUM_LATEST_FIRMWARE_VERSIONS]

        # Add gold firmware if requested
        if include_gold_firmware:
            gold_firmware_metadata = get_transceiver_gold_firmware_metadata(
                normalized_vendor_name,
                normalized_vendor_pn,
                transceiver_firmware_info,
                transceiver_common_attributes
            )
            if gold_firmware_metadata:
                # Add gold firmware and remove duplicates while preserving order
                all_firmware = selected_firmware + [gold_firmware_metadata]
                seen_versions = set()
                unique_firmware = []
                for firmware in all_firmware:
                    version = firmware.get('version')
                    if version and version not in seen_versions:
                        seen_versions.add(version)
                        unique_firmware.append(firmware)
                selected_firmware = unique_firmware
                if len(selected_firmware) < NUM_LATEST_FIRMWARE_VERSIONS + 1:
                    pytest.fail(
                        f"Not enough unique firmware versions found for transceiver type {transceiver_key}. "
                        f"Expected at least {NUM_LATEST_FIRMWARE_VERSIONS + 1}, found {len(selected_firmware)}."
                    )
            else:
                logger.error(f"No gold firmware metadata found for transceiver type {transceiver_key}")

        firmware_metadata_by_transceiver_type[transceiver_key] = selected_firmware

    if not firmware_metadata_by_transceiver_type:
        pytest.skip("No transceiver types found with firmware versions, skipping test.")

    logger.info(f"Found firmware metadata for {len(firmware_metadata_by_transceiver_type)} transceiver types")
    for transceiver_type, firmware_list in firmware_metadata_by_transceiver_type.items():
        versions = [fw.get('version', 'unknown') for fw in firmware_list]
        logger.info(f"Transceiver type {transceiver_type}: versions {versions}")

    return firmware_metadata_by_transceiver_type


def get_dut_firmware_base_url(duthost, firmware_base_url_dict):
    """
    Returns the firmware base URL for the given DUT host.

    @param duthost: DUT host object containing hostname information
    @param firmware_base_url_dict: Dictionary mapping DUT names to firmware base URLs
    @return: Firmware base URL string for the DUT
    @raises: pytest.fail if no matching URL is found
    """
    for dut_inv_name, firmware_base_url in firmware_base_url_dict.items():
        if dut_inv_name in duthost.hostname:
            logger.info(f"Found firmware base URL for DUT {duthost.hostname}: {firmware_base_url}")
            return firmware_base_url
    pytest.fail(f"No firmware base URL found for DUT {duthost.hostname} in the firmware base URL dictionary.")


def prepare_firmware_base_directory_on_dut(duthost, firmware_base_path):
    """
    Prepares the firmware directory on the DUT by cleaning and recreating it.

    @param duthost: DUT host object for running commands
    @param firmware_base_path: Base path to prepare on the DUT
    """
    if not firmware_base_path:
        pytest.fail("Base path for firmware directory cannot be empty.")
    logger.info(f"Creating base directory for firmware on DUT: {firmware_base_path}")
    duthost.command(f"rm -rf {firmware_base_path}/*")
    duthost.command(f"mkdir -p {firmware_base_path}")


def download_firmware_binary(duthost, src_url, dest_path):
    """
    Downloads a firmware binary from src_url to dest_path on the DUT.

    @param duthost: DUT host object for running commands
    @param src_url: Source URL for the firmware binary
    @param dest_path: Destination path on the DUT
    @raises: pytest.fail if download fails
    """
    logger.info(f"Downloading firmware from {src_url} to {dest_path}")
    duthost.command(f"mkdir -p {os.path.dirname(dest_path)}")
    result = duthost.command(f"curl -o {dest_path} {src_url}")
    if result['rc'] != 0:
        pytest.fail(f"Failed to download firmware from {src_url}. Error: {result['stderr']}")
    logger.info(f"Downloaded firmware to {dest_path}")


def verify_firmware_checksum(duthost, file_path, expected_md5sum):
    """
    Verifies the md5 checksum of the file at file_path on the DUT.

    @param duthost: DUT host object for running commands
    @param file_path: Path to the file on the DUT
    @param expected_md5sum: Expected MD5 checksum string
    @raises: pytest.fail if checksums don't match
    """
    logger.info(f"Verifying checksum for {file_path}")
    result = duthost.command(f"md5sum {file_path}")
    actual_md5sum = result['stdout'].split()[0]
    if actual_md5sum != expected_md5sum:
        pytest.fail(f"Checksum mismatch for {file_path}. Expected: {expected_md5sum}, Found: {actual_md5sum}")
    logger.info(f"Checksum verified for {file_path}")


def download_and_validate_firmware_binaries(duthost, firmware_base_url, firmware_metadata_by_type, base_path):
    """
    Downloads firmware binaries for each transceiver type to the DUT.
    Also, compares the checksum of the downloaded binary with the expected checksum

    @param duthost: DUT host object for running commands
    @param firmware_base_url: Base URL for firmware downloads
    @param firmware_metadata_by_type: Dictionary mapping transceiver types to firmware metadata
    @param base_path: Base path on DUT where firmware will be stored
    """
    for transceiver_type, firmware_metadata_list in firmware_metadata_by_type.items():
        normalized_vendor_name, normalized_vendor_pn = transceiver_type
        for firmware_metadata in firmware_metadata_list:
            fw_binary_path_on_server = os.path.join(
                firmware_base_url,
                normalized_vendor_name,
                normalized_vendor_pn,
                firmware_metadata['binary']
            )
            fw_binary_path_on_dut = os.path.join(
                base_path,
                normalized_vendor_name,
                normalized_vendor_pn,
                firmware_metadata['binary']
            )

            download_firmware_binary(duthost, fw_binary_path_on_server, fw_binary_path_on_dut)
            verify_firmware_checksum(duthost, fw_binary_path_on_dut, firmware_metadata['md5sum'])
    logger.info("All firmware binaries downloaded and verified successfully.")


def cleanup_firmware_files(duthost, firmware_base_path):
    """
    Remove the entire firmware directory and all its contents from DUT.

    @param duthost: DUT host object for running commands
    @param firmware_base_path: Base path on DUT where firmware directory is located
    """
    try:
        if not firmware_base_path:
            pytest.fail("Firmware base path cannot be empty.")
        logger.info(f"Removing firmware directory {firmware_base_path} and all its contents")
        duthost.shell(f"rm -rf {firmware_base_path}", module_ignore_errors=True)
        logger.info(f"Firmware directory {firmware_base_path} removed successfully")
    except Exception as e:
        logger.warning(f"Failed to remove firmware directory {firmware_base_path}: {e}")
