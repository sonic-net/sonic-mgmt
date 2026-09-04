import logging
import os
import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
)

logger = logging.getLogger(__name__)

EXPECTED_FIRMWARE_VERSIONS_COUNT = 3


def get_required_firmware_metadata_for_all_transceivers(
    port_attributes_dict,
    transceiver_firmware_info,
    qualifying_ports,
):
    """Return exact manifest metadata for each qualifying port's firmware_versions."""
    if not port_attributes_dict:
        pytest.skip("No port attributes available, skipping test.")
    if not qualifying_ports:
        pytest.skip("No qualifying CDB firmware ports found, skipping test.")

    firmware_metadata_by_transceiver_type = {}
    failures = []

    for port in qualifying_ports:
        port_attrs = port_attributes_dict[port]
        base_attrs = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
        cdb_attrs = port_attrs.get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})
        normalized_vendor_name = base_attrs.get("normalized_vendor_name")
        normalized_vendor_pn = base_attrs.get("normalized_vendor_pn")
        if not normalized_vendor_name or not normalized_vendor_pn:
            failures.append(f"{port}: normalized vendor name or part number is missing")
            continue

        transceiver_key = (normalized_vendor_name, normalized_vendor_pn)
        firmware_versions = cdb_attrs.get("firmware_versions")
        if not firmware_versions:
            failures.append(f"{port}: firmware_versions is missing or empty")
            continue
        if len(firmware_versions) != EXPECTED_FIRMWARE_VERSIONS_COUNT:
            failures.append(
                f"{port}: firmware_versions must contain exactly "
                f"{EXPECTED_FIRMWARE_VERSIONS_COUNT} entries, got {len(firmware_versions)}"
            )
            continue
        if len(set(firmware_versions)) != len(firmware_versions):
            failures.append(f"{port}: firmware_versions must not contain duplicates: {firmware_versions}")
        gold_firmware_version = cdb_attrs.get("gold_firmware_version")
        if gold_firmware_version != firmware_versions[-1]:
            failures.append(
                f"{port}: gold_firmware_version '{gold_firmware_version}' must be the last entry "
                f"in firmware_versions {firmware_versions}"
            )
        if cdb_attrs.get("dual_bank_supported", True):
            inactive_firmware_version = cdb_attrs.get("inactive_firmware_version")
            if inactive_firmware_version != firmware_versions[-2]:
                failures.append(
                    f"{port}: inactive_firmware_version '{inactive_firmware_version}' must be the "
                    f"second to last entry in firmware_versions {firmware_versions}"
                )
        if transceiver_key in firmware_metadata_by_transceiver_type:
            continue

        firmware_metadata_list = transceiver_firmware_info.get(transceiver_key)
        if not firmware_metadata_list:
            failures.append(f"{port}: no firmware manifest metadata found for transceiver type {transceiver_key}")
            continue

        metadata_by_version = {}
        for firmware_metadata in firmware_metadata_list:
            version = firmware_metadata.get("version")
            if version:
                metadata_by_version[version] = firmware_metadata

        missing_versions = [
            version for version in firmware_versions if version not in metadata_by_version
        ]
        if missing_versions:
            failures.append(
                f"{port}: firmware version(s) {missing_versions} for {transceiver_key} "
                "are missing from the manifest"
            )
            continue

        selected_firmware = [metadata_by_version[version] for version in firmware_versions]
        incomplete_versions = [
            fw.get("version") for fw in selected_firmware
            if not fw.get("binary") or not fw.get("md5sum")
        ]
        if incomplete_versions:
            failures.append(
                f"{port}: incomplete firmware metadata for {transceiver_key} version(s) {incomplete_versions}"
            )
            continue

        firmware_metadata_by_transceiver_type[transceiver_key] = selected_firmware

    if failures:
        pytest.fail("Firmware metadata validation failures:\n" + "\n".join(failures))

    logger.info(f"Found firmware metadata for {len(firmware_metadata_by_transceiver_type)} transceiver types")
    for transceiver_type, firmware_list in firmware_metadata_by_transceiver_type.items():
        versions = [fw.get('version', 'unknown') for fw in firmware_list]
        logger.info(f"Transceiver type {transceiver_type}: versions {versions}")

    return firmware_metadata_by_transceiver_type


def resolve_binary_path(metadata_map, vendor, pn, version):
    """Return ``(dut_path, err)`` for the staged ``(vendor, pn, version)`` binary."""
    entries = metadata_map.get((vendor, pn))
    if not entries:
        return None, f"no staged firmware metadata for ({vendor}, {pn})"
    for entry in entries:
        if entry["version"] == version:
            return entry["dut_path"], None
    return None, f"firmware version {version} not staged for ({vendor}, {pn})"


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
                firmware_metadata['version'],
                firmware_metadata['binary']
            )
            fw_binary_path_on_dut = os.path.join(
                base_path,
                normalized_vendor_name,
                normalized_vendor_pn,
                firmware_metadata['version'],
                firmware_metadata['binary']
            )
            firmware_metadata['dut_path'] = fw_binary_path_on_dut

            download_firmware_binary(duthost, fw_binary_path_on_server, fw_binary_path_on_dut)
            verify_firmware_checksum(duthost, fw_binary_path_on_dut, firmware_metadata['md5sum'])
    logger.info("All firmware binaries downloaded and verified successfully.")


def copy_firmware_binary(duthost, src_path, dest_path):
    """
    Copies a pre-staged firmware binary already present on the DUT from src_path to dest_path.

    @param duthost: DUT host object for running commands
    @param src_path: Source path of the pre-staged firmware binary on the DUT
    @param dest_path: Destination path on the DUT
    @raises: pytest.fail if the source is missing or the copy fails
    """
    logger.info(f"Copying pre-staged firmware from {src_path} to {dest_path}")
    if duthost.command(f'test -f "{src_path}"', module_ignore_errors=True)['rc'] != 0:
        pytest.fail(f"Pre-staged firmware binary not found on DUT: {src_path}")
    duthost.command(f'mkdir -p "{os.path.dirname(dest_path)}"')
    result = duthost.command(f'cp "{src_path}" "{dest_path}"', module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail(f"Failed to copy firmware from {src_path}. Error: {result['stderr']}")
    logger.info(f"Copied firmware binaries to {dest_path}")


def stage_prestaged_firmware_binaries(duthost, firmware_host_path, firmware_metadata_by_type, base_path):
    """
    Stages pre-staged firmware binaries for each transceiver type into the test directory on the DUT.

    Used when no firmware base URL is configured (pre-staged mode): the binaries are expected to
    already exist on the DUT under firmware_host_path using the same normalized layout as the
    download source. Each binary is copied into base_path and its checksum verified.

    @param duthost: DUT host object for running commands
    @param firmware_host_path: Base path on the DUT where pre-staged binaries live (e.g. /host/cmis_cdb_firmware)
    @param firmware_metadata_by_type: Dictionary mapping transceiver types to firmware metadata
    @param base_path: Base path on DUT where firmware will be staged for the test run
    """
    for transceiver_type, firmware_metadata_list in firmware_metadata_by_type.items():
        normalized_vendor_name, normalized_vendor_pn = transceiver_type
        for firmware_metadata in firmware_metadata_list:
            fw_binary_path_on_host = os.path.join(
                firmware_host_path,
                normalized_vendor_name,
                normalized_vendor_pn,
                firmware_metadata['version'],
                firmware_metadata['binary']
            )
            fw_binary_path_on_dut = os.path.join(
                base_path,
                normalized_vendor_name,
                normalized_vendor_pn,
                firmware_metadata['version'],
                firmware_metadata['binary']
            )
            firmware_metadata['dut_path'] = fw_binary_path_on_dut

            copy_firmware_binary(duthost, fw_binary_path_on_host, fw_binary_path_on_dut)
            verify_firmware_checksum(duthost, fw_binary_path_on_dut, firmware_metadata['md5sum'])
    logger.info("All pre-staged firmware binaries copied and verified successfully.")


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
