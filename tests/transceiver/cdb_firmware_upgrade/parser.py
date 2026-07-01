from collections import defaultdict
import json
import logging
import os

logger = logging.getLogger(__name__)

CDB_FIRMWARE_UPGRADE_MANIFEST_FILE = "cdb_firmware_upgrade_manifest.json"
CDB_FIRMWARE_UPGRADE_URL_FILE = "cdb_firmware_upgrade_url.json"
CDB_FIRMWARE_UPGRADE_ATTRIBUTES_DIR = "attributes/cdb_firmware_upgrade"


class TransceiverFirmwareInfoParser:
    def __init__(self, ansible_path):
        self.ansible_path = ansible_path
        self.transceiver_inventory_path = os.path.join(
            self.ansible_path, "files/transceiver/inventory/"
        )
        self.cdb_firmware_upgrade_path = os.path.join(
            self.transceiver_inventory_path, CDB_FIRMWARE_UPGRADE_ATTRIBUTES_DIR
        )
        self.transceiver_firmware_info = self.parse_all_firmware_manifests()
        if not self.transceiver_firmware_info:
            logger.warning("No transceiver firmware information found.")
        else:
            logger.info(f"Transceiver Firmware Info is: {self.transceiver_firmware_info}")

        self.firmware_base_url_dict = self.parse_firmware_base_url()
        if not self.firmware_base_url_dict:
            logger.info("No firmware base URL configured, using pre-staged mode.")
        else:
            logger.info(f"Firmware Base URL is: {self.firmware_base_url_dict}")

    def parse_all_firmware_manifests(self):
        """
        Discovers and parses all per-PN cdb_firmware_upgrade_manifest.json files and
        returns a dictionary with (normalized_vendor_name, normalized_vendor_pn) as keys.
        The values are lists of dictionaries containing firmware version,
        binary filename, and md5sum information.

        Returns an empty dict if no manifests are found.
        """
        vendors_path = os.path.join(
            self.cdb_firmware_upgrade_path, "transceivers", "vendors"
        )
        firmware_data = defaultdict(list)

        if not os.path.isdir(vendors_path):
            logger.error(f"Vendors directory does not exist: {vendors_path}")
            return {}

        for vendor_name in os.listdir(vendors_path):
            pn_path = os.path.join(vendors_path, vendor_name, "part_numbers")
            if not os.path.isdir(pn_path):
                continue

            for vendor_pn in os.listdir(pn_path):
                manifest_file = os.path.join(
                    pn_path, vendor_pn, CDB_FIRMWARE_UPGRADE_MANIFEST_FILE
                )
                if not os.path.isfile(manifest_file):
                    continue

                fw_versions = self.parse_single_manifest(manifest_file, vendor_name, vendor_pn)
                if fw_versions:
                    firmware_data[(vendor_name, vendor_pn)] = fw_versions

        return dict(firmware_data)

    def parse_single_manifest(self, manifest_file, vendor_name, vendor_pn):
        """
        Parses a single per-PN cdb_firmware_upgrade_manifest.json file.

        Returns a list of firmware entry dicts, or empty list on error.
        """
        try:
            with open(manifest_file) as jsonfile:
                data = json.load(jsonfile)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading firmware manifest {manifest_file}: {e}")
            return []

        if not isinstance(data, dict):
            logger.error(f"Expected JSON object in manifest file: {manifest_file}")
            return []

        fw_versions = []
        for fw_version, metadata in data.items():
            if not isinstance(metadata, dict):
                logger.warning(
                    f"Invalid metadata for version '{fw_version}' "
                    f"in '{vendor_name}/{vendor_pn}', skipping."
                )
                continue
            fw_binary_name = metadata.get('fw_binary_name')
            md5sum = metadata.get('md5sum')
            if not fw_binary_name or not md5sum:
                logger.warning(
                    f"Missing fw_binary_name or md5sum for version '{fw_version}' "
                    f"in '{vendor_name}/{vendor_pn}', skipping."
                )
                continue
            fw_versions.append({
                'version': fw_version,
                'binary': fw_binary_name,
                'md5sum': md5sum
            })

        return fw_versions

    def parse_firmware_base_url(self):
        """
        Parses the cdb_firmware_upgrade_url.json file and returns a dictionary
        mapping inventory names to firmware base URLs.
        """
        firmware_base_url_file = os.path.join(
            self.cdb_firmware_upgrade_path, CDB_FIRMWARE_UPGRADE_URL_FILE
        )

        if not os.path.exists(firmware_base_url_file):
            logger.info(f"Firmware base URL file not found: {firmware_base_url_file} (pre-staged mode)")
            return {}

        try:
            with open(firmware_base_url_file) as jsonfile:
                url_dict = json.load(jsonfile)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading firmware base URL JSON: {e}")
            return {}

        if not isinstance(url_dict, dict):
            logger.error(f"Expected JSON object in URL file: {firmware_base_url_file}")
            return {}

        return url_dict
