from collections import defaultdict
import json
import logging
import os

logger = logging.getLogger(__name__)

TRANSCEIVER_FIRMWARE_INFO_FILE = "cdb_firmware_binaries.json"
CMIS_CDB_FIRMWARE_BASE_URL_FILE = "cdb_firmware_base_url.json"


class TransceiverFirmwareInfoParser:
    def __init__(self, ansible_path):
        self.ansible_path = ansible_path
        self.transceiver_inventory_path = os.path.join(
            self.ansible_path, "files/transceiver/inventory/"
        )
        self.transceiver_firmware_info = self.parse_firmware_json()
        if not self.transceiver_firmware_info:
            logger.warning("No transceiver firmware information found.")
        else:
            logger.info(f"Transceiver Firmware Info is: {self.transceiver_firmware_info}")

        self.firmware_base_url_dict = self.parse_firmware_base_url()
        if not self.firmware_base_url_dict:
            logger.warning(f"No firmware base URL found in {CMIS_CDB_FIRMWARE_BASE_URL_FILE}")
        else:
            logger.info(f"Firmware Base URL is: {self.firmware_base_url_dict}")

    def parse_firmware_json(self):
        """
        Parses the cdb_firmware_binaries.json file and returns a dictionary
        with (normalized_vendor_name, normalized_vendor_pn) as keys.
        The values are lists of dictionaries containing firmware version,
        binary filename, and md5sum information.

        Returns an empty dict if file is missing or invalid.
        """
        firmware_info_file = os.path.join(
            self.transceiver_inventory_path, TRANSCEIVER_FIRMWARE_INFO_FILE
        )
        firmware_data = defaultdict(list)

        if not os.path.exists(firmware_info_file):
            logger.error(f"Firmware info file does not exist: {firmware_info_file}")
            return {}

        try:
            with open(firmware_info_file) as jsonfile:
                data = json.load(jsonfile)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading firmware info JSON: {e}")
            return {}

        for vendor_name, part_numbers in data.items():
            for vendor_pn, versions in part_numbers.items():
                key = (vendor_name, vendor_pn)
                for fw_version, metadata in versions.items():
                    fw_binary_name = metadata.get('fw_binary_name')
                    md5sum = metadata.get('md5sum')
                    if not fw_binary_name or not md5sum:
                        logger.warning(
                            f"Missing fw_binary_name or md5sum for version '{fw_version}' "
                            f"under '{vendor_name}/{vendor_pn}', skipping."
                        )
                        continue
                    firmware_data[key].append({
                        'version': fw_version,
                        'binary': fw_binary_name,
                        'md5sum': md5sum
                    })

        return firmware_data

    def parse_firmware_base_url(self):
        """
        Parses the cdb_firmware_base_url.json file and returns a dictionary
        mapping inventory names to firmware base URLs.
        """
        firmware_base_url_file = os.path.join(
            self.transceiver_inventory_path, CMIS_CDB_FIRMWARE_BASE_URL_FILE
        )

        if not os.path.exists(firmware_base_url_file):
            logger.error(f"Firmware base URL file does not exist: {firmware_base_url_file}")
            return {}

        try:
            with open(firmware_base_url_file) as jsonfile:
                url_dict = json.load(jsonfile)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading firmware base URL JSON: {e}")
            return {}

        return url_dict
