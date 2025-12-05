from collections import defaultdict
import csv
import logging
import os

logger = logging.getLogger(__name__)

TRANSCEIVER_FIRMWARE_INFO_FILE = "transceiver_firmware_info.csv"
CMIS_CDB_FIRMWARE_BASE_URL_FILE = "cmis_cdb_firmware_base_url.csv"


class TransceiverFirmwareInfoParser:
    def __init__(self, ansible_path):
        self.ansible_path = ansible_path
        self.transceiver_inventory_path = os.path.join(
            self.ansible_path, "files/transceiver_inventory/"
        )
        self.transceiver_firmware_info = self.parse_firmware_csv()
        if not self.transceiver_firmware_info:
            logger.warning("No transceiver firmware information found.")
        else:
            logger.info(f"Transceiver Firmware Info is: {self.transceiver_firmware_info}")

        self.firmware_base_url_dict = self.parse_firmware_base_url()
        if not self.firmware_base_url_dict:
            logger.warning(f"No firmware base URL found in {CMIS_CDB_FIRMWARE_BASE_URL_FILE}")
        else:
            logger.info(f"Firmware Base URL is: {self.firmware_base_url_dict}")

    def parse_firmware_csv(self):
        """
        Parses the TRANSCEIVER_FIRMWARE_INFO_FILE and returns a
        dictionary with (normalized_vendor_name, normalized_vendor_pn) as keys.
        The values are lists of dictionaries containing firmware version and binary information.
        Returns an empty dict if file is missing or invalid.
        """
        firmware_info_file = os.path.join(self.transceiver_inventory_path, TRANSCEIVER_FIRMWARE_INFO_FILE)
        firmware_data = defaultdict(list)
        required_fields = [
            'normalized_vendor_name',
            'normalized_vendor_pn',
            'fw_version',
            'fw_binary_name',
            'md5sum'
        ]
        if not os.path.exists(firmware_info_file):
            logger.error(f"Firmware info file does not exist: {firmware_info_file}")
            return {}
        try:
            with open(firmware_info_file, mode='r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if not all(row.get(field) for field in required_fields):
                        continue
                    key = (row['normalized_vendor_name'], row['normalized_vendor_pn'])
                    firmware_data[key].append({
                        'version': row['fw_version'],
                        'binary': row['fw_binary_name'],
                        'md5sum': row['md5sum']
                    })
        except csv.Error as e:
            logger.error(f"Error reading firmware info CSV: {e}")
            return {}
        return firmware_data

    def parse_firmware_base_url(self):
        """
        Parses the CMIS_CDB_FIRMWARE_BASE_URL_FILE and returns a dictionary
        mapping inventory names to firmware base URLs.
        The keys are the inventory names and the values are the firmware base URLs.
        If the file is empty or no valid rows are found, returns an empty dict.
        """
        firmware_base_url_file = os.path.join(self.transceiver_inventory_path, CMIS_CDB_FIRMWARE_BASE_URL_FILE)
        url_dict = {}
        if not os.path.exists(firmware_base_url_file):
            logger.error(f"Firmware base URL file does not exist: {firmware_base_url_file}")
            return {}
        try:
            with open(firmware_base_url_file, mode='r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    inv_name = row.get('inv_name')
                    fw_base_url = row.get('fw_base_url')
                    if inv_name and fw_base_url:
                        url_dict.setdefault(inv_name, fw_base_url)
        except csv.Error as e:
            logger.error(f"Error reading firmware base URL CSV: {e}")
            return {}
        return url_dict
