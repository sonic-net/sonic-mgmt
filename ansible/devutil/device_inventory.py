import os
import csv
import glob
from typing import Dict, List, Optional


class DeviceInfo(object):
    """Device information."""

    def __init__(
        self,
        hostname: str,
        management_ip: str,
        hw_sku: str,
        device_type: str,
        protocol: str = "",
        os: str = "",
    ):
        self.hostname = hostname
        self.management_ip = management_ip
        self.hw_sku = hw_sku
        self.device_type = device_type
        self.protocol = protocol
        self.os = os

    @staticmethod
    def from_csv_row(row: List[str]) -> "DeviceInfo":
        # The device CSV file has the following columns (the last 2 are optional):
        #
        #   Hostname,ManagementIp,HwSku,Type,Protocol,Os
        #
        return DeviceInfo(
            row[0],
            row[1].split("/")[0],
            row[2],
            row[3],
            row[4] if len(row) > 4 else "",
            row[5] if len(row) > 5 else "",
        )

    def is_ssh_supported(self) -> bool:
        if self.device_type == "ConsoleServer":
            return False

        if self.protocol == "snmp":
            return False

        return True


class DeviceInventory(object):
    """Device inventory from csv files."""

    def __init__(
        self, inv_name: str, device_file_name: str, devices: Dict[str, DeviceInfo]
    ):
        self.inv_name = inv_name
        self.device_file_name = device_file_name
        self.devices = devices

    @staticmethod
    def from_device_files(device_file_pattern: str) -> "List[DeviceInventory]":
        inv: List[DeviceInventory] = []
        for file_path in glob.glob(device_file_pattern):
            device_inventory = DeviceInventory.from_device_file(file_path)
            inv.append(device_inventory)

        return inv

    @staticmethod
    def from_device_file(file_path: str) -> "DeviceInventory":
        print(f"Loading device inventory: {file_path}")

        # Parse inv name from the file path.
        # The inv name can be deducted from the file name part in the path using format sonic_<inv_name>_devices.csv
        inv_name = os.path.basename(file_path).split("_")[1]

        devices: Dict[str, DeviceInfo] = {}
        with open(file_path, newline="") as file:
            reader = csv.reader(file)

            # Skip the header line
            next(reader)

            for row in reader:
                if row:
                    device_info = DeviceInfo.from_csv_row(row)
                    devices[device_info.hostname] = device_info

            return DeviceInventory(inv_name, file_path, devices)

    def get_device(self, hostname: str) -> Optional[DeviceInfo]:
        return self.devices.get(hostname)
