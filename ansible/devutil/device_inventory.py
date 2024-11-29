import copy
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
        self.physical_hostname = None
        self.console_port = 0

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


class DeviceLinkInfo:
    """Device link information."""

    def __init__(
        self,
        start_device: str,
        start_port: str,
        end_device: str,
        end_port: str,
        bandwidth: int,
        vlan_ranges: List[range],
        vlan_mode: str,
        auto_neg: str
    ):
        self.start_device = start_device
        self.start_port = start_port
        self.end_device = end_device
        self.end_port = end_port
        self.bandwidth = bandwidth
        self.vlan_ranges = vlan_ranges
        self.vlan_mode = vlan_mode
        self.auto_neg = auto_neg

    @staticmethod
    def from_csv_row(row: List[str]) -> "DeviceLinkInfo":
        vlan_list = row[5] if row[5] else ""
        vlan_ranges_str = vlan_list.split(",") if vlan_list != "" else []
        vlan_ranges = []
        for vlan_range_str in vlan_ranges_str:
            vlan_range = vlan_range_str.split("-")
            if len(vlan_range) == 1:
                vlan_ranges.append(range(int(vlan_range[0]), int(vlan_range[0]) + 1))
            elif len(vlan_range) == 2:
                vlan_ranges.append(range(int(vlan_range[0]), int(vlan_range[1]) + 1))
            else:
                raise ValueError(f"Invalid vlan range: {vlan_range_str}")

        return DeviceLinkInfo(
            start_device=row[0],
            start_port=row[1],
            end_device=row[2],
            end_port=row[3],
            bandwidth=int(row[4]),
            vlan_ranges=vlan_ranges,
            vlan_mode=row[6],
            auto_neg=row[7] if len(row) > 7 else ""
        )

    def create_reverse_link(self) -> "DeviceLinkInfo":
        return DeviceLinkInfo(
            start_device=self.end_device,
            start_port=self.end_port,
            end_device=self.start_device,
            end_port=self.start_port,
            bandwidth=self.bandwidth,
            vlan_ranges=self.vlan_ranges,
            vlan_mode=self.vlan_mode,
            auto_neg=self.auto_neg
        )


class DeviceLinkMap:
    """Device link map."""

    @staticmethod
    def from_csv_file(file_path: str) -> "DeviceLinkMap":
        links = DeviceLinkMap()
        with open(file_path, newline="") as file:
            reader = csv.reader(file)

            # Skip the header line
            next(reader)

            for row in reader:
                if row:
                    device_link = DeviceLinkInfo.from_csv_row(row)
                    links.add_link(device_link)

        return links

    def __init__(self):
        self.links: Dict[str, Dict[str, DeviceLinkInfo]] = {}

    def add_link(self, link: DeviceLinkInfo):
        if link.start_device not in self.links:
            self.links[link.start_device] = {}
        self.links[link.start_device][link.start_port] = link

        reverse_link = link.create_reverse_link()
        if reverse_link.start_device not in self.links:
            self.links[reverse_link.start_device] = {}
        self.links[reverse_link.start_device][reverse_link.start_port] = reverse_link

    def get_links(self, device: str) -> Optional[Dict[str, DeviceLinkInfo]]:
        return self.links.get(device)

    def get_link(self, device: str, port: str) -> Optional[DeviceLinkInfo]:
        links = self.get_links(device)
        return links.get(port) if links else None


class DeviceInventory(object):
    """Device inventory from csv files."""

    def __init__(
        self, inv_name: str, device_file_name: str, devices: Dict[str, DeviceInfo]
    ):
        self.inv_name = inv_name
        self.device_file_name = device_file_name
        self.devices = devices
        self.links = DeviceLinkMap()

    @staticmethod
    def from_device_files(device_file_pattern: str) -> "List[DeviceInventory]":
        inv: List[DeviceInventory] = []
        for file_path in glob.glob(device_file_pattern):
            device_inventory = DeviceInventory.from_device_file(file_path)

            console_links_file_path = file_path.replace("_devices", "_console_links")
            if os.path.exists(console_links_file_path):
                device_inventory.load_console_links_info(console_links_file_path)

            device_links_file_path = file_path.replace("_devices", "_links")
            if os.path.exists(device_links_file_path):
                device_inventory.load_device_link_map(device_links_file_path)

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

    def load_console_links_info(self, file_path: str):
        print(f"Loading console links inventory: {file_path}")

        with open(file_path, newline="") as file:
            reader = csv.reader(file)

            # Skip the header line
            next(reader)

            for row in reader:
                if row:
                    console_hostname = row[0]
                    console_port = int(row[1])
                    device_hostname = row[2]
                    console_device_info = self.get_device(console_hostname)
                    device_info = self.get_device(device_hostname)
                    if not console_device_info:
                        print(f"Unknown console hostname {console_hostname}, skipping")
                        continue
                    if not device_info:
                        print(f"Unknown device hostname {device_hostname}, skipping")
                        continue

                    device_console_device = copy.deepcopy(console_device_info)
                    device_console_device.hostname = f"{device_hostname}-console"
                    device_console_device.device_type = "Console"  # Make it different from ConsoleServer
                    device_console_device.physical_hostname = console_hostname
                    device_console_device.console_port = console_port
                    self.devices[device_console_device.hostname] = device_console_device

    def load_device_link_map(self, file_path: str):
        print(f"Loading device links inventory: {file_path}")
        self.links = DeviceLinkMap.from_csv_file(file_path)

    def get_device(self, hostname: str) -> Optional[DeviceInfo]:
        return self.devices.get(hostname)
