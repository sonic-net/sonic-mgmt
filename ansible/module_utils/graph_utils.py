import csv
import os
import logging
import ipaddress
import six
from operator import itemgetter
from itertools import groupby
from natsort import natsorted

from ansible.module_utils.port_utils import get_port_alias_to_name_map


class LabGraph(object):

    SUPPORTED_CSV_FILES = {
        "devices": "sonic_{}_devices.csv",
        "links": "sonic_{}_links.csv",
        "pdu_links": "sonic_{}_pdu_links.csv",
        "console_links": "sonic_{}_console_links.csv",
        "bmc_links": "sonic_{}_bmc_links.csv",
        "l1_links": "sonic_{}_l1_links.csv",
    }

    def __init__(self, path, group):
        self.path = path
        self.group = group
        self.csv_files = {k: os.path.join(self.path, v.format(group)) for k, v in self.SUPPORTED_CSV_FILES.items()}

        self._cache_port_alias_to_name = {}
        self._cache_port_name_to_alias = {}

        self.csv_facts = {}
        self.read_csv_files()

        self.graph_facts = {}
        self.csv_to_graph_facts()

    def read_csv_files(self):
        for k, v in self.csv_files.items():
            if os.path.exists(v):
                self.csv_facts[k] = self.read_csv_file(v)
            else:
                logging.debug("Missing file {}".format(v))
                self.csv_facts[k] = {}

    def read_csv_file(self, v):
        with open(v) as csvfile:
            reader = csv.DictReader(csvfile)
            return [row for row in reader]

    def _port_vlanlist(self, vlanrange):
        """Convert vlan range string to list of vlan ids

        Args:
            vlanrange (str): vlan range string, e.g. "1-10,20,30-40"

        Raises:
            ValueError: Unexpected vlanrange string.

        Returns:
            list: list of vlan ids
        """
        vlans = []
        for vlanid in list(map(str.strip, vlanrange.split(','))):
            if vlanid.isdigit():
                vlans.append(int(vlanid))
                continue
            elif '-' in vlanid:
                vlanlist = list(map(str.strip, vlanid.split('-')))
                vlans.extend(list(range(int(vlanlist[0]), int(vlanlist[1]) + 1)))
                continue
            elif vlanid != '':
                raise ValueError('vlan range error "{}"'.format(vlanrange))
        vlans = sorted(set(vlans))
        return vlans

    def _convert_list2range(self, vlans):
        """Convert list of vlan ids to vlan range string
        """
        vlan_ranges = []
        sl = sorted(set(vlans))
        for _, g in groupby(enumerate(sl), lambda t: t[0] - t[1]):
            group = list(map(itemgetter(1), g))
            if len(group) == 1:
                vlan_ranges.append(str(group[0]))
            else:
                vlan_ranges.append(str(group[0]) + '-' + str(group[-1]))
        return vlan_ranges

    def _get_port_alias_to_name_map(self, hwsku):
        if hwsku in self._cache_port_alias_to_name:
            return self._cache_port_alias_to_name[hwsku]
        port_alias_to_name_map, _, _ = get_port_alias_to_name_map(hwsku)
        self._cache_port_alias_to_name[hwsku] = port_alias_to_name_map
        return port_alias_to_name_map

    def _port_alias_to_name(self, device, port):
        hwsku = self.graph_facts["devices"][device]["HwSku"]
        if self.graph_facts["devices"][device].get("Os", "").lower() != "sonic":
            return port
        return self._get_port_alias_to_name_map(hwsku).get(port, port)

    def _get_sorted_port_name_list(self, hwsku):
        return natsorted(self._get_port_alias_to_name_map(hwsku).values())

    def _get_port_name_to_alias_map(self, hwsku):
        """
        Retrive port name to alias map for specific hwsku.
        """
        if hwsku in self._cache_port_name_to_alias:
            return self._cache_port_name_to_alias[hwsku]
        port_alias_to_name_map = self._get_port_alias_to_name_map(hwsku)
        port_name_to_alias_map = dict([(name, alias) for alias, name in port_alias_to_name_map.items()])
        self._cache_port_name_to_alias[hwsku] = port_name_to_alias_map
        return port_name_to_alias_map

    def _get_port_name_set(self, device_hostname):
        """
        Retrive port name set of a specific hwsku.
        """
        hwsku = self.graph_facts["devices"][device_hostname]['HwSku']
        return set(self._get_port_name_to_alias_map(hwsku).keys())

    def _get_port_alias_set(self, device_hostname):
        """
        Retrive port alias set of a specific hwsku.
        """
        hwsku = self.graph_facts["devices"][device_hostname]['HwSku']
        return set(self._get_port_alias_to_name_map(hwsku).keys())

    def csv_to_graph_facts(self):
        devices = {}
        for entry in self.csv_facts["devices"]:
            management_ip = entry["ManagementIp"]
            if len(management_ip.split("/")) > 1:
                iface = ipaddress.ip_interface(six.text_type(management_ip))
                entry["mgmtip"] = str(iface.ip)
                entry["ManagementGw"] = str(iface.network.network_address + 1)

            if entry["Type"].lower() not in ["pdu", "consoleserver", "mgmttstorrouter"]:
                if "CardType" not in entry:
                    entry["CardType"] = "Linecard"
                if "HwSkuType" not in entry:
                    entry["HwSkuType"] = "predefined"
            devices[entry["Hostname"]] = entry
        self.graph_facts["devices"] = devices

        links = {}
        port_vlans = {}
        links_group_by_devices = {}
        ports_group_by_devices = {}

        for entry in self.csv_facts["links"]:
            if entry['StartDevice'] not in links_group_by_devices:
                links_group_by_devices[entry['StartDevice']] = []
            if entry['EndDevice'] not in links_group_by_devices:
                links_group_by_devices[entry['EndDevice']] = []
            if entry['StartDevice'] not in ports_group_by_devices:
                ports_group_by_devices[entry['StartDevice']] = []
            if entry['EndDevice'] not in ports_group_by_devices:
                ports_group_by_devices[entry['EndDevice']] = []

            links_group_by_devices[entry['StartDevice']].append(entry)
            links_group_by_devices[entry['EndDevice']].append(entry)
            ports_group_by_devices[entry['StartDevice']].append(entry['StartPort'])
            ports_group_by_devices[entry['EndDevice']].append(entry['EndPort'])

        convert_alias_to_name = []
        for device, device_links in links_group_by_devices.items():
            if self.graph_facts["devices"][device].get("Os", "").lower() == "sonic":
                if any([port not in self._get_port_alias_set(device) and port not in self._get_port_name_set(device) for port in ports_group_by_devices[device]]):  # noqa: E501
                    continue
                elif all([port in self._get_port_alias_set(device) for port in ports_group_by_devices[device]]):
                    convert_alias_to_name.append(device)
                elif not all([port in self._get_port_name_set(device) for port in ports_group_by_devices[device]]):
                    raise Exception(
                        "[Failed] For device {}, please check {} and ensure all ports use "
                        "port name, or ensure all ports use port alias.".format(
                            device, ports_group_by_devices[device]
                        )
                    )

        logging.debug("convert_alias_to_name {}".format(convert_alias_to_name))

        for link in self.csv_facts["links"]:
            start_device = link["StartDevice"]
            end_device = link["EndDevice"]
            start_port = link["StartPort"]
            end_port = link["EndPort"]

            if link["StartDevice"] in convert_alias_to_name:
                start_port = self._port_alias_to_name(link["StartDevice"], link['StartPort'])
            if link["EndDevice"] in convert_alias_to_name:
                end_port = self._port_alias_to_name(link["EndDevice"], link['EndPort'])

            band_width = link["BandWidth"]
            vlan_ID = link["VlanID"]
            vlan_mode = link["VlanMode"]
            autoneg_mode = link.get("AutoNeg")
            fec_disable = link.get("FECDisable", False)

            if start_device not in links:
                links[start_device] = {}
            if end_device not in links:
                links[end_device] = {}
            if start_device not in port_vlans:
                port_vlans[start_device] = {}
            if end_device not in port_vlans:
                port_vlans[end_device] = {}

            links[start_device][start_port] = {
                "peerdevice": end_device,
                "peerport": end_port,
                "speed": band_width,
                "fec_disable": fec_disable
            }
            links[end_device][end_port] = {
                "peerdevice": start_device,
                "peerport": start_port,
                "speed": band_width,
                "fec_disable": fec_disable
            }

            if autoneg_mode:
                links[start_device][start_port].update({"autoneg": autoneg_mode})
                links[end_device][end_port].update({"autoneg": autoneg_mode})

            port_vlans[start_device][start_port] = {
                "mode": vlan_mode,
                "vlanids": vlan_ID,
                "vlanlist": self._port_vlanlist(vlan_ID),
            }
            port_vlans[end_device][end_port] = {
                "mode": vlan_mode,
                "vlanids": vlan_ID,
                "vlanlist": self._port_vlanlist(vlan_ID),
            }

        self.graph_facts["links"] = links
        self.graph_facts["port_vlans"] = port_vlans

        console_links = {}
        for entry in self.csv_facts["console_links"]:
            start_device = entry["EndDevice"]
            if start_device not in console_links:
                console_links[start_device] = {}
            console_links[start_device] = {
                "ConsolePort": {
                    "baud_rate": entry.get("BaudRate", None),
                    "peerdevice": entry["StartDevice"],
                    "peerport": entry["StartPort"],
                    "proxy": entry["Proxy"],
                    "type": entry["Console_type"],
                    "menu_type": entry["Console_menu_type"],
                }
            }
        self.graph_facts["console_links"] = console_links

        pdu_links = {}
        for entry in self.csv_facts["pdu_links"]:
            start_device = entry["EndDevice"]
            pdu_links_of_device = pdu_links.get(start_device, {})
            start_port = entry["EndPort"]
            pdu_links_of_psu = pdu_links_of_device.get(start_port, {})
            feed = entry.get("EndFeed", "N/A")
            pdu_links_of_feed = {
                "peerdevice": entry["StartDevice"],
                "peerport": entry["StartPort"],
                "feed": feed,
            }
            pdu_links_of_psu[feed] = pdu_links_of_feed
            pdu_links_of_device[start_port] = pdu_links_of_psu
            pdu_links[start_device] = pdu_links_of_device
        self.graph_facts["pdu_links"] = pdu_links

        bmc_links = {}
        for entry in self.csv_facts["bmc_links"]:
            start_device = entry["EndDevice"]
            if start_device not in bmc_links:
                bmc_links[start_device] = {}
            bmc_links[start_device][entry["EndPort"]] = {
                "peerdevice": entry["StartDevice"],
                "peerport": entry["StartPort"],
                "bmc_ip": entry["BmcIp"],
            }
        self.graph_facts["bmc_links"] = bmc_links

        from_l1_links = {}
        to_l1_links = {}
        for entry in self.csv_facts["l1_links"]:
            device_name = entry["StartDevice"]
            device_port = entry["StartPort"]
            l1_name = entry["EndDevice"]
            l1_port = entry["EndPort"]

            if l1_name not in from_l1_links:
                from_l1_links[l1_name] = {}
            from_l1_links[l1_name][l1_port] = {
                "peerdevice": device_name,
                "peerport": device_port,
            }

            if device_name not in to_l1_links:
                to_l1_links[device_name] = {}
            to_l1_links[device_name][device_port] = {
                "peerdevice": l1_name,
                "peerport": l1_port,
            }

        logging.debug("Found L1 links from L1 switches to devices: {}".format(from_l1_links))
        logging.debug("Found L1 links from devices to L1 switches: {}".format(to_l1_links))

        self.graph_facts["from_l1_links"] = from_l1_links
        self.graph_facts["to_l1_links"] = to_l1_links

        # Create L1 cross connects
        # If the start and end port of a link are both connected to the same L1 switches,
        # we consider it as a cross connect link.
        l1_cross_connects = {}
        for start_device, device_links in links.items():
            for start_port, link in device_links.items():
                end_device = link["peerdevice"]
                end_port = link["peerport"]

                # Skip if not connected to any L1 devices
                if start_device not in to_l1_links or \
                        end_device not in to_l1_links:
                    continue

                # Skip if the start and end ports are not connected to any L1 devices
                if start_port not in to_l1_links[start_device] and \
                        end_port not in to_l1_links[end_device]:
                    continue

                # Skip if the start and end ports are not connected to the same L1 device
                l1_start_device = to_l1_links[start_device][start_port]["peerdevice"]
                l1_end_device = to_l1_links[end_device][end_port]["peerdevice"]
                if l1_start_device != l1_end_device:
                    logging.debug(f"Found L1 connected port pairs not using the same L1 device: "
                                  f"{start_device}:{start_port} <-> {end_device}:{end_port} "
                                  f"on L1 devices {l1_start_device} and {l1_end_device}")
                    continue

                logging.debug("Found L1 cross connect: {}:{} <-> {}:{} on L1 device {}".format(
                    start_device, start_port, end_device, end_port, l1_start_device))

                if l1_start_device not in l1_cross_connects:
                    l1_cross_connects[l1_start_device] = {}

                l1_start_port = to_l1_links[start_device][start_port]["peerport"]
                l1_end_port = to_l1_links[end_device][end_port]["peerport"]
                l1_port_pair = sorted([l1_start_port, l1_end_port])
                l1_cross_connects[l1_start_device][l1_port_pair[0]] = l1_port_pair[1]
        self.graph_facts["l1_cross_connects"] = l1_cross_connects

    def build_results(self, hostnames, ignore_error=False):
        device_info = {}
        device_conn = {}
        device_port_vlans = {}
        device_vlan_list = {}
        device_vlan_range = {}
        device_vlan_map_list = {}
        device_console_link = {}
        device_console_info = {}
        device_pdu_info = {}
        device_pdu_links = {}
        device_bmc_link = {}
        device_bmc_info = {}
        device_from_l1_links = {}
        device_to_l1_links = {}
        device_l1_cross_connects = {}
        msg = ""

        for hostname in hostnames:
            device = self.graph_facts["devices"].get(hostname, None)
            if device is None and not ignore_error:
                msg = "Cannot find device {}, check if it is in {}".format(hostname, self.csv_files["devices"])
                return (False, msg)
            if device is None:
                continue
            device_info[hostname] = device
            device_conn[hostname] = self.graph_facts["links"].get(hostname, {})

            device_port_vlans[hostname] = self.graph_facts["port_vlans"].get(hostname, {})

            vlan_list = []
            for port_info in device_port_vlans[hostname].values():
                vlan_list.extend(port_info["vlanlist"])
            vlan_list = natsorted(vlan_list)
            device_vlan_list[hostname] = vlan_list
            device_vlan_range[hostname] = self._convert_list2range(vlan_list)

            if device["Type"].lower() != "devsonic":
                device_vlan_map_list[hostname] = vlan_list
            else:
                device_vlan_map_list[hostname] = {}

                sorted_port_name_list = self._get_sorted_port_name_list(device["HwSku"])

                for host_vlan in vlan_list:
                    found_port_for_vlan = False
                    for port_name, port_info in device_port_vlans[hostname].items():
                        if host_vlan in port_info["vlanlist"]:
                            if port_name in sorted_port_name_list:
                                port_index = sorted_port_name_list.index(port_name)
                                device_vlan_map_list[hostname][port_index] = host_vlan
                                found_port_for_vlan = True
                            elif not ignore_error:
                                msg = (f"Did not find port for '{port_name}' in the ports based on "
                                       f"hwsku '{device['HwSku']}' for host '{hostname}'")
                                logging.error("Sorted port name list: {}".format(sorted_port_name_list))
                                logging.error("port_vlans of host {}: {}".format(hostname, device_port_vlans[hostname]))
                                return (False, msg)
                    if not found_port_for_vlan and not ignore_error:
                        msg = (f"Did not find corresponding link for vlan {host_vlan} in "
                               f"{device_port_vlans[hostname]} for host {hostname}")
                        return (False, msg)
            device_console_link[hostname] = self.graph_facts["console_links"].get(hostname, {})
            device_console_info[hostname] = self.graph_facts["devices"].get(
                device_console_link[hostname].get("ConsolePort", {}).get("peerdevice"),
                {}
            )
            """
            pdu_links in the format of:
            {
                "str-7250-7": {
                    "PSU1": {
                        "A": {
                            "peerdevice": "pdu-2",
                            "peerport": "5",
                            "feed": "A",
                        },
                        "B": {
                            "peerdevice": "pdu-2",
                            "peerport": "6",
                            "feed": "B",
                        }
                    },
                    "PSU2": {
                        "N/A": {
                            "peerdevice": "pdu-2",
                            "peerport": "7",
                            "feed": "A",
                        },
                    },
                },
            }
            pdu_info in the format of:
            {
                "str-7250-7": {
                    "pdu-2": {
                        "Hostname": "pdu-2",
                        "Protocol": "snmp",
                        "ManagementIp": "10.3.155.107",
                        "HwSku": "Sentry",
                        "Type": "Pdu",
                    },
                },
            }
            """
            device_pdu_links[hostname] = self.graph_facts["pdu_links"].get(hostname, {})
            device_pdu_info[hostname] = {}
            for psu_name, psu_info in device_pdu_links[hostname].items():
                for feed_name, feed_info in psu_info.items():
                    pdu_hostname = feed_info.get("peerdevice")
                    device_pdu_info[hostname][pdu_hostname] = self.graph_facts["devices"].get(pdu_hostname, {})

            device_bmc_link[hostname] = self.graph_facts["bmc_links"].get(hostname, {})
            device_bmc_info[hostname] = {}
            for _, bmc_link in device_bmc_link[hostname].items():
                bmc_hostname = bmc_link.get("peerdevice")
                device_bmc_info[hostname] = self.graph_facts["devices"].get(bmc_hostname, {})
                break

            device_from_l1_links[hostname] = self.graph_facts["from_l1_links"].get(hostname, {})
            device_to_l1_links[hostname] = self.graph_facts["to_l1_links"].get(hostname, {})
            device_l1_cross_connects[hostname] = self.graph_facts["l1_cross_connects"].get(hostname, {})

        results = {k: v for k, v in locals().items() if (k.startswith("device_") and v)}

        return (True, results)
