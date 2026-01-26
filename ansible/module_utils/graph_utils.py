import csv
import os
import logging
import ipaddress
import six
from operator import itemgetter
from itertools import groupby
from natsort import natsorted

try:
    from ansible.module_utils.port_utils import get_port_alias_to_name_map
except ImportError:
    from module_utils.port_utils import get_port_alias_to_name_map


class LabGraph(object):

    SUPPORTED_CSV_FILES = {
        "devices": "sonic_{}_devices.csv",
        "links": "sonic_{}_links.csv",
        "pdu_links": "sonic_{}_pdu_links.csv",
        "console_links": "sonic_{}_console_links.csv",
        "bmc_links": "sonic_{}_bmc_links.csv",
        "l1_links": "sonic_{}_l1_links.csv",
        "serial_links": "sonic_{}_serial_links.csv",
    }

    def __init__(self, path, group, forced_mgmt_routes=None):
        self.path = path
        self.group = group
        self.csv_files = {k: os.path.join(self.path, v.format(group)) for k, v in self.SUPPORTED_CSV_FILES.items()}

        self.forced_mgmt_routes = forced_mgmt_routes or []
        self.forced_mgmt_routes_v4, self.forced_mgmt_routes_v6 = self._parse_forced_mgmt_routes(
            self.forced_mgmt_routes
        )

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

    def _parse_forced_mgmt_routes(self, forced_mgmt_routes):
        routes_v4 = []
        routes_v6 = []
        if not forced_mgmt_routes:
            return routes_v4, routes_v6

        if isinstance(forced_mgmt_routes, six.string_types):
            route_items = [
                route.strip()
                for route in forced_mgmt_routes.replace(";", ",").split(",")
                if route.strip()
            ]
        elif isinstance(forced_mgmt_routes, (list, tuple, set)):
            route_items = []
            for route in forced_mgmt_routes:
                if route is None:
                    continue
                if isinstance(route, six.string_types):
                    route = route.strip()
                route_items.append(str(route).strip())
            route_items = [route for route in route_items if route]
        else:
            route_items = [str(forced_mgmt_routes).strip()]

        for route in route_items:
            if not route:
                continue
            try:
                network = ipaddress.ip_network(six.text_type(route), strict=False)
            except ValueError:
                try:
                    interface = ipaddress.ip_interface(six.text_type(route))
                    network = interface.network
                except ValueError:
                    logging.warning("Skipping invalid forced mgmt route: %s", route)
                    continue

            if network.version == 4:
                routes_v4.append(route)
            else:
                routes_v6.append(route)

        return routes_v4, routes_v6

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
            entry["ManagementRoutes"] = list(self.forced_mgmt_routes_v4)
            entry["ManagementRoutesV6"] = list(self.forced_mgmt_routes_v6)
            devices[entry["Hostname"]] = entry
        self.graph_facts["devices"] = devices

        links = {}
        linked_ports = {}
        port_vlans = {}
        vrfs = {}
        port_vrfs = {}
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
        for device, start_ports in links_group_by_devices.items():
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
            start_vlan_id = link.get("StartVlanID", vlan_ID)
            start_vlan_mode = link.get("StartVlanMode", vlan_mode)
            start_vrf_name = link.get("StartVrf", None)
            end_vlan_id = link.get("EndVlanID", vlan_ID)
            end_vlan_mode = link.get("EndVlanMode", vlan_mode)
            end_vrf_name = link.get("EndVrf", None)
            start_port_mac = link.get("StartPortMac", None)
            end_port_mac = link.get("EndPortMac", None)
            autoneg_mode = link.get("AutoNeg")
            fec_disable = link.get("FECDisable", False)

            links.setdefault(start_device, {})
            links.setdefault(end_device, {})
            linked_ports.setdefault(start_device, {}).setdefault(start_port, [])
            linked_ports.setdefault(end_device, {}).setdefault(end_port, [])
            port_vlans.setdefault(start_device, {})
            port_vlans.setdefault(end_device, {})
            vrfs.setdefault(start_device, set())
            vrfs.setdefault(end_device, set())
            port_vrfs.setdefault(start_device, {})
            port_vrfs.setdefault(end_device, {})

            start_port_linked_port = {
                "peerdevice": end_device,
                "peerport": end_port,
                "speed": band_width,
                "fec_disable": fec_disable
            }
            end_port_linked_port = {
                "peerdevice": start_device,
                "peerport": start_port,
                "speed": band_width,
                "fec_disable": fec_disable
            }

            if autoneg_mode:
                start_port_linked_port.update({"autoneg": autoneg_mode})
                end_port_linked_port.update({"autoneg": autoneg_mode})

            if start_port_mac:
                start_port_linked_port.update({"mac": start_port_mac})

            if end_port_mac:
                end_port_linked_port.update({"mac": end_port_mac})

            links[start_device][start_port] = start_port_linked_port
            links[end_device][end_port] = end_port_linked_port
            linked_ports[start_device][start_port].append(start_port_linked_port)
            linked_ports[end_device][end_port].append(end_port_linked_port)

            port_vlans[start_device][start_port] = {
                "mode": start_vlan_mode,
                "vlanids": start_vlan_id,
                "vlanlist": self._port_vlanlist(start_vlan_id),
            }
            port_vlans[end_device][end_port] = {
                "mode": end_vlan_mode,
                "vlanids": end_vlan_id,
                "vlanlist": self._port_vlanlist(end_vlan_id),
            }

            if start_vrf_name:
                vrfs[start_device].add(start_vrf_name)
                port_vrfs[start_device][start_port] = {"name": start_vrf_name}

            if end_vrf_name:
                vrfs[end_device].add(end_vrf_name)
                port_vrfs[end_device][end_port] = {"name": end_vrf_name}

        self.graph_facts["links"] = links
        self.graph_facts["linked_ports"] = linked_ports
        self.graph_facts["port_vlans"] = port_vlans
        self.graph_facts["vrfs"] = vrfs
        self.graph_facts["port_vrfs"] = port_vrfs

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

            if "|" in l1_port:
                lanes = l1_port.split("|")

                for lane in lanes:
                    from_l1_links[l1_name][lane] = {
                        "peerdevice": device_name,
                        "peerport": device_port
                    }
            else:
                from_l1_links[l1_name][l1_port] = {
                    "peerdevice": device_name,
                    "peerport": device_port,
                }

            if device_name not in to_l1_links:
                to_l1_links[device_name] = {}

            to_l1_links[device_name][device_port] = {
                "peerdevice": l1_name,
                "peerport": l1_port if "|" not in l1_port else l1_port.split("|"),
            }

        logging.debug("Found L1 links from L1 switches to devices: {}".format(from_l1_links))
        logging.debug("Found L1 links from devices to L1 switches: {}".format(to_l1_links))

        self.graph_facts["from_l1_links"] = from_l1_links
        self.graph_facts["to_l1_links"] = to_l1_links

        # Process serial links
        serial_links = {}
        for entry in self.csv_facts["serial_links"]:
            start_device = entry["StartDevice"]
            start_port = entry["StartPort"]
            end_device = entry["EndDevice"]
            end_port = entry["EndPort"]

            if start_device not in serial_links:
                serial_links[start_device] = {}
            if end_device not in serial_links:
                serial_links[end_device] = {}

            serial_links[start_device][start_port] = {
                "peerdevice": end_device,
                "peerport": end_port,
                "baud_rate": entry.get("BaudRate", "9600"),
                "flow_control": entry.get("FlowControl", "0"),
            }
            serial_links[end_device][end_port] = {
                "peerdevice": start_device,
                "peerport": start_port,
                "baud_rate": entry.get("BaudRate", "9600"),
                "flow_control": entry.get("FlowControl", "0"),
            }

        logging.debug("Found serial links: {}".format(serial_links))
        self.graph_facts["serial_links"] = serial_links

    def build_results(self, hostnames, ignore_error=False):
        device_info = {}
        device_conn = {}
        device_linked_ports = {}
        device_vrfs = {}
        device_port_vlans = {}
        device_port_vrfs = {}
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
        device_serial_link = {}
        msg = ""

        logging.debug("Building results for hostnames: {}".format(hostnames))

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
            device_port_vrfs[hostname] = self.graph_facts["port_vrfs"].get(hostname, {})
            device_vrfs[hostname] = self.graph_facts["vrfs"].get(hostname, {})

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

            device_serial_link[hostname] = self.graph_facts["serial_links"].get(hostname, {})

        filtered_linked_ports = self._filter_linked_ports(hostnames)
        l1_cross_connects = self._create_l1_cross_connects(filtered_linked_ports)

        for hostname in hostnames:
            device_linked_ports[hostname] = filtered_linked_ports.get(hostname, {})
            device_l1_cross_connects[hostname] = l1_cross_connects.get(hostname, {})

        results = {k: v for k, v in locals().items()
                   if (k.startswith("device_") and v)}

        return (True, results)

    def _filter_linked_ports(self, hostnames):
        # Create L1 cross connects for the requested hostnames
        # Filter linked ports to only include connections between devices
        # that are in the hostnames list, then craft cross connects
        hostnames_set = set(hostnames)

        # First, collect all relevant linked ports between requested hostnames
        # Maintain the same data structure as linked_ports
        filtered_linked_ports = {}
        for hostname in hostnames:
            if hostname not in self.graph_facts["linked_ports"]:
                continue

            linked_ports_facts = self.graph_facts["linked_ports"][hostname]
            for start_port, linked_ports in linked_ports_facts.items():
                for linked_port in linked_ports:
                    end_device = linked_port["peerdevice"]

                    # Only include links where both devices are in hostnames
                    if end_device in hostnames_set:
                        if hostname not in filtered_linked_ports:
                            filtered_linked_ports[hostname] = {}
                        filtered_linked_ports[hostname][start_port] = linked_port

        logging.debug("Filtered linked ports: {}".format(filtered_linked_ports))

        return filtered_linked_ports

    def _create_l1_cross_connects(self, filtered_linked_ports):
        # Now process the filtered linked ports to create cross connects
        l1_cross_connects = {}
        to_l1_links = self.graph_facts["to_l1_links"]
        for start_device, start_ports in filtered_linked_ports.items():
            for start_port, linked_port in start_ports.items():
                end_device = linked_port["peerdevice"]
                end_port = linked_port["peerport"]

                # Skip if not connected to any L1 devices
                if start_device not in to_l1_links or end_device not in to_l1_links:
                    continue

                # Skip if the start and end ports are not connected to
                # any L1 devices
                if start_port not in to_l1_links[start_device] or end_port not in to_l1_links[end_device]:
                    continue

                # Skip if the start and end ports are not connected to
                # the same L1 device
                l1_start_device = to_l1_links[start_device][start_port]["peerdevice"]
                l1_end_device = to_l1_links[end_device][end_port]["peerdevice"]
                l1_start_port = to_l1_links[start_device][start_port]["peerport"]
                l1_end_port = to_l1_links[end_device][end_port]["peerport"]

                if l1_start_device != l1_end_device:
                    logging.debug(
                        f"Found L1 connected port pairs not using the "
                        f"same L1 device: {start_device}:{start_port} <-> "
                        f"{end_device}:{end_port} on L1 devices "
                        f"{l1_start_device} and {l1_end_device}")
                    continue

                logging.debug(
                    "Found L1 cross connect: {}:{} <-> {}:{} on L1 device {}:{}:{}".format(
                        start_device, start_port, end_device, end_port, l1_start_device, l1_start_port, l1_end_port))

                if l1_start_device not in l1_cross_connects:
                    l1_cross_connects[l1_start_device] = {}

                l1_port_pair = sorted([l1_start_port, l1_end_port])

                if isinstance(l1_port_pair[0], list) and isinstance(l1_port_pair[1], list):
                    for l1_port_start, l1_port_end in zip(l1_port_pair[0], l1_port_pair[1]):
                        l1_cross_connects[l1_start_device][l1_port_start] = l1_port_end
                else:
                    l1_cross_connects[l1_start_device][l1_port_pair[0]] = l1_port_pair[1]

        return l1_cross_connects
