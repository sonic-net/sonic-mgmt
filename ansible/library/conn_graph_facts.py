#!/usr/bin/env python
import csv

from ansible.module_utils.basic import AnsibleModule
import yaml
import os
import logging
import traceback
import ipaddress
import six
from operator import itemgetter
from itertools import groupby
from natsort import natsorted

try:
    from ansible.module_utils.port_utils import get_port_alias_to_name_map
    from ansible.module_utils.debug_utils import config_module_logging
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.port_utils import get_port_alias_to_name_map
    from module_utils.debug_utils import config_module_logging


config_module_logging('conn_graph_facts')


DOCUMENTATION = '''
module: conn_graph_facts.py
short_description: Retrieve lab devices and physical connections information.
Description:
    Retrieve lab devices information and the physical connections between the devices.
options:
    host:
        [fanout switch name|Server name|Sonic Switch Name]
        required: False
    hosts:
        List of hosts. Applicable for multi-DUT and single-DUT setup. The host option for single DUT setup is kept
        for backward compatibility.
        required: False
    anchor:
        List of hosts. When no host and hosts is provided, the anchor option must be specified with list of hosts.
        This option is to supply the relevant list of hosts for looking up the connection graph xml file which has
        all the supplied hosts. The whole graph will be returned when this option is used. This is for configuring
        the root fanout switch.
        required: False
    filepath:
        Folder of the csv graph files.

    group:
        The csv files are organized in multiple groups. Each group has a set of csv files describing the connections
        and devices connected to a same root fanout switch. Usually devices within a same group are also tracked
        in a dedicated inventory file under the `ansible` folder.
        When the group file is not supplied, this module will try to find the group based on the supplied
        host/hosts/anchor information.
        required: False

    Mutually exclusive options: host, hosts, anchor

Ansible_facts:
    device_info: The device(host) type and hwsku
    device_conn: each physical connection of the device(host)
    device_vlan_range: all configured vlan range for the device(host)
    device_port_vlans: detailed vlanids for each physical port and switchport mode
    server_links: each server port vlan ids
    device_console_info: The device's console server type, mgmtip, hwsku and protocol
    device_console_link:  The console server port connected to the device
    device_bmc_info: The device's bmc server type, mgmtip, hwsku and protocol
    device_bmc_link:  The bmc server port connected to the device
    device_pdu_info: A dict of pdu device's pdu type, mgmtip, hwsku and protocol
    device_pdu_links: The pdu server ports connected to the device and pdu info

'''


EXAMPLES = '''
    - name: conn_graph_facts: host = "str-7260-11"

    return:
          "device_info": {
              "ManagementIp": "10.251.0.76/24",
              "HwSku": "Arista-7260QX-64",
              "Type": "FanoutLeaf"
            },
          "device_conn": {
              "str-7260-11": {
                  "Ethernet0": {
                      "peerdevice": "str-7050qx-2",
                      "peerport": "Ethernet4",
                      "speed": "40000"
                  },
              }
          },
           "device_vlan_range": {
              "VlanRange": "201-980,1041-1100"
            },
           "device_vlan_port:=: {
                ...
              "Ethernet44": {
                "vlanids": "801-860",
                "mode": "Trunk"
              },
              "Ethernet42": {
                "vlanids": "861-920",
                "mode": "Trunk"
               },......
            }

'''


LAB_GRAPHFILE_PATH = "files/"
LAB_GRAPH_GROUPS_FILE = "graph_groups.yml"


class LabGraph(object):

    SUPPORTED_CSV_FILES = {
        "devices": "sonic_{}_devices.csv",
        "links": "sonic_{}_links.csv",
        "pdu_links": "sonic_{}_pdu_links.csv",
        "console_links": "sonic_{}_console_links.csv",
        "bmc_links": "sonic_{}_bmc_links.csv",
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
            autoneg_mode = link.get("AutoNeg", "off")

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
                "autoneg": autoneg_mode,
            }
            links[end_device][end_port] = {
                "peerdevice": start_device,
                "peerport": start_port,
                "speed": band_width,
                "autoneg": autoneg_mode,
            }

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
                                msg = "Did not find port for '{}' in the ports based on hwsku '{}' for host '{}'"\
                                    .format(port_name, device["HwSku"], hostname)
                                logging.error("Sorted port name list: {}".format(sorted_port_name_list))
                                logging.error("port_vlans of host {}: {}".format(hostname, device_port_vlans[hostname]))
                                return (False, msg)
                    if not found_port_for_vlan and not ignore_error:
                        msg = "Did not find corresponding link for vlan {} in {} for host {}"\
                            .format(host_vlan, device_port_vlans[hostname], hostname)
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
        results = {k: v for k, v in locals().items() if (k.startswith("device_") and v)}

        return (True, results)


def find_graph(hostnames, part=False):
    """Find the graph file for the target device

    Args:
        hostnames (list): List of hostnames
        part (bool, optional): Select the graph file if over 80% of hosts are found in conn_graph when part is True.
                               Defaults to False.

    Returns:
        obj: Instance of LabGraph or None if no graph file is found.
    """
    graph_group_file = os.path.join(LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE)
    with open(graph_group_file) as fd:
        graph_groups = yaml.safe_load(fd)

    target_graph = None
    target_group = None
    for group in graph_groups:
        logging.debug("Looking at graph files of group {} for hosts {}".format(group, hostnames))
        lab_graph = LabGraph(LAB_GRAPHFILE_PATH, group)
        graph_hostnames = set(lab_graph.graph_facts["devices"].keys())
        logging.debug("For graph group {}, got hostnames {}".format(group, graph_hostnames))

        if not part:
            if set(hostnames) <= graph_hostnames:
                target_graph = lab_graph
                target_group = group
                break
        else:
            THRESHOLD = 0.8
            in_graph_hostnames = set(hostnames).intersection(graph_hostnames)
            if len(in_graph_hostnames) * 1.0 / len(hostnames) >= THRESHOLD:
                target_graph = lab_graph
                target_group = group
                break

    if target_graph is not None:
        logging.debug("Returning lab graph of group {} for hosts {}".format(target_group, hostnames))

    return target_graph


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=False),
            hosts=dict(required=False, type='list'),
            filepath=dict(required=False),
            group=dict(required=False),
            anchor=dict(required=False, type='list'),
            ignore_errors=dict(required=False, type='bool', default=False),
        ),
        mutually_exclusive=[['host', 'hosts', 'anchor']],
        supports_check_mode=True
    )
    m_args = module.params
    anchor = m_args['anchor']
    if m_args['hosts']:
        hostnames = m_args['hosts']
    elif m_args['host']:
        hostnames = [m_args['host']]
    else:
        # return the whole graph
        hostnames = []

    try:
        # When called by pytest, the file path is obscured to /tmp/.../.
        # we need the caller to tell us where the graph files are with
        # filepath argument.
        if m_args["filepath"]:
            global LAB_GRAPHFILE_PATH
            LAB_GRAPHFILE_PATH = m_args['filepath']

        if m_args["group"]:
            lab_graph = LabGraph(LAB_GRAPHFILE_PATH, m_args["group"])
        else:
            # When calling passed in anchor instead of hostnames,
            # the caller is asking to return the whole graph. This
            # is needed when configuring the root fanout switch.
            target = anchor if anchor else hostnames
            lab_graph = find_graph(target)

        if not lab_graph:
            results = {
                'device_info': {},
                'device_conn': {},
                'device_port_vlans': {},
            }
            module.exit_json(ansible_facts=results)

        # early return for the whole graph
        if not hostnames:
            results = {
                'device_info': lab_graph.graph_facts["devices"],
                'device_conn': lab_graph.graph_facts["links"],
                'device_port_vlans': lab_graph.graph_facts["port_vlans"]
            }
            module.exit_json(ansible_facts=results)
        succeed, results = lab_graph.build_results(hostnames, m_args['ignore_errors'])
        if succeed:
            module.exit_json(ansible_facts=results)
        else:
            module.fail_json(msg=results)
    except (IOError, OSError):
        module.fail_json(msg="Can not find required file, exception: {}".format(traceback.format_exc()))
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
