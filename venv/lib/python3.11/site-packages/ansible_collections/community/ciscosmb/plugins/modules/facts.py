#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: facts
author: "Petr Klima (@qaxi)"
short_description: Collect facts from remote devices running Cisco SMB
description:
  - Collects a base set of device facts from a remote device that
    is running Cisco SMB.  This module prepends all of the
    base network fact keys with C(ansible_net_<fact>).  The facts
    module will always collect a base set of facts from the device
    and can enable or disable collection of additional facts.
options:
  gather_subset:
    description:
      - When supplied, this argument will restrict the facts collected
        to a given subset.  Possible values for this argument include
        C(all), C(hardware), C(config) and C(interfaces).  Can specify a list of
        values to include a larger subset.  Values can also be used
        with an initial C(!) to specify that a specific subset should
        not be collected.
    required: false
    type: list
    elements: str
    choices: [ 'default', 'all', 'hardware', 'config', 'interfaces', '!hardware', '!config', '!interfaces' ]
    default: '!config'
notes:
  - Supports C(check_mode).
"""

EXAMPLES = """
- name: Collect all facts from the device
  community.ciscosmb.facts:
    gather_subset: all

- name: Collect only the config and default facts
  community.ciscosmb.facts:
    gather_subset:
      - config

- name: Do not collect hardware facts
  community.ciscosmb.facts:
    gather_subset:
      - "!hardware"
"""

RETURN = """
ansible_net_gather_subset:
  description: The list of fact subsets collected from the device.
  returned: always
  type: list

# default
ansible_net_model:
  description: The model name returned from the device.
  returned: always
  type: str
ansible_net_serialnum:
  description: The serial number of the remote device.
  returned: always
  type: str
ansible_net_version:
  description: The operating system version running on the remote device.
  returned: always
  type: str
ansible_net_hostname:
  description: The configured hostname of the device.
  returned: always
  type: str
ansible_net_uptime:
  description: The uptime of the device.
  returned: always
  type: str
ansible_net_cpu_load:
  description: Current CPU load.
  returned: always
  type: str
ansible_net_stacked_models:
  description: The model names of each device in the stack.
  returned: when multiple devices are configured in a stack
  type: list
ansible_net_stacked_serialnums:
  description: The serial numbers of each device in the stack.
  returned: when multiple devices are configured in a stack
  type: list

# hardware
ansible_net_spacefree_mb:
  description: The available disk space on the remote device in MiB.
  returned: when hardware is configured
  type: dict
ansible_net_spacetotal_mb:
  description: The total disk space on the remote device in MiB.
  returned: when hardware is configured
  type: dict
ansible_net_memfree_mb:
  description: The available free memory on the remote device in MiB.
  returned: when hardware is configured
  type: int
ansible_net_memtotal_mb:
  description: The total memory on the remote device in MiB.
  returned: when hardware is configured
  type: int

# config
ansible_net_config:
  description: The current active config from the device.
  returned: when config is configured
  type: str

# interfaces
ansible_net_all_ipv4_addresses:
  description: All IPv4 addresses configured on the device.
  returned: when interfaces is configured
  type: list
ansible_net_all_ipv6_addresses:
  description: All IPv6 addresses configured on the device.
  returned: when interfaces is configured
  type: list
ansible_net_interfaces:
  description: A hash of all interfaces running on the system.
  returned: when interfaces is configured
  type: dict
ansible_net_neighbors:
  description: The list of neighbors from the remote device.
  returned: when interfaces is configured
  type: dict

"""
import re

from ansible_collections.community.ciscosmb.plugins.module_utils.ciscosmb import (
    run_commands,
    ciscosmb_argument_spec,
    interface_canonical_name,
    ciscosmb_split_to_tables,
    ciscosmb_parse_table,
    ciscosmb_merge_dicts,
)
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import iteritems


class FactsBase(object):

    COMMANDS = list()

    def __init__(self, module):
        self.module = module
        self.facts = dict()
        self.responses = None

    def populate(self):
        self.responses = run_commands(
            self.module, commands=self.COMMANDS, check_rc=False
        )

    def run(self, cmd):
        return run_commands(self.module, commands=cmd, check_rc=False)


class Default(FactsBase):

    COMMANDS = [
        "show version",
        "show system",
        "show cpu utilization",
        "show inventory",
    ]

    def populate(self):
        super(Default, self).populate()

        data = self.responses[0]
        if data:
            self.facts["version"] = self.parse_version(data)
            self.facts["boot_version"] = self.parse_boot_version(data)

        data = self.responses[1]
        if data:
            self.facts["uptime"] = self.parse_uptime(data)
            self.facts["hostname"] = self.parse_hostname(data)

        data = self.responses[2]
        if data:
            self.facts["cpu_load"] = self.parse_cpu_load(data)

        data = self.responses[3]
        if data:
            modules = self.parse_inventory(data)
            stacked_models = self.parse_stacked_models(modules)
            if len(stacked_models) >= 2:
                stacked_serialnums = self.parse_stacked_serialnums(modules)
                self.facts["stacked_models"] = stacked_models
                self.facts["stacked_serialnums"] = stacked_serialnums
            self.facts["model"] = self.parse_model(modules)
            self.facts["serialnum"] = self.parse_serialnum(modules)
            self.facts["hw_version"] = self.parse_hw_version(modules)
            self.facts["hw_modules"] = modules

    # show version
    def parse_version(self, data):
        # Cisco SMB 300 and 500 - fw 1.x.x.x
        match = re.search(r"^SW version\s*(\S+)\s*.*$", data, re.M)
        if match:
            return match.group(1)
        # Cisco SMB 350 and 550 - fw 2.x.x.x
        match = re.search(r"^  Version:\s*(\S+)\s*.*$", data, re.M)
        if match:
            return match.group(1)

    def parse_boot_version(self, data):
        match = re.search(r"Boot version\s*(\S+)\s*.*$", data, re.M)
        if match:
            return match.group(1)

    # show system
    def parse_uptime(self, data):
        match = re.search(r"^System Up Time \S+:\s+(\S+)\s*$", data, re.M)
        if match:
            (dayhour, mins, sec) = match.group(1).split(":")
            (day, hour) = dayhour.split(",")
            # output in seconds
            return (int(day) * 86400) + (int(hour) * 3600) + (int(mins) * 60) + int(sec)

    def parse_hostname(self, data):
        match = re.search(r"^System Name:\s*(\S+)\s*$", data, re.M)
        if match:
            return match.group(1)

    # show cpu utilization
    def parse_cpu_load(self, data):
        match = re.search(r"one minute:\s+(\d+)%;\s*", data, re.M)
        if match:
            return match.group(1)

    # show inventory
    def parse_inventory(self, data):
        # make 1 module 1 line
        data = re.sub(r"\nPID", "  PID", data)
        # delete empty lines
        data = re.sub(r"^\n", "", data)
        data = re.sub(r"\n\n", "", data)
        data = re.sub(r"\n\s*\n", r"\n", data)

        lines = data.splitlines()

        modules = {}
        for line in lines:
            # remove extra chars
            line = re.sub(r'"', r"", line)
            line = re.sub(r"\s+", r" ", line)
            # normalize lines
            line = re.sub(r":\s", r'"', line)
            line = re.sub(r'\s+DESCR"', r'"DESCR"', line)
            line = re.sub(r'\s+PID"', r'"PID"', line)
            line = re.sub(r'\s+VID"', r'"VID"', line)
            line = re.sub(r'\s+SN"', r'"SN"', line)
            line = re.sub(r"\s*$", r"", line)

            match = re.search(
                r'^NAME"(?P<name>[^"]+)"DESCR"(?P<descr>[^"]+)"PID"(?P<pid>[^"]+)"VID"(?P<vid>[^"]+)"SN"(?P<sn>\S+)\s*',
                line,
            )

            if match:
                modul = match.groupdict()
                modules[modul["name"]] = modul

        if modules:
            return modules

    def parse_stacked_models(self, data):
        # every inventory has module with NAME: "1"
        # stacks have modules 2 3 ... 8
        models = []
        for n in range(1, 9):
            # index is string
            if str(n) in data:
                models.append(data[str(n)]["pid"])
        return models

    def parse_stacked_serialnums(self, data):
        # every inventory has module with NAME: "1"
        # stacks have modules 2 3 ... 8
        sn = []
        for n in range(1, 9):
            # index is string
            if str(n) in data:
                sn.append(data[str(n)]["sn"])
        return sn

    def parse_model(self, data):
        # every inventory has module with NAME: "1"
        model = data["1"]["pid"]
        if "stacked_models" in self.facts:
            model = re.sub(r"-.*$", "", model)
            model = "Stack " + model
        return model

    def parse_serialnum(self, data):
        # every inventory has module with NAME: "1"
        sn = data["1"]["sn"]
        return sn

    def parse_hw_version(self, data):
        # every inventory has module with NAME: "1"
        sn = data["1"]["vid"]
        return sn


class Hardware(FactsBase):

    COMMANDS = [
        "dir",
    ]

    def populate(self):
        super(Hardware, self).populate()
        data = self.responses[0]
        if data:
            self.parse_filesystem_info(data)

    def parse_filesystem_info(self, data):
        match = re.search(r"Total size of (\S+): (\d+) bytes", data, re.M)

        if match:  # fw 1.x
            self.facts["spacetotal_mb"] = round(int(match.group(2)) / 1024 / 1024, 1)
            match = re.search(r"Free size of (\S+): (\d+) bytes", data, re.M)
            self.facts["spacefree_mb"] = round(int(match.group(2)) / 1024 / 1024, 1)

        else:
            match = re.search(r"(\d+)K of (\d+)K are free", data, re.M)
            if match:  # fw 2.x, 3.x
                self.facts["spacetotal_mb"] = round(int(match.group(2)) / 1024, 1)
                self.facts["spacefree_mb"] = round(int(match.group(1)) / 1024, 1)


class Config(FactsBase):

    COMMANDS = ["show running-config detailed"]

    def populate(self):
        super(Config, self).populate()
        data = self.responses[0]
        if data:
            self.facts["config"] = data


class Interfaces(FactsBase):

    COMMANDS = [
        "show ports jumbo-frame",
        "show ip interface",
        "show ipv6 interface brief",
        "show interfaces status",
        "show interfaces configuration",
        "show interfaces description",
        "show lldp neighbors",
    ]

    DETAIL_RE = re.compile(
        r"([\w\d\-]+)=\"?(\w{3}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}|[\w\d\-\.:/]+)"
    )
    WRAPPED_LINE_RE = re.compile(r"^\s+(?!\d)")

    def populate(self):
        super(Interfaces, self).populate()

        self.facts["interfaces"] = dict()
        self.facts["all_ipv4_addresses"] = list()
        self.facts["all_ipv6_addresses"] = list()
        self.facts["neighbors"] = list()

        data = self.responses[0]
        if data:
            self.populate_interfaces_mtu(data)

        data = self.responses[1]
        if data:
            self.populate_addresses_ipv4(data)

        data = self.responses[2]
        if data:
            self.populate_addresses_ipv6(data)

        data = self.responses[3]
        if data:
            self.populate_interfaces_status(data)

        data = self.responses[4]
        if data:
            self.populate_interfaces_configuration(data)

        data = self.responses[5]
        if data:
            self.populate_interfaces_description(data)

        data = self.responses[6]
        if data:
            self.populate_neighbors(data)

    def _populate_interfaces_status_interface(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            i = interface_table[key]
            interface = dict()
            interface["state"] = i[6].lower()
            interface["type"] = i[1]
            interface["mtu"] = self._mtu
            interface["duplex"] = i[2].lower()
            interface["negotiation"] = i[4].lower()
            interface["control"] = i[5].lower()
            interface["presure"] = i[7].lower()
            interface["mode"] = i[8].lower()

            if i[6] == "Up":
                interface["bandwidth"] = int(i[3]) * 1000  # to get speed in kb
                interface["bandwith"] = interface["bandwidth"]
            else:
                interface["bandwidth"] = None
                interface["bandwith"] = interface["bandwidth"]

            for key in interface:
                if interface[key] == "--":
                    interface[key] = None

            interfaces[interface_canonical_name(i[0])] = interface
        return interfaces

    def _populate_interfaces_status_portchanel(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            interface = dict()
            i = interface_table[key]
            interface["state"] = i[6].lower()
            interface["type"] = i[1]
            interface["mtu"] = self._mtu
            interface["duplex"] = i[2].lower()
            interface["negotiation"] = i[4].lower()
            interface["control"] = i[5].lower()

            if i[6] == "Up":
                interface["bandwidth"] = int(i[3]) * 1000  # to get speed in kb
                interface["bandwith"] = interface["bandwidth"]
            else:
                interface["bandwidth"] = None
                interface["bandwith"] = interface["bandwidth"]

            for key in interface:
                if interface[key] == "--":
                    interface[key] = None

            interfaces[interface_canonical_name(i[0])] = interface

        return interfaces

    def populate_interfaces_status(self, data):
        tables = ciscosmb_split_to_tables(data)

        interface_table = ciscosmb_parse_table(tables[0])
        portchanel_table = ciscosmb_parse_table(tables[1])

        interfaces = self._populate_interfaces_status_interface(interface_table)
        self.facts["interfaces"] = ciscosmb_merge_dicts(
            self.facts["interfaces"], interfaces
        )
        interfaces = self._populate_interfaces_status_portchanel(portchanel_table)
        self.facts["interfaces"] = ciscosmb_merge_dicts(
            self.facts["interfaces"], interfaces
        )

    def _populate_interfaces_configuration_interface(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            i = interface_table[key]
            interface = dict()
            interface["admin_state"] = i[6].lower()
            interface["mdix"] = i[8].lower()

            interfaces[interface_canonical_name(i[0])] = interface
        return interfaces

    def _populate_interfaces_configuration_portchanel(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            interface = dict()
            i = interface_table[key]

            interface["admin_state"] = i[5].lower()

            interfaces[interface_canonical_name(i[0])] = interface

        return interfaces

    def populate_interfaces_configuration(self, data):
        tables = ciscosmb_split_to_tables(data)

        interface_table = ciscosmb_parse_table(tables[0])
        portchanel_table = ciscosmb_parse_table(tables[1])

        interfaces = self._populate_interfaces_configuration_interface(interface_table)
        self.facts["interfaces"] = ciscosmb_merge_dicts(
            self.facts["interfaces"], interfaces
        )
        interfaces = self._populate_interfaces_configuration_portchanel(
            portchanel_table
        )
        self.facts["interfaces"] = ciscosmb_merge_dicts(
            self.facts["interfaces"], interfaces
        )

    def _populate_interfaces_description_interface(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            i = interface_table[key]
            interface = dict()
            interface["description"] = i[1]

            if interface["description"] == "":
                interface["description"] = None

            interfaces[interface_canonical_name(i[0])] = interface
        return interfaces

    def _populate_interfaces_description_portchanel(self, interface_table):
        interfaces = dict()

        for key in interface_table:

            interface = dict()
            i = interface_table[key]

            interface["description"] = i[1]

            if interface["description"] == "":
                interface["description"] = None

            interfaces[interface_canonical_name(i[0])] = interface

        return interfaces

    def populate_interfaces_description(self, data):
        tables = ciscosmb_split_to_tables(data)

        interface_table = ciscosmb_parse_table(tables[0], False)
        portchanel_table = ciscosmb_parse_table(tables[1], False)

        interfaces = self._populate_interfaces_description_interface(interface_table)
        self.facts["interfaces"] = ciscosmb_merge_dicts(
            self.facts["interfaces"], interfaces
        )
        interfaces = self._populate_interfaces_description_portchanel(portchanel_table)
        self.facts["interfaces"] = ciscosmb_merge_dicts(
            self.facts["interfaces"], interfaces
        )

    def _populate_address_ipv4(self, ip_table):
        ips = list()

        for key in ip_table:
            cidr = ip_table[key][0]

            interface = interface_canonical_name(ip_table[key][1])
            ip, mask = cidr.split("/")

            ips.append(ip)

            # add ips to interface
            self._new_interface(interface)
            if "ipv4" not in self.facts["interfaces"][interface]:
                self.facts["interfaces"][interface]["ipv4"] = list()

            self.facts["interfaces"][interface]["ipv4"].append(
                dict(address=ip, subnet=mask)
            )

        return ips

    def populate_addresses_ipv4(self, data):
        tables = ciscosmb_split_to_tables(data)
        ip_table = ciscosmb_parse_table(tables[0])

        ips = self._populate_address_ipv4(ip_table)
        self.facts["all_ipv4_addresses"] = ips

    def _populate_address_ipv6(self, ip_table):
        ips = list()

        for key in ip_table:
            ip = ip_table[key][3]
            interface = interface_canonical_name(ip_table[key][0])

            ips.append(ip)

            # add ips to interface
            self._new_interface(interface)
            if "ipv6" not in self.facts["interfaces"][interface]:
                self.facts["interfaces"][interface]["ipv6"] = list()

            self.facts["interfaces"][interface]["ipv6"].append(dict(address=ip))

        return ips

    def _new_interface(self, interface):

        if interface in self.facts["interfaces"]:
            return
        else:
            self.facts["interfaces"][interface] = dict()
            self.facts["interfaces"][interface]["mtu"] = self._mtu
            self.facts["interfaces"][interface]["admin_state"] = "up"
            self.facts["interfaces"][interface]["description"] = None
            self.facts["interfaces"][interface]["state"] = "up"
            self.facts["interfaces"][interface]["bandwidth"] = None
            self.facts["interfaces"][interface]["bandwith"] = None
            self.facts["interfaces"][interface]["duplex"] = None
            self.facts["interfaces"][interface]["negotiation"] = None
            self.facts["interfaces"][interface]["control"] = None
            return

    def populate_addresses_ipv6(self, data):
        tables = ciscosmb_split_to_tables(data)

        ip_table = ciscosmb_parse_table(tables[0])
        ips = self._populate_address_ipv6(ip_table)
        self.facts["all_ipv6_addresses"] = ips

    def populate_interfaces_mtu(self, data):
        # by documentation SG350
        match = re.search(r"Jumbo frames are enabled", data, re.M)
        if match:
            mtu = 9000
        else:
            mtu = 1518

        self._mtu = mtu

    def populate_neighbors(self, data):
        tables = ciscosmb_split_to_tables(data)

        neighbor_table = ciscosmb_parse_table(
            tables[0],
            allow_empty_fields=[3, 4]
        )

        neighbors = dict()
        for key in neighbor_table:
            neighbor = neighbor_table[key]

            ifcname = interface_canonical_name(neighbor[0])

            host = neighbor[3]
            port = neighbor[2]

            hostport = {"host": host, "port": port}

            if ifcname not in neighbors:
                neighbors[ifcname] = list()

            neighbors[ifcname].append(hostport)

        self.facts["neighbors"] = neighbors


FACT_SUBSETS = dict(
    default=Default,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
)

VALID_SUBSETS = frozenset(FACT_SUBSETS.keys())

warnings = list()


def main():
    """main entry point for module execution"""
    argument_spec = dict(
        gather_subset=dict(
            default=["!config"],
            type="list",
            elements="str",
            choices=[
                "all",
                "default",
                "hardware",
                "interfaces",
                "config",
                "!hardware",
                "!interfaces",
                "!config",
            ],
        )
    )

    argument_spec.update(ciscosmb_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    gather_subset = module.params["gather_subset"]

    runable_subsets = set()
    exclude_subsets = set()

    for subset in gather_subset:
        if subset == "all":
            runable_subsets.update(VALID_SUBSETS)
            continue

        if subset.startswith("!"):
            subset = subset[1:]
            if subset == "all":
                exclude_subsets.update(VALID_SUBSETS)
                continue
            exclude = True
        else:
            exclude = False

        if subset not in VALID_SUBSETS:
            module.fail_json(msg="Bad subset: %s" % subset)

        if exclude:
            exclude_subsets.add(subset)
        else:
            runable_subsets.add(subset)

    if not runable_subsets:
        runable_subsets.update(VALID_SUBSETS)

    runable_subsets.difference_update(exclude_subsets)
    runable_subsets.add("default")

    facts = dict()
    facts["gather_subset"] = list(runable_subsets)

    instances = list()
    for key in runable_subsets:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        inst.populate()
        facts.update(inst.facts)

    ansible_facts = dict()
    for key, value in iteritems(facts):
        key = "ansible_net_%s" % key
        ansible_facts[key] = value

    module.exit_json(ansible_facts=ansible_facts, warnings=warnings)


if __name__ == "__main__":
    main()
