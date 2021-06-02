"""
Testbed file related utilities.
"""
from __future__ import print_function
import argparse
import csv
import ipaddr as ipaddress
import json
import os
import re
import string
import yaml
import logging

from collections import defaultdict
from collections import OrderedDict

logger = logging.getLogger(__name__)


class TestbedInfo(object):
    """Parse the testbed file used to describe whole testbed info."""

    TESTBED_FIELDS_DEPRECATED = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf', 'ptf_ip', 'ptf_ipv6', 'server', 'vm_base', 'dut', 'comment')
    TESTBED_FIELDS_RECOMMENDED = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf', 'ptf_ip', 'ptf_ipv6', 'server', 'vm_base', 'dut', 'inv_name', 'auto_recover', 'comment')

    def __init__(self, testbed_file):
        if testbed_file.endswith(".csv"):
            self.testbed_filename = testbed_file
            self.testbed_yamlfile = testbed_file.replace(".csv", ".yaml")
            """
            TODO: don't give preference to yaml unless specified explicitly.
                  we need to make sure the ansible tasks are also can use
                  testbed.yaml first.
            logging.warn(
                "Deprecated CSV format testbed file, please use yaml file"
                )
            if os.path.exists(self.testbed_yamlfile):
                logging.debug(
                    "Use yaml testbed file: %s", self.testbed_yamlfile
                    )
                self.testbed_filename = self.testbed_yamlfile
            """
        elif testbed_file.endswith(".yaml"):
            self.testbed_filename = testbed_file
        else:
            raise ValueError("Unsupported testbed file type")

        # use OrderedDict here to ensure yaml file has same order as csv.
        self.testbed_topo = OrderedDict()
        # use to convert from netmask to cidr
        self._address_cache = {}
        if self.testbed_filename.endswith(".yaml"):
            self._read_testbed_topo_from_yaml()
        if self.testbed_filename.endswith(".csv"):
            self._read_testbed_topo_from_csv()
            # create yaml testbed file
            self.dump_testbeds_to_yaml()
        self.parse_topo()

    def _cidr_to_ip_mask(self, network):
        addr = ipaddress.IPNetwork(network)
        ip_address, netmask = str(addr.ip), str(addr.netmask)
        self._address_cache[(ip_address, netmask)] = network
        return ip_address, netmask

    def _ip_mask_to_cidr(self, ip_address, netmask):
        return self._address_cache[(ip_address, netmask)]

    def _read_testbed_topo_from_csv(self):
        """Read csv testbed info file."""
        with open(self.testbed_filename) as f:
            header = [field.strip(' #') for field in f.readline().strip().split(',')]
            print(header)
            if len(header) == len(self.TESTBED_FIELDS_DEPRECATED):
                self.testbed_fields = self.TESTBED_FIELDS_DEPRECATED
            elif len(header) == len(self.TESTBED_FIELDS_RECOMMENDED):
                self.testbed_fields = self.TESTBED_FIELDS_RECOMMENDED
            else:
                raise ValueError('Unsupported testbed fields %s' % str(header))
            for header_field, expect_field in zip(header, self.testbed_fields):
                assert header_field == expect_field

            topo = csv.DictReader(f, fieldnames=self.testbed_fields, delimiter=',')

            for line in topo:
                if line['conf-name'].lstrip().startswith('#'):
                    # skip comment line
                    continue
                if line['ptf_ip']:
                    line['ptf_ip'], line['ptf_netmask'] = \
                        self._cidr_to_ip_mask(line['ptf_ip'])
                if line['ptf_ipv6']:
                    line['ptf_ipv6'], line['ptf_netmask_v6'] = \
                        self._cidr_to_ip_mask(line['ptf_ipv6'])

                line['duts'] = line['dut'].translate(string.maketrans("", ""), "[] ").split(';')
                line['duts_map'] = {dut: line['duts'].index(dut) for dut in line['duts']}
                del line['dut']

                self.testbed_topo[line['conf-name']] = line

    def _read_testbed_topo_from_yaml(self):
        """Read yaml testbed info file."""
        with open(self.testbed_filename) as f:
            tb_info = yaml.safe_load(f)
            for tb in tb_info:
                if tb["ptf_ip"]:
                    tb["ptf_ip"], tb["ptf_netmask"] = \
                        self._cidr_to_ip_mask(tb["ptf_ip"])
                if tb["ptf_ipv6"]:
                    tb["ptf_ipv6"], tb["ptf_netmask_v6"] = \
                        self._cidr_to_ip_mask(tb["ptf_ipv6"])
                tb["duts"] = tb.pop("dut")
                tb["duts_map"] = {dut: i for i, dut in enumerate(tb["duts"])}
                self.testbed_topo[tb["conf-name"]] = tb

    def dump_testbeds_to_yaml(self):

        def none_representer(dumper, _):
            return dumper.represent_scalar("tag:yaml.org,2002:null", "")

        def ordereddict_representer(dumper, data):
            value = []
            node = yaml.MappingNode("tag:yaml.org,2002:map", value)
            for item_key, item_value in data.items():
                node_key = dumper.represent_data(item_key)
                node_value = dumper.represent_data(item_value)
                value.append((node_key, node_value))
            return node

        class IncIndentDumper(yaml.Dumper):
            """
            Dumper class to increase indentation for nested list.

            Add extra indentation since py-yaml doesn't add extra
            indentation for list inside mapping by default [1].

            This also add extra blank lines between each testbed entry [2].

            [1]: https://web.archive.org/web/20170903201521/https://pyyaml.org/ticket/64
            [2]: https://github.com/yaml/pyyaml/issues/127
            """

            def increase_indent(self, flow=False, indentless=False):
                return yaml.Dumper.increase_indent(self, flow, False)

            def write_line_break(self, data=None):
                yaml.Dumper.write_line_break(self, data)
                if len(self.indents) == 1:
                    yaml.Dumper.write_line_break(self)

        testbed_data = []
        for tb_name, tb_dict in self.testbed_topo.items():
            ptf_ip, ptf_ipv6 = None, None
            if tb_dict["ptf_ip"]:
                ptf_ip = self._ip_mask_to_cidr(tb_dict["ptf_ip"],
                                               tb_dict["ptf_netmask"])
            if tb_dict["ptf_ipv6"]:
                ptf_ipv6 = self._ip_mask_to_cidr(tb_dict["ptf_ipv6"],
                                                 tb_dict["ptf_netmask_v6"])

            if len(self.testbed_fields) == len(self.TESTBED_FIELDS_DEPRECATED):
                tb_dict_fields = [
                    tb_name,
                    tb_dict["group-name"],
                    tb_dict["topo"],
                    tb_dict["ptf_image_name"],
                    tb_dict["ptf"],
                    ptf_ip,
                    ptf_ipv6,
                    tb_dict["server"],
                    tb_dict["vm_base"] or None,
                    tb_dict["duts"],
                    tb_dict["comment"]
                ]
            elif len(self.testbed_fields) == len(self.TESTBED_FIELDS_RECOMMENDED):
                tb_dict_fields = [
                    tb_name,
                    tb_dict["group-name"],
                    tb_dict["topo"],
                    tb_dict["ptf_image_name"],
                    tb_dict["ptf"],
                    ptf_ip,
                    ptf_ipv6,
                    tb_dict["server"],
                    tb_dict["vm_base"] or None,
                    tb_dict["duts"],
                    tb_dict["inv_name"],
                    tb_dict["auto_recover"],
                    tb_dict["comment"]
                ]
            testbed_mapping = zip(self.testbed_fields, tb_dict_fields)
            testbed = OrderedDict(testbed_mapping)
            testbed_data.append(testbed)

        # dump blank instead of 'null' for None
        IncIndentDumper.add_representer(type(None), none_representer)
        # dump testbed fields in the order same as csv
        IncIndentDumper.add_representer(OrderedDict, ordereddict_representer)

        with open(self.testbed_yamlfile, "w") as yamlfile:
            yaml.dump(testbed_data, yamlfile,
                      explicit_start=True, Dumper=IncIndentDumper)

    def get_testbed_type(self, topo_name):
        pattern = re.compile(r'^(t0|t1|ptf|fullmesh|dualtor|t2|tgen|mgmttor)')
        match = pattern.match(topo_name)
        if match == None:
            logger.warning("Unsupported testbed type - {}".format(topo_name))
            return "unsupported"
        tb_type = match.group()
        if tb_type in ['mgmttor', 'dualtor']:
            # certain testbed types are in 't0' category with different names.
            tb_type = 't0'
        return tb_type

    def _parse_dut_port_index(self, port):
        """
        parse port string

        port format : dut_index.port_index@ptf_index

        """
        m = re.match("(\d+)(?:\.(\d+))?(?:@(\d+))?", str(port).strip())
        m1, m2, m3 = m.groups()
        if m3:
            # Format: <dut_index>.<port_index>@<ptf_index>
            # Example: ['0.0@0,1.0@0', '0.1@1,1.1@1', '0.2@2,1.2@2', ... ]
            dut_index = m1
            port_index = m2
            ptf_index = m3
        else:
            if m2:
                # Format: <dut_index>.<port_index>
                # Example: ['0.0,1.0', '0.1,1.1', '0.2,1.2', ... ]
                dut_index = m1
                port_index = m2
                ptf_index = m2
            else:
                # Format: <port_index>
                # Example: ['0', '1', '2']
                dut_index = '0'
                port_index = m1
                ptf_index = m1
        return dut_index, port_index, ptf_index

    def calculate_ptf_index_map(self, tb):
        map = defaultdict(dict)

        # For multi-DUT testbed, because multiple DUTs are sharing a same
        # PTF docker, the ptf docker interface index will not be exactly
        # match the interface index on DUT. The information is available
        # in the topology facts. Get these information out and put them
        # in the 2 levels dictionary as:
        # { dut_index : { dut_port_index : ptf_index * } * }

        topo_facts = tb['topo']['properties']
        if 'topology' not in topo_facts:
            return map

        topology = topo_facts['topology']
        if 'host_interfaces' in topology:
            for _ports in topology['host_interfaces']:
                # Example: ['0', '1', '2']
                # Example: ['0.0,1.0', '0.1,1.1', '0.2,1.2', ... ]
                # Example: ['0.0@0,1.0@0', '0.1@1,1.1@1', '0.2@2,1.2@2', ... ]
                for port in str(_ports).split(','):
                    dut_index, dut_port_index, ptf_port_index = self._parse_dut_port_index(port)
                    map[dut_index][dut_port_index] = int(ptf_port_index)

        if 'VMs' in topology:
            for vm in topology['VMs'].values():
                if 'vlans' in vm:
                    for port in vm['vlans']:
                        # Example: '0.31@34'
                        dut_index, dut_port_index, ptf_port_index = self._parse_dut_port_index(port)
                        map[dut_index][dut_port_index] = int(ptf_port_index)
        return map

    def calculate_ptf_index_map_disabled(self, tb):
        map = defaultdict(dict)
        topo_facts = tb['topo']['properties']
        if 'topology' not in topo_facts:
            return map

        topology = topo_facts['topology']
        if 'disabled_host_interfaces' in topology:
            for _ports in topology['disabled_host_interfaces']:
                # Example: ['0', '1', '2']
                # Example: ['0.0,1.0', '0.1,1.1', '0.2,1.2', ... ]
                # Example: ['0.0@0,1.0@0', '0.1@1,1.1@1', '0.2@2,1.2@2', ... ]
                for port in str(_ports).split(','):
                    dut_index, dut_port_index, ptf_port_index = self._parse_dut_port_index(port)
                    map[dut_index][dut_port_index] = int(ptf_port_index)
        return map

    def calculate_ptf_dut_intf_map(self, tb):
        map = defaultdict(dict)
        for dut_index, dut_ptf_map in tb['topo']['ptf_map'].items():
            for dut_port_index, ptf_port_index in dut_ptf_map.items():
                map[str(ptf_port_index)][dut_index] = int(dut_port_index)
        return map

    def parse_topo(self):
        for tb_name, tb in self.testbed_topo.items():
            topo = tb.pop("topo")
            tb["topo"] = defaultdict()
            tb["topo"]["name"] = topo
            tb["topo"]["type"] = self.get_testbed_type(topo)
            topo_dir = os.path.join(os.path.dirname(__file__), "../../ansible/vars/")
            topo_file = os.path.join(topo_dir, "topo_{}.yml".format(topo))
            with open(topo_file, 'r') as fh:
                tb['topo']['properties'] = yaml.safe_load(fh)
            tb['topo']['ptf_map'] = self.calculate_ptf_index_map(tb)
            tb['topo']['ptf_map_disabled'] = self.calculate_ptf_index_map_disabled(tb)
            tb['topo']['ptf_dut_intf_map'] = self.calculate_ptf_dut_intf_map(tb)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        Render testbed file, input could be either CSV or yaml file.
        If input is a CSV file, will dump its content as a yaml file with the
        same name in same directory.
        """
    )

    file_group = parser.add_mutually_exclusive_group(required=True)
    file_group.add_argument("-y", "--yaml", dest="testbed_yamlfile", help="testbed yaml file")
    file_group.add_argument("-c", "--csv", dest="testbed_csvfile", help="testbed csv file")

    parser.add_argument("--print-data", help="print testbed", action="store_true")

    args = parser.parse_args()
    testbedfile = args.testbed_csvfile or args.testbed_yamlfile
    tbinfo = TestbedInfo(testbedfile)
    if args.print_data:
        print(json.dumps(tbinfo.testbed_topo, indent=4))
