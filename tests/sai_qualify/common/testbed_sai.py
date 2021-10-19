from __future__ import print_function
import argparse
import yaml
import logging
from collections import OrderedDict
logger = logging.getLogger(__name__)


class SAITestbedInfo(object):
    """Parse the testbed file used to describe whole testbed info."""

    TESTBED_FIELDS_RECOMMENDED = ('conf-name', 'group-name', 'topo', 'ptf_image_name', 'ptf',
                                  'ptf_ip', 'ptf_ipv6', 'server', 'vm_base', 'dut', 'inv_name', 'auto_recover', 'comment')

    def __init__(self, testbed_file):
        if testbed_file.endswith(".yaml"):
            self.testbed_filename = testbed_file
        else:
            raise ValueError("Unsupported testbed file type")

        # use OrderedDict here to ensure yaml file has same order as csv.
        self.testbed_topo = OrderedDict()

        if self.testbed_filename.endswith(".yaml"):
            self._read_testbed_topo_from_yaml()

    def _read_testbed_topo_from_yaml(self):
        """Read yaml testbed info file."""
        with open(self.testbed_filename) as f:
            tb_info = yaml.safe_load(f)
            for tb in tb_info:
                self.testbed_topo[tb["conf-name"]] = tb

    def dump_testbeds_to_yaml(self, args):

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
        tb_name = args.sai_testbed_name
        sai_topo = ""
        sai_ptf_image = ""

        if self.testbed_topo[tb_name]["topo"] not in ["ptf32", "ptf64"]:
            sai_topo = "ptf32"
        else:
            sai_topo = self.testbed_topo[tb_name]["topo"]

        if args.sai_test_ptf:
            sai_ptf_image = args.sai_test_ptf
        else:
            sai_ptf_image = "docker-ptf"

        tb_dict_fields = [
            tb_name,
            self.testbed_topo[tb_name]["group-name"],
            sai_topo,
            sai_ptf_image,
            self.testbed_topo[tb_name]["ptf"],
            self.testbed_topo[tb_name]["ptf_ip"],
            self.testbed_topo[tb_name]["ptf_ipv6"],
            self.testbed_topo[tb_name]["server"],
            self.testbed_topo[tb_name]["vm_base"] or None,
            self.testbed_topo[tb_name]["dut"],
            self.testbed_topo[tb_name]["inv_name"],
            self.testbed_topo[tb_name]["auto_recover"],
            "SAI Testing"
        ]
        testbed_mapping = zip(
            self.TESTBED_FIELDS_RECOMMENDED, tb_dict_fields)
        testbed = OrderedDict(testbed_mapping)
        testbed_data.append(testbed)

        # dump blank instead of 'null' for None
        IncIndentDumper.add_representer(type(None), none_representer)
        # dump testbed fields in the order same as csv
        IncIndentDumper.add_representer(OrderedDict, ordereddict_representer)

        with open("testbed_sai.yaml", "w+") as yamlfile:
            yaml.dump(testbed_data, yamlfile,
                      explicit_start=True, Dumper=IncIndentDumper)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        Render testbed file, input could be either CSV or yaml file.
        If input is a CSV file, will dump its content as a yaml file with the
        same name in same directory.
        """
    )

    parser.add_argument(
        "-f", "--yaml", dest="testbed_yamlfile", help="testbed yaml file",  required=True)
    parser.add_argument(
        "-n", "--testbed", dest="sai_testbed_name", help="sai testbed name")
    parser.add_argument(
        "-p", "--ptf", dest="sai_test_ptf", help="sai test ptf image")

    args = parser.parse_args()
    testbedfile = args.testbed_yamlfile

    if str(testbedfile).endswith("testbed.yaml"):
        tbinfo = SAITestbedInfo(testbedfile)
        tbinfo.dump_testbeds_to_yaml(args)
    else:
        raise Exception("No testbed.yaml file provided")