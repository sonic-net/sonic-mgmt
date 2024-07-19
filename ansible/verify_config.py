import argparse
import csv
import glob
import logging
import os
from abc import ABC, abstractmethod
from collections import deque
from enum import Enum
from functools import lru_cache
from typing import Callable, Deque, Dict, List, Set

import yaml


class Formatting(Enum):
    BOLD = "\033[1m"
    YELLOW = "\033[33m"
    UNDERLINE = '\033[4m'
    END = "\033[0m"
    RED = "\033[91m"

    @staticmethod
    def bold(word: str):
        return f"{Formatting.BOLD.value}{word}{Formatting.END.value}"

    @staticmethod
    def yellow(word: str):
        return f"{Formatting.YELLOW.value}{word}{Formatting.END.value}"

    @staticmethod
    def red(word: str):
        return f"{Formatting.RED.value}{word}{Formatting.END.value}"

    @staticmethod
    def underline(word: str):
        return f"{Formatting.UNDERLINE.value}{word}{Formatting.END.value}"


class Formatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            self._style._fmt = "%(message)s"
        elif record.levelno == logging.WARNING:
            self._style._fmt = f"{Formatting.bold(Formatting.yellow('[%(levelname)s]'))}: %(message)s"
        elif record.levelno == logging.ERROR:
            self._style._fmt = f"{Formatting.bold(Formatting.red('[%(levelname)s]'))}: %(message)s"
        return super().format(record)


log = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(Formatter())
log.setLevel(logging.INFO)
log.addHandler(handler)


class VMRange:
    def __init__(self, vm_base: str, topo_name: str):
        self.topo_name = topo_name
        self.start = self._parse_start(vm_base)
        self.end = self._parse_end(vm_base)

    def _parse_start(self, vm_base):
        filtered = ''.join(filter(lambda x: x.isdigit(), vm_base))
        return int(filtered)

    def _parse_end(self, vm_base):
        start = self._parse_start(vm_base)
        return start + Utility.get_num_vm(self.topo_name) - 1

    def __contains__(self, vm_range: 'VMRange'):
        return not (self.end < vm_range.start or vm_range.end < self.start)


class Assertion:
    def __init__(self, file):
        self.file = file
        self.pass_validation = True
        self.error_details = deque()

    def assert_true(self, fn: Callable[[], bool], reason: str):
        if not fn():
            self.pass_validation = False
            self.log_error(reason, error_file=self.file, error_details=self.error_details)

    def add_error_details(self, detail: str):
        self.error_details.append(detail)

    def log_error(self, reason: str, error_file: str, error_type='warning', error_details: Deque[str] = None):
        getattr(log, error_type)(
            f"{reason}. Error file: '{Formatting.yellow(error_file)}'." + (" Details:" if len(error_details) else ""))
        while error_details:
            log.info("\t- " + error_details.popleft())


class Config(Enum):
    DOCKER_REGISTRY_FILE = "vars/docker_registry.yml"
    TESTBED_FILE = "testbed.yaml"
    TOPO_FILE_PATTERN = "vars/topo*.yml"
    VEOS_FILE = "veos"
    FANOUT_LINKS_FILE = "files/sonic_*_links.csv"
    FANOUT_DEVICES_FILE = "files/sonic_*_devices.csv"
    FANOUT_BMC_LINKS_FILE = "files/sonic_*_bmc_links.csv"
    FANOUT_PDU_LINKS_FILE = "files/sonic_*_pdu_links.csv"
    FANOUT_CONSOLE_LINKS_FILE = "files/sonic_*_console_links.csv"
    FANOUT_GRAPH_GROUP_FILE = "files/graph_groups.yml"


class Utility:
    @staticmethod
    @lru_cache
    def parse_yml(file: str):
        with open(file, "r") as stream:
            return yaml.safe_load(stream)

    @staticmethod
    @lru_cache
    def parse_csv(file: str) -> List[Dict[str, str]]:
        try:
            with open(file, "r") as stream:
                return list(csv.DictReader(stream))
        except FileNotFoundError:
            return []

    @staticmethod
    @lru_cache
    def get_devices_from_links_file(file: str) -> Set[str]:
        devices = set()

        for row in Utility.parse_csv(file):
            devices.add(row['StartDevice'])
            devices.add(row['EndDevice'])

        return devices

    @staticmethod
    @lru_cache
    def get_devices_from_devices_file(file: str) -> Set[str]:
        devices = set()

        for row in Utility.parse_csv(file):
            devices.add(row['Hostname'])

        return devices

    @staticmethod
    @lru_cache
    def get_topo_from_var_files() -> Set[str]:
        topo_name_set = set()

        for topo_file_path in glob.glob(os.path.abspath(Config.TOPO_FILE_PATTERN.value)):
            file_name, _ = os.path.basename(topo_file_path).split(".")
            topo_name = file_name[len("topo_"):]
            topo_name_set.add(topo_name)

        return topo_name_set

    @staticmethod
    @lru_cache
    def get_inv_name_from_file(link_file: str):
        inv_name_set = set()

        for inv_file_path in glob.glob(os.path.abspath(link_file)):
            file_name, _ = os.path.basename(inv_file_path).split(".")

            inv_name = file_name[len("sonic_"): file_name.index("_", len("sonic_"))]
            inv_name_set.add(inv_name)

        return inv_name_set

    @staticmethod
    @lru_cache
    def get_num_vm(topo_name: str) -> int:
        topology = Utility.parse_yml(Config.TOPO_FILE_PATTERN.value.replace("*", f"_{topo_name}"))
        if 'topology' not in topology or 'VMs' not in topology['topology']:
            return 0

        return len(topology['topology']['VMs'])


class Validator(ABC):
    def __init__(self, validate_file):
        self._file = validate_file
        self.assertion = Assertion(self.file)

    @property
    def file(self):
        return self._file

    @file.setter
    def file(self, file_name: str):
        if not file_name:
            return None

        file_name = os.path.abspath(file_name)
        self.assertion.file = file_name
        return file_name

    @abstractmethod
    def validate(self):
        pass


class DockerRegistryValidator(Validator):
    def __init__(self):
        super().__init__(Config.DOCKER_REGISTRY_FILE.value)

    def validate(self):
        var: Dict[str, str] = Utility.parse_yml(self.file)
        self.assertion.assert_true(lambda: self._assertion_fn(var),
                                   reason=f"Key '{Formatting.red('docker_registry_host')}' must be defined")

    def _assertion_fn(self, var: Dict[str, str]):
        required_key = 'docker_registry_host'
        return required_key in var and var[required_key] is not None


class TestbedValidator(Validator):
    def __init__(self):
        super().__init__(Config.TESTBED_FILE.value)

    def validate(self):
        conf_name_check_unique = set()
        group_name_check = {}
        conf_name_to_vm_range: Dict[str, VMRange] = {}

        for testbed in Utility.parse_yml(self.file):
            conf_name = testbed['conf-name']

            self.assertion.assert_true(lambda: self._required_attributes_must_be_in_testbed(testbed),
                                       reason=f"Required attributes must be in testbed '{Formatting.red(conf_name)}'")
            self.assertion.assert_true(lambda: conf_name not in conf_name_check_unique,
                                       reason=f"Config name conf_name='{Formatting.red(conf_name)}' must be unique")
            self.assertion.assert_true(lambda: len(testbed['group-name']) <= 8,
                                       reason=f"Group name '{Formatting.red(testbed['group-name'])}' must be up to 8 "
                                              f"characters long. Actual length: {len(testbed['group-name'])}")
            self.assertion.assert_true(lambda: self._group_name_must_have_unique_attributes(group_name_check, testbed),
                                       reason=f"Group name '{Formatting.red(testbed['group-name'])}' of "
                                              f"'{Formatting.red(conf_name)}' does not have unique attributes")
            self.assertion.assert_true(lambda: testbed['topo'] in Utility.get_topo_from_var_files(),
                                       reason=f"Topology name '{Formatting.red(testbed['topo'])}' is not "
                                              f"declared in '{Config.TOPO_FILE_PATTERN.value}'")
            self.assertion.assert_true(lambda: self._topo_name_must_be_in_veos_file(testbed),
                                       reason=f"Topology name '{Formatting.red(testbed['topo'])}' is not "
                                              f"declared in '{Config.VEOS_FILE.value}'")
            self.assertion.assert_true(lambda: self._server_name_must_be_in_veos_file(testbed),
                                       reason=f"Server name '{Formatting.red(testbed['server'])}' is not "
                                              f"declared in '{Config.VEOS_FILE.value}'")

            if testbed['vm_base']:
                self.assertion.assert_true(lambda: Utility.get_num_vm(testbed['topo']) != 0,
                                           reason=f"Topology '{Formatting.red(testbed['topo'])}' does not declared to "
                                                  f"have VM in '{Config.TOPO_FILE_PATTERN.value}' but its VM base "
                                                  f"specified as '{testbed['vm_base']}' in '"
                                                  f"{Formatting.red(conf_name)}'")

                vm_range = VMRange(testbed['vm_base'], testbed['topo'])
                self.assertion.assert_true(
                    lambda: self._vm_base_must_not_overlap(testbed, vm_range, conf_name_to_vm_range),
                    reason=f"VM base '{Formatting.red(conf_name)}' must not overlap with other testbed")
                conf_name_to_vm_range[conf_name] = vm_range

            conf_name_check_unique.add(conf_name)
            group_name_check[testbed['group-name']] = {"conf-name": conf_name, "ptf_ip": testbed["ptf_ip"],
                                                       "server": testbed["server"], "vm_base": testbed["vm_base"]}

    def _vm_base_must_not_overlap(self, testbed, vm_range: VMRange, conf_name_to_vm_range):
        is_valid = True

        for conf_name in conf_name_to_vm_range:
            occupied_range = conf_name_to_vm_range[conf_name]

            if vm_range in occupied_range:
                self.assertion.add_error_details(
                    f"VM Range of '{testbed['conf-name']}' (start={vm_range.start}, end={vm_range.end}) is overlap "
                    f"with '{conf_name}' (start={occupied_range.start}, end={occupied_range.end})")
                is_valid = False

        return is_valid

    def _group_name_must_have_unique_attributes(self, group_name_check, testbed) -> bool:
        unique_attributes = ["ptf_ip", "server", "vm_base"]
        is_valid = True

        group_name = testbed["group-name"]

        if group_name not in group_name_check:
            return True

        group_name_attributes = group_name_check[group_name]
        for attribute in unique_attributes:
            if testbed[attribute] != group_name_attributes[attribute]:
                self.assertion.add_error_details(
                    f"Attribute: {attribute}={testbed[attribute]} is not the same in group name '{group_name}' for "
                    f"conf-name='{testbed['conf-name']}'. Previously declared as {attribute}="
                    f"{group_name_attributes[attribute]} in conf-name={group_name_attributes['conf-name']}")
                is_valid = False

        return is_valid

    def _server_name_must_be_in_veos_file(self, testbed) -> bool:
        try:
            return (testbed['server'] in
                    Utility.parse_yml(Config.VEOS_FILE.value)['all']['children']['servers']['children'])
        except KeyError as unknown_key:
            self.assertion.add_error_details(f"Key not found: {unknown_key}")
            self.assertion.log_error(
                "veos file is not in the correct format. Update the file or update this script",
                error_file=Config.VEOS_FILE.value,
                error_type="error"
            )

    def _topo_name_must_be_in_veos_file(self, testbed) -> bool:
        try:
            return testbed['topo'] in Utility.parse_yml(Config.VEOS_FILE.value)['all']['children']['servers']['vars'][
                'topologies']
        except KeyError as unknown_key:
            self.assertion.add_error_details(f"Key not found: {unknown_key}")
            self.assertion.log_error(
                "veos file is not in the correct format. Update the file or update this script",
                error_file=Config.VEOS_FILE.value,
                error_type="error"
            )

    def _required_attributes_must_be_in_testbed(self, testbed: Dict['str', 'str']) -> bool:
        is_valid = True
        required_attributes = {
            "conf-name",
            "group-name",
            "topo",
            "ptf_image_name",
            "ptf_ip",
            "server",
            "vm_base",
            "dut",
            "inv_name",
            "auto_recover",
            "comment"
        }

        missing_keys = required_attributes - testbed.keys()

        if missing_keys:
            self.assertion.add_error_details(f"Found missing required keys: {missing_keys}")
            is_valid = False

        return is_valid


class InventoryNameValidator(Validator):
    def __init__(self):
        super().__init__(Config.FANOUT_GRAPH_GROUP_FILE.value)

    def validate(self):
        self.assertion.assert_true(lambda: self._inv_name_from_devices_files_must_be_the_same_as_graph_group_yml_file(),
                                   reason="Inventory name must be consistence between "
                                          f"{Formatting.bold(Config.FANOUT_GRAPH_GROUP_FILE.value)} and "
                                          f"{Formatting.bold(Config.FANOUT_DEVICES_FILE.value)}")
        self.assertion.assert_true(lambda: self._check_if_inv_name_has_inv_file(),
                                   reason="Inventory should have an inventory file")

    def _inv_name_from_devices_files_must_be_the_same_as_graph_group_yml_file(self):
        inv_name_from_devices_files: Set[str] = Utility.get_inv_name_from_file(Config.FANOUT_DEVICES_FILE.value)
        inv_name_from_graph_group_yml_file: Set[str] = set(Utility.parse_yml(self.file))

        differences = inv_name_from_devices_files ^ inv_name_from_graph_group_yml_file

        if len(differences) != 0:
            self.assertion.add_error_details(
                "These are the group names that are not consistent between the 2 files: "
                f"{Formatting.red(', '.join(differences))}")
            return False

        return True

    def _check_if_inv_name_has_inv_file(self):
        is_valid = True
        inv_name_from_graph_group_yml_file: Set[str] = set(Utility.parse_yml(Config.FANOUT_GRAPH_GROUP_FILE.value))
        inv_files = set([f for f in os.listdir('.') if os.path.isfile(f)])

        for inv_name in inv_name_from_graph_group_yml_file:
            if inv_name not in inv_files:
                is_valid = False
                self.assertion.add_error_details(
                    f"'{Formatting.red(inv_name)}' is declared in "
                    f"{Formatting.bold(Config.FANOUT_GRAPH_GROUP_FILE.value)}"
                    f"but does not have inventory file. Consider creating '{Formatting.bold('ansible/' + inv_name)}'")
        return is_valid


class FanoutLinkValidator(Validator):
    def __init__(self):
        super().__init__(None)

    def validate(self):
        params = [
            {"name": "Link file", "file": Config.FANOUT_LINKS_FILE.value},
            {"name": "Pdu link file", "file": Config.FANOUT_PDU_LINKS_FILE.value},
            {"name": "Bmc link file", "file": Config.FANOUT_BMC_LINKS_FILE.value},
            {"name": "Console link file", "file": Config.FANOUT_CONSOLE_LINKS_FILE.value}
        ]

        for param in params:
            self.file = param["file"]
            self.assertion.assert_true(lambda: self._links_file_should_have_equivalent_devices_file(param),
                                       reason=f"{param['name']} should have its equivalent devices file")
            self.assertion.assert_true(lambda: self._devices_in_links_file_should_be_in_devices_file(param),
                                       reason=f"{param['name']} devices does not exist in its devices file")

    def _links_file_should_have_equivalent_devices_file(self, param: Dict[str, str]):
        inv_name_from_links_files: Set[str] = Utility.get_inv_name_from_file(param["file"])
        inv_name_from_devices_files: Set[str] = Utility.get_inv_name_from_file(Config.FANOUT_DEVICES_FILE.value)

        differences = inv_name_from_links_files - inv_name_from_devices_files

        if len(differences) != 0:
            self.assertion.add_error_details(
                f"These are the group names that does not have devices file: {Formatting.red(', '.join(differences))}. "
                "Consider creating "
                f"[{', '.join(Formatting.bold(f'files/sonic_{group_name}_devices.csv') for group_name in differences)}]"
            )
            return False

        return True

    def _devices_in_links_file_should_be_in_devices_file(self, param: Dict[str, str]):
        is_valid = True
        inv_name_from_links_files: Set[str] = Utility.get_inv_name_from_file(param["file"])

        for group_name in inv_name_from_links_files:
            device_file = Config.FANOUT_DEVICES_FILE.value.replace("*", group_name)
            link_file = param['file'].replace("*", group_name)
            devices_from_links_file = Utility.get_devices_from_links_file(link_file)
            devices_from_devices_file = Utility.get_devices_from_devices_file(device_file)

            differences = devices_from_links_file - devices_from_devices_file

            if len(differences) != 0:
                self.assertion.add_error_details(
                    "These are the devices that are in "
                    f"{Formatting.yellow(param['file'].replace('*', group_name))} "
                    f"but not in devices file: {Formatting.red(', '.join(differences))}. "
                    f"Consider adding in {Formatting.bold(device_file)}")
                is_valid = False

        return is_valid


def main(args):
    validators: List[Validator] = [
        DockerRegistryValidator(),
        TestbedValidator(),
        InventoryNameValidator(),
        FanoutLinkValidator()
    ]

    for validator in validators:
        validator.validate()

    if all(map(lambda _validator: _validator.assertion.pass_validation, validators)):
        log.info("Successful! No validation error found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify if configuration files are valid")
    main(parser.parse_args())
