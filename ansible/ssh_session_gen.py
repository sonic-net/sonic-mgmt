"""
Script used to generate SSH session files for console access to devices.
"""

import argparse
import os
import re
from typing import Dict, List, Optional, Tuple
from devutil.device_inventory import DeviceInfo, DeviceInventory
from devutil.testbed import TestBed
from devutil.inv_helpers import HostManager
from devutil.ssh_session_repo import (
    SecureCRTSshSessionRepoGenerator,
    SshConfigSshSessionRepoGenerator,
    SshSessionRepoGenerator,
)


class SSHInfoSolver(object):
    """SSH info solver for testbeds and devices."""

    def __init__(
        self,
        ansible_hosts: HostManager,
        dut_user: Optional[str],
        dut_pass: Optional[str],
        server_user: Optional[str],
        server_pass: Optional[str],
        leaf_fanout_user: Optional[str],
        leaf_fanout_pass: Optional[str],
        root_fanout_user: Optional[str],
        root_fanout_pass: Optional[str],
        console_server_user: Optional[str],
        console_server_pass: Optional[str],
        ptf_user: Optional[str],
        ptf_pass: Optional[str],
    ):
        """
        Init SSH credential solver.

        Args:
            ansible_hosts (HostManager): Ansible host inventory manager.
            dut_user (str): Default SSH user for DUTs.
            dut_pass (str): Default SSH password for DUTs.
            server_user (str): Default SSH user for servers.
            server_pass (str): Default SSH password for servers.
            leaf_fanout_user (str): Default SSH user for leaf fanouts.
            leaf_fanout_pass (str): Default SSH password for leaf fanouts.
            root_fanout_user (str): Default SSH user for root fanouts.
            root_fanout_pass (str): Default SSH password for root fanouts.
        """
        self.ansible_hosts = ansible_hosts

        self.ssh_overrides = {
            "Server": {"user": server_user, "pass": server_pass},
            "DevSonic": {"user": dut_user, "pass": dut_pass},
            "FanoutLeaf": {"user": leaf_fanout_user, "pass": leaf_fanout_pass},
            "FanoutLeafSonic": {"user": leaf_fanout_user, "pass": leaf_fanout_pass},
            "FanoutRoot": {"user": root_fanout_user, "pass": root_fanout_pass},
            "ConsoleServer": {"user": console_server_user, "pass": console_server_pass},
            "PTF": {"user": ptf_user, "pass": ptf_pass},
        }

    def get_ssh_cred(self, device: DeviceInfo) -> Tuple[str, str, str, str]:
        """
        Get SSH info for a testbed node.

        Args:
            device (DeviceInfo): Represents a connectable node in the testbed.

        Returns:
            tuple: SSH IP, user and password.
        """
        ssh_ip = device.management_ip
        ssh_ipv6 = None
        ssh_user = (
            self.ssh_overrides[device.device_type]["user"]
            if device.device_type in self.ssh_overrides
            else ""
        )
        ssh_pass = (
            self.ssh_overrides[device.device_type]["pass"]
            if device.device_type in self.ssh_overrides
            else ""
        )

        if not ssh_ip or not ssh_user or not ssh_pass or not ssh_ipv6:
            try:
                host_vars = self.ansible_hosts.get_host_vars(device.hostname)

                ssh_ip = host_vars["ansible_host"] if not ssh_ip else ssh_ip
                ssh_ipv6 = host_vars["ansible_hostv6"] if not ssh_ipv6 and "ansible_hostv6" in host_vars else ssh_ipv6
                ssh_user = host_vars["creds"]["username"] if not ssh_user else ssh_user
                ssh_pass = (
                    host_vars["creds"]["password"][-1] if not ssh_pass else ssh_pass
                )
            except Exception as e:
                print(
                    f"Error: Failed to get SSH credential for device {device.hostname} ({device.device_type}): {str(e)}"
                )

        ssh_ip = "" if ssh_ip is None else ssh_ip
        ssh_ipv6 = "" if ssh_ipv6 is None else ssh_ipv6
        ssh_user = "" if ssh_user is None else ssh_user
        ssh_pass = "" if ssh_pass is None else ssh_pass

        return ssh_ip, ssh_ipv6, ssh_user, ssh_pass


class DeviceSshSessionRepoGenerator(object):
    def __init__(
        self, repo_generator: SshSessionRepoGenerator, ssh_info_solver: SSHInfoSolver
    ) -> None:
        self.repo_generator = repo_generator
        self.ssh_info_solver = ssh_info_solver

    def generate_ssh_session_for_device(self, device: DeviceInfo, session_path: str):
        """Generate SSH session for a device.

        Args:
            device (DeviceInfo): Represents a device.
            session_path (str): Path to store the SSH session file.
        """
        if not device.is_ssh_supported():
            return

        ssh_ip, ssh_ipv6, ssh_user, ssh_pass = self.ssh_info_solver.get_ssh_cred(device)
        if not ssh_ip and not ssh_ipv6:
            print(
                f"WARNING: Management IP is not specified for testbed node, skipped: {device.hostname}"
            )
            return

        if not ssh_user:
            print(
                "WARNING: SSH credential is missing for device: {}".format(
                    device.hostname
                )
            )

        self.repo_generator.generate(
            session_path,
            ssh_ip,
            ssh_ipv6,
            ssh_user,
            ssh_pass,
        )


class TestBedSshSessionRepoGenerator(DeviceSshSessionRepoGenerator):
    """SSH session repo generator for testbeds."""

    def __init__(
        self,
        testbeds: Dict[str, TestBed],
        repo_generator: SshSessionRepoGenerator,
        ssh_info_solver: SSHInfoSolver,
    ):
        """
        Store all parameters as attributes.

        Args:
            testbeds (dict): Testbed name to testbed object mapping.
            repo_generator (SshSessionRepoGenerator): SSH session repo generator.
        """
        super().__init__(repo_generator, ssh_info_solver)
        self.testbeds = testbeds

    def generate(self):
        """Generate SSH session repo."""

        print("\nStart generating SSH session files for all testbeds:")

        for testbed in self.testbeds.values():
            self._generate_ssh_sessions_for_testbed(testbed)

        self.repo_generator.finish()

    def _generate_ssh_sessions_for_testbed(self, testbed: TestBed):
        """
        Generate SSH sessions for a testbed.

        Args:
            testbed (object): Represents a testbed setup.
        """
        devices = [testbed.ptf_node] + list(testbed.dut_nodes.values())
        for device in devices:
            self._generate_ssh_session_for_testbed_node(testbed, device)

    def _generate_ssh_session_for_testbed_node(
        self, testbed: TestBed, device: DeviceInfo
    ):
        """
        Generate SSH session for a testbed node.

        We use the following naming convention for SSH session path:
            testbeds/<InvName>/<TestbedName>/<NodeType>-<NodeName>

        Args:
            testbed (object): Represents a testbed setup.
            testbed_node_type (str): Type of the testbed node. It can be "ptf" or "dut".
            testbed_node (object): Represents a connectable node in the testbed.
        """
        device_type = "dut" if device.device_type != "PTF" else "ptf"

        session_path = os.path.join(
            "testbeds",
            testbed.inv_name,
            testbed.conf_name,
            device_type + "-" + device.hostname,
        )

        self.generate_ssh_session_for_device(device, session_path)


device_type_pattern = re.compile(r"(?<!^)(?=[A-Z])")


class DeviceSessionRepoGenerator(DeviceSshSessionRepoGenerator):
    """SSH session repo generator from device data."""

    def __init__(
        self,
        device_inventories: List[DeviceInventory],
        repo_generator: DeviceInventory,
        ssh_info_solver: SSHInfoSolver,
    ):
        """Init device session repo generator."""
        super().__init__(repo_generator, ssh_info_solver)
        self.device_inventories = device_inventories

    def generate(self):
        """Generate SSH session repo."""
        for device_inventory in self.device_inventories:
            self._generate_ssh_sessions_for_device_inventory(device_inventory)

        self.repo_generator.finish()

    def _generate_ssh_sessions_for_device_inventory(
        self, device_inventory: DeviceInventory
    ):
        """
        Generate SSH sessions for a device inventory.

        We use the following naming convention for SSH session path:

            devices/<InvName>/<DeviceType>/<DeviceHostname>

        Args:
            device_inventory (List[DeviceInventory]): Represents a device inventory.
        """
        print(
            "\nStart generating SSH session files for device inventory: {}".format(
                device_inventory.inv_name
            )
        )

        for device in device_inventory.devices.values():
            device_type = device_type_pattern.sub("-", device.device_type).lower()
            session_path = os.path.join(
                "devices", device_inventory.inv_name, device_type, device.hostname
            )
            self.generate_ssh_session_for_device(device, session_path)


def main(args):
    print(
        "Creating generator with config: Target = {}, Format = {}, Template = {}".format(
            args.target, args.format, args.template_file_path
        )
    )
    if args.format == "securecrt":
        repo_generator = SecureCRTSshSessionRepoGenerator(
            args.target, args.template_file_path
        )
    elif args.format == "ssh":
        ssh_config_params = {}
        for param in args.ssh_config_params:
            key, value = param.split("=")
            ssh_config_params[key] = value

        repo_generator = SshConfigSshSessionRepoGenerator(
            args.target, ssh_config_params
        )
    else:
        print("Unsupported output format: {}".format(args.format))
        return

    print(f"\nLoading device inventories: Files = {args.device_file_pattern}")
    device_inventories = DeviceInventory.from_device_files(args.device_file_pattern)

    print(
        f"\nLoading testbeds: TestBedFile = {args.testbed_file_path}, Pattern = {args.testbed_pattern}"
    )
    testbeds = TestBed.from_file(
        device_inventories, args.testbed_file_path, args.testbed_pattern
    )

    print(f"\nLoading ansible host inventory for getting SSH info: {args.inventory_file_paths}")
    ansible_hosts = HostManager(args.inventory_file_paths)

    ssh_info_solver = SSHInfoSolver(
        ansible_hosts,
        args.dut_user,
        args.dut_pass,
        args.server_user,
        args.server_pass,
        args.leaf_fanout_user,
        args.leaf_fanout_pass,
        args.root_fanout_user,
        args.root_fanout_pass,
        args.console_server_user,
        args.console_server_pass,
        args.ptf_user,
        args.ptf_pass,
    )

    if len(testbeds) == 0:
        print("No testbeds loaded. Skipped.")
    else:
        testbed_repo_generator = TestBedSshSessionRepoGenerator(
            testbeds, repo_generator, ssh_info_solver
        )
        testbed_repo_generator.generate()

    if len(device_inventories) == 0:
        print("No device inventories loaded. Skipped.")
    else:
        device_repo_generator = DeviceSessionRepoGenerator(
            device_inventories, repo_generator, ssh_info_solver
        )
        device_repo_generator.generate()


if __name__ == "__main__":
    # Parse arguments
    example_text = """Examples:
- python3 ssh_session_gen.py -i inventory -o /data/sessions/testbeds -p some_securecrt_session.ini
- python3 ssh_session_gen.py -i lab t2_lab -n vms-.* -o /data/sessions/testbeds --format ssh
- python3 ssh_session_gen.py -i your_own_inv -t your_own_testbed.yaml -n .*some_tests.* -o /data/sessions/testbeds \
    -p some_securecrt_session.ini

To generate the SSH session files for SecureCRT, we need to do a few things first:
1. Install pycryptodome package. We can do it via pip3: pip3 install pycryptodome.
2. Prepare an existing session file as template (passed by -p). Since our dev machine might not have direct access
   to your testbed machines, this allows us to inherit the session settings from the template file, such as SSH
   proxies, fonts and etc. This is te some_securecrt_session.ini file in the examples above.
3. Setup the `secrets.json` file under `ansible/group_vars/all`. This allows us to get the SSH credentials for the
   testbed nodes.

Please also note that, sonic-mgmt ansible playbook support multiple credentials for the same host. However, SecureCRT
only supports one credential, so we will use the first one in the list. If you see SSH login failures, please check
the `secrets.json` file and use the alternative credentials.
"""
    parser = argparse.ArgumentParser(
        description="Generate SSH session files for console access to devices.",
        epilog=example_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-d",
        "--device-file",
        type=str,
        dest="device_file_pattern",
        default="files/sonic_*_devices.csv",
        help="Device file path.",
    )

    parser.add_argument(
        "-t",
        "--testbed",
        type=str,
        dest="testbed_file_path",
        default="testbed.yaml",
        help="Testbed file path.",
    )

    parser.add_argument(
        "-n",
        "--testbed-name",
        type=str,
        dest="testbed_pattern",
        default=".*",
        help="Testbed name regex.",
    )

    parser.add_argument(
        "-i",
        "--inventory",
        dest="inventory_file_paths",
        nargs="+",
        help="Ansible host inventory file paths.",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        dest="target",
        required=True,
        help="Output target.",
    )

    parser.add_argument(
        "--format",
        type=str,
        dest="format",
        choices=["securecrt", "ssh"],
        default="securecrt",
        help="Output target format, currently supports securecrt or ssh.",
    )

    parser.add_argument(
        "--ssh-config-params",
        type=str,
        dest="ssh_config_params",
        nargs="+",
        default="",
        help="Extra SSH config parameters, only used when --format=ssh. E.g. ProxyJump=jumpbox",
    )

    parser.add_argument(
        "-p",
        "--template",
        type=str,
        dest="template_file_path",
        help="Session file template path. Used for clone your current session settings. "
        "Only used when --format=securecrt.",
    )

    parser.add_argument(
        "--dut-user",
        type=str,
        dest="dut_user",
        help="SSH user name of DUTs. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--dut-pass",
        type=str,
        dest="dut_pass",
        help="SSH password of DUTs. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--ptf-user",
        type=str,
        dest="ptf_user",
        help="SSH user name of PTF containers. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--ptf-pass",
        type=str,
        dest="ptf_pass",
        help="SSH password of PTF containers. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--server-user",
        type=str,
        dest="server_user",
        help="SSH user name of servers. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--server-pass",
        type=str,
        dest="server_pass",
        help="SSH password of servers. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--leaf-fanout-user",
        type=str,
        dest="leaf_fanout_user",
        help="SSH user name of leaf fanouts. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--leaf-fanout-pass",
        type=str,
        dest="leaf_fanout_pass",
        help="SSH password of leaf fanouts. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--root-fanout-user",
        type=str,
        dest="root_fanout_user",
        help="SSH user name of root fanouts. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--root-fanout-pass",
        type=str,
        dest="root_fanout_pass",
        help="SSH password of root fanouts. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--console-server-user",
        type=str,
        dest="console_server_user",
        help="SSH user name of console server. If not specified, we will use ansible to get the SSH configuration.",
    )

    parser.add_argument(
        "--console-server-pass",
        type=str,
        dest="console_server_pass",
        help="SSH password of console server. If not specified, we will use ansible to get the SSH configuration.",
    )

    args = parser.parse_args()

    main(args)
