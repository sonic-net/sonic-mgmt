"""
Script used to generate SSH session files for console access to devices.
"""

import argparse
import os
from devutil.testbed import TestBed
from devutil.inv_helpers import HostManager
from devutil.ssh_session_repo import SecureCRTSshSessionRepoGenerator, SshConfigSshSessionRepoGenerator


class TestBedSshSessionRepoGenerator(object):
    """SSH session repo generator for testbeds."""

    def __init__(self, testbeds, repo_generator):
        """Store all parameters as attributes.

        Args:
            testbeds (dict): Testbed name to testbed object mapping.
            repo_generator (SshSessionRepoGenerator): SSH session repo generator.
        """
        self.testbeds = testbeds
        self.repo_generator = repo_generator

    def generate(self):
        """Generate SSH session repo."""
        for testbed in self.testbeds.values():
            self._generate_ssh_sessions_for_testbed(testbed)

        self.repo_generator.finish()

    def _generate_ssh_sessions_for_testbed(self, testbed):
        """Generate SSH sessions for a testbed.

        Args:
            testbed (object): Represents a testbed setup.
        """
        print("Start generating SSH sessions for testbed: {}".format(testbed.conf_name))

        testbed_nodes = [["ptf", testbed.ptf_node]] + [
            ["dut", item] for item in testbed.dut_nodes.values()
        ]
        for testbed_node in testbed_nodes:
            self._generate_ssh_session_for_testbed_node(
                testbed, testbed_node[0], testbed_node[1]
            )

        print(
            "Finish generating SSH session files for testbed: {}\n".format(
                testbed.conf_name
            )
        )

    def _generate_ssh_session_for_testbed_node(
        self, testbed, testbed_node_type, testbed_node
    ):
        """Generate SSH session for a testbed node.

        We use the following naming convention for SSH session path:
            <InvName>/<TestbedName>/<NodeType>-<NodeName>

        Args:
            testbed (object): Represents a testbed setup.
            testbed_node_type (str): Type of the testbed node. It can be "ptf" or "dut".
            testbed_node (object): Represents a connectable node in the testbed.
        """
        if testbed_node.ssh_ip is None:
            print(
                """Skip generating SSH session for testbed node: Testbed = {}, Type = {}, Node = {}
                (SSH IP is not specified)""".format(
                    testbed.conf_name, testbed_node_type, testbed_node.name
                )
            )
            return

        print(
            "Start generating SSH session for testbed node: Testbed = {}, Type = {}, Node = {}".format(
                testbed.conf_name, testbed_node_type, testbed_node.name
            )
        )

        if testbed_node.ssh_user == '':
            print("WARNING: SSH user is empty for testbed node: {}".format(testbed_node.name))

        session_path = os.path.join(
            testbed.inv_name,
            testbed.conf_name,
            testbed_node_type + "-" + testbed_node.name,
        )
        self.repo_generator.generate(
            session_path,
            testbed_node.ssh_ip,
            testbed_node.ssh_user,
            testbed_node.ssh_pass,
        )


def main(args):
    print("Loading ansible host inventory: {}\n".format(args.inventory_file_paths))
    ansible_hosts = HostManager(args.inventory_file_paths)

    print(
        "Loading testbed config: TestBedFile = {}, Pattern = {}".format(
            args.testbed_file_path, args.testbed_pattern
        )
    )
    testbeds = TestBed.from_file(
        args.testbed_file_path, args.testbed_pattern, ansible_hosts
    )
    if len(testbeds) == 0:
        print("No testbeds loaded. Exit.")
        return
    else:
        print("{} testbeds loaded.\n".format(len(testbeds)))

    print(
        "Starting SSH session repo generation with config: Target = {}, Format = {}, Template = {}".format(
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

    testbed_repo_generator = TestBedSshSessionRepoGenerator(testbeds, repo_generator)
    testbed_repo_generator.generate()


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
        formatter_class=argparse.RawDescriptionHelpFormatter)

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

    args = parser.parse_args()

    main(args)
