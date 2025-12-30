#!/usr/bin/env python3
from collections import defaultdict
import json
import re
from types import SimpleNamespace
from typing import List, Tuple
import argparse
import os
import sys
import logging
import traceback

logging.basicConfig(level=logging.INFO,  format="[%(levelname)s] (SONiC L1 CLI) %(asctime)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.sonic import SonicHosts  # noqa: E402

PORT_DIVIDER = "|"
A_SIDE = "A"
B_SIDE = "B"


class L1Device(SonicHosts):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = self.hostnames[0]

    def connect(self, ports: List[Tuple[str, str]]):
        for from_port, to_port in ports:
            combinations = self._generate_l1_combination(from_port, to_port)
            for combine in combinations:
                logger.info(f"{self.name} connecting port: {combine}")
                output = self.command(f"config ocs cross-connect add {combine} update", module_attrs={
                    "become": True
                })

                if not any("cross-connect succeeded" in line
                           for line in output.get(self.name, {}).get("stdout_lines", [])):
                    logger.error(
                        f"Device {self.name} port mapping failed for port {combine}, output: {output}"
                    )
                    raise RuntimeError(
                        f"Device {self.name} port mapping failed for port {combine}, output: {output}"
                    )
                else:
                    logger.info(f"(Success) Device {self.name} successfully connected port: {combine}")

    def read(self, output_file):
        output = self.command("show ocs cross-connect config")

        result = output.get(self.name, {})

        if result.get("failed", True):
            logger.error(f"Device {self.name} cannot get current port mapping")
            raise RuntimeError(f"Device {self.name} cannot get current port mapping")

        port_map = defaultdict(lambda: defaultdict(
            lambda: SimpleNamespace(A=False, B=False)
        ))

        for i in range(2, len(result["stdout_lines"])):
            # Skip the first 2 header row
            row = result["stdout_lines"][i]
            _, from_port, to_port = row.split()

            from_match = re.match(r"(\d+)([A-Ba-b])", from_port)
            to_match = re.match(r"(\d+)([A-Ba-b])", to_port)

            if not from_match or not to_match:
                raise RuntimeError(f"Device {self.name} has invalid port without A|B side: {from_port} {to_port}")

            from_port, from_side = from_match.groups()
            to_port, to_side = to_match.groups()

            combination = ",".join(sorted([from_port, to_port]))

            if from_side.lower() == A_SIDE.lower():
                port_map[combination][from_port].A = True
            if from_side.lower() == B_SIDE.lower():
                port_map[combination][from_port].B = True

            if to_side.lower() == A_SIDE.lower():
                port_map[combination][to_port].A = True
            if to_side.lower() == B_SIDE.lower():
                port_map[combination][to_port].B = True

        result = {
            "port_list": list(filter(
                lambda combination: all([setup.A and setup.B for setup in port_map[combination].values()]),
                port_map.keys()))
        }

        result_json = json.dumps(result, indent=4)

        logger.info(f"(Success) Device {self.name} get port successfully, result: {result_json}")

        if output_file:
            with open(output_file, "w") as f:
                f.write(result_json)
                logger.info(f"Written result to file {output_file}")

        return result

    def _generate_l1_combination(self, from_port: str, to_port: str):
        if PORT_DIVIDER in from_port and PORT_DIVIDER in to_port:
            # Combine each of sub port in from_port to to_port
            from_subports = from_port.split(PORT_DIVIDER)
            to_subports = to_port.split(PORT_DIVIDER)

            if len(from_subports) != len(to_subports):
                raise RuntimeError(
                    f"The 2 combined ports is not equivalent in number of subports: {from_port} {to_port}"
                )

            combinations = []
            for from_subport, to_support in zip(from_subports, to_subports):
                combinations.append(f"{from_subport}A-{to_support}B")
                combinations.append(f"{to_support}A-{from_subport}B")

            return combinations

        if PORT_DIVIDER in from_port or PORT_DIVIDER in to_port:
            raise RuntimeError(f"Does not support to map combined port with normal port: {from_port} {to_port}")

        # Normal case
        return [f"{from_port}A-{to_port}B", f"{to_port}A-{from_port}B"]


def show_help_message():
    return """
Usecases:

1. Connect port
../.azure-pipelines/sonic_l1_cli.py connect --device l1_device --port "1,41" -i inventory

This will do the following connection:
    Connect single port
        1A -> 41B
        41A -> 1B

2. Connect port in a combined port group
../.azure-pipelines/sonic_l1_cli.py connect --device l1_device --port "1|2|3|4,41|42|43|44" -i inventory

This will do the following connection:
    Connect port group:
        1A -> 41B
        41A -> 1B
        ...
        4A -> 44B
        44A -> 4B

3. Connect multiple port
../.azure-pipelines/sonic_l1_cli.py connect --device l1_device --port "1,41" --port "2,42" -i inventory

This will do the following connection:
    Connect single port
        1A -> 41B
        41A -> 1B

        2A -> 42B
        42A -> 2B

4. Read the port connection
../.azure-pipelines/sonic_l1_cli.py read --output output_file --device l1_device -i inventory

This will write to output_file
{
    "port_list": [
        "1,43",
        "2,46",
        "17,45",
        "19,47",
        "20,48",
        "21,49",
        "22,50",
        "23,51",
        "24,52"
    ]
}

If you dont want to output to any file, simply omit --output

"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        # formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Sonic-mgmt utility command-line to connect ports and read ports from SONiC L1 device.",
        epilog=show_help_message())

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_options(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--device", required=True, help="Device name.")
        subparser.add_argument(
            "-i", "--inventory",
            dest="inventory",
            nargs="+",
            required=True,
            help="Ansible inventory file")

    connect_parser = subparsers.add_parser("connect", help="Connect to device.")
    add_common_options(connect_parser)
    connect_parser.add_argument(
        "--port",
        dest="raw_ports",
        action="append",
        required=True,
        metavar="FROM_PORT,TO_PORT",
        help="Comma-separated port pair; repeat for multiple ports.",
    )

    read_parser = subparsers.add_parser("read", help="Read from device.")
    read_parser.add_argument("--output", help="(Optional) output file to store read result")
    add_common_options(read_parser)

    args = parser.parse_args()
    if hasattr(args, "raw_ports"):
        args.ports = [(*group.replace(" ", "").split(","),) for group in args.raw_ports]
        delattr(args, "raw_ports")
    else:
        args.ports = []

    logger.info(f"{args.command}: device={args.device}, ports={args.ports}, inventory={args.inventory}")

    l1_device = L1Device(
        inventories=args.inventory,
        host_pattern=args.device
    )

    try:
        # Step 1. Check if connection is good. If not ansible_hosts will throw Exception
        l1_device.ping()

        # Step 2. Perform relative command
        if args.command == "connect":
            l1_device.connect(args.ports)
        elif args.command == "read":
            l1_device.read(args.output)
        else:
            raise ValueError(f"Command '{args.command}' is not a valid command")
    except Exception as e:
        traceback.print_exception(type(e), e, e.__traceback__, file=sys.stderr)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
