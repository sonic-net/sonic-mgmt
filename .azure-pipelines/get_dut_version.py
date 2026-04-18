#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys

import yaml

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_localhost, init_testbed_sonichosts  # noqa: E402

logger = logging.getLogger(__name__)

RC_INIT_FAILED = 1
RC_GET_DUT_VERSION_FAILED = 2

ASIC_NAME_PATH = '../ansible/group_vars/sonic/variables'


def read_asic_name(hwsku):
    asic_name_file = os.path.join(os.path.dirname(__file__), ASIC_NAME_PATH)
    try:
        with open(asic_name_file) as f:
            asic_name = yaml.safe_load(f)

        asic_name_dict = {}
        for key, value in asic_name.items():
            if "hwskus" in key:
                asic_name_dict[key] = value

        for name, hw in asic_name_dict.items():
            if hwsku in hw:
                return name.split('_')[1]

        return "unknown"

    except IOError:
        return None


def get_duts_version(sonichosts, output=None):
    """
    Collect version information from DUTs via `show version`.

    For SmartSwitch testbeds, if a DPU host is unreachable, enables NAT on its
    NPU host and retries the command.

    Returns:
        dict: Parsed version info per DUT, structured with general fields and Docker images.
    """
    try:
        ret = {}
        duts_version = sonichosts.command("show version", module_ignore_errors=True)

        for dut, version in duts_version.items():
            # If a DPU host is unreachable, try enabling NAT and retry
            if version.get("unreachable") or (version.get("failed") and not version.get("stdout_lines")):
                if "dpu" in dut.lower():
                    version = _retry_dpu_with_nat(sonichosts, dut)
                if version is None:
                    logger.warning("Skipping unreachable or failed host: %s", dut)
                    continue

            dut_info = {}
            dut_version = version.get("stdout_lines", [])
            in_docker_section = False

            for line in dut_version:
                line = line.strip()
                if not line:
                    continue

                # ---- General info ----
                if not in_docker_section:
                    if line.startswith("Docker images"):
                        dut_info["Docker images"] = []
                        in_docker_section = True
                        continue

                    if ":" in line:
                        key, value = [x.strip() for x in line.split(":", 1)]
                        if key == "HwSKU":
                            dut_info["HwSKU"] = value
                            dut_info["ASIC"] = read_asic_name(value)
                        elif key == "ASIC":
                            dut_info["ASIC TYPE"] = value
                        else:
                            dut_info[key] = value
                    continue

                # ---- Docker images ----
                if line.startswith("REPOSITORY"):
                    continue  # skip header

                parts = line.split()
                if len(parts) < 4:
                    continue  # malformed line, skip

                image = {
                    "REPOSITORY": parts[0],
                    "TAG": parts[1],
                    "IMAGE ID": parts[2],
                    "SIZE": " ".join(parts[3:])  # safe join for "742 MB" / "683kB"
                }
                dut_info["Docker images"].append(image)

            ret[dut] = dut_info

        # ---- Output handling ----
        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(ret, f, indent=2)
        else:
            print(json.dumps(ret, indent=2))

        return ret
    except Exception as e:
        logger.error(f"Failed to get DUT version: {repr(e)}", exc_info=True)
        sys.exit(RC_GET_DUT_VERSION_FAILED)


def validate_args(args):
    _log_level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }
    logging.basicConfig(
        stream=sys.stdout,
        level=_log_level_map[args.log_level],
        format="%(asctime)s %(filename)s#%(lineno)d %(levelname)s - %(message)s"
    )


def _retry_dpu_with_nat(sonichosts, dpu_hostname):
    """Enable NAT for a single DPU host and retry 'show version'.

    Returns the retried command result dict on success, or None.
    """
    try:
        from devutil.devices.dpu_utils import enable_nat_for_dpuhosts
    except ImportError:
        logger.warning("dpu_utils not available, skipping NAT enablement for %s", dpu_hostname)
        return None

    npu_hosts = [h for h in sonichosts if "dpu" not in h.hostname.lower()]
    try:
        logger.info("Enabling NAT for DPU host: %s", dpu_hostname)
        enable_nat_for_dpuhosts(npu_hosts, sonichosts.inventories, [dpu_hostname])

        # Retry the command on the now-reachable DPU
        retry_result = sonichosts.command("show version", module_ignore_errors=True)
        version = retry_result.get(dpu_hostname)
        if version and not version.get("unreachable") and version.get("stdout_lines"):
            return version
        logger.warning("DPU host %s still unreachable after enabling NAT", dpu_hostname)
    except Exception as e:
        logger.warning("Failed to enable NAT for %s: %s", dpu_hostname, repr(e))

    return None


def main(args):
    logger.info("Validating arguments")
    validate_args(args)

    logger.info("Initializing hosts")
    localhost = init_localhost(args.inventory, options={"verbosity": args.verbosity})
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile, options={"verbosity": args.verbosity}
    )

    if not localhost or not sonichosts:
        sys.exit(RC_INIT_FAILED)

    get_duts_version(sonichosts, args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for getting sonic device version.")

    parser.add_argument(
        "-i", "--inventory",
        dest="inventory",
        nargs="+",
        help="Ansible inventory file")

    parser.add_argument(
        "-t", "--testbed-name",
        type=str,
        required=True,
        dest="testbed_name",
        help="Testbed name."
    )

    parser.add_argument(
        "--tbfile",
        type=str,
        dest="tbfile",
        default="testbed.yaml",
        help="Testbed definition file."
    )

    parser.add_argument(
        "-v", "--verbosity",
        type=int,
        dest="verbosity",
        default=2,
        help="Log verbosity (0-3)."
    )

    parser.add_argument(
        "--log-level",
        type=str,
        dest="log_level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="debug",
        help="Loglevel"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        dest="output",
        required=False,
        help="Output duts version to the specified file."
    )

    args = parser.parse_args()
    main(args)
