#!/usr/bin/env python3

"""Script for bringing up all BGP sessions on DUT hosts in a testbed.

Intended to be called as a soft recovery step by the Elastictest management
service when BGP neighbors are detected in Idle (Admin) state, before
escalating to a full remove-topo operation.

"""
import argparse
import logging
import os
import sys
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_sonichosts  # noqa: E402

logger = logging.getLogger(__name__)


def get_testbed_dut_names(testbed_file, testbed_name):
    try:
        with open(testbed_file) as f:
            testbeds = yaml.safe_load(f.read())
        for testbed in testbeds:
            if testbed["conf-name"] == testbed_name:
                return testbed.get("dut", [])
    except Exception as e:
        logger.error("Failed to read testbed file {}: {}".format(testbed_file, repr(e)))
    return []


def setup_logging(args):
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


def _startup_one_host(sonichost):
    try:
        logger.info("Running 'sudo config bgp startup all' on {}".format(sonichost.hostname))
        sonichost.shell("sudo config bgp startup all")
        logger.info("BGP startup completed on {}.".format(sonichost.hostname))
        logger.info("Running 'sudo config save -y' on {}".format(sonichost.hostname))
        sonichost.shell("sudo config save -y")
        logger.info("Config saved on {}.".format(sonichost.hostname))
    except Exception as e:
        logger.error("Failed on {}: {}".format(sonichost.hostname, repr(e)))
        return False
    return True


def main(args):
    logger.info("Setting up logging")
    setup_logging(args)

    testbed_file = os.path.realpath(os.path.join(ansible_path, args.tbfile))

    dut_names = get_testbed_dut_names(testbed_file, args.testbed_name)
    if not dut_names:
        logger.error("No DUTs found for testbed '{}' in '{}'.".format(args.testbed_name, testbed_file))
        sys.exit(1)

    # DPU hosts do not run BGP independently
    npu_names = [name for name in dut_names if "dpu" not in name.lower()]
    if not npu_names:
        logger.error("No NPU hosts found for testbed '{}'.".format(args.testbed_name))
        sys.exit(1)

    logger.info("Initializing hosts: {}".format(npu_names))
    sonichosts = init_sonichosts(args.inventory, npu_names, options={"verbosity": args.verbosity})
    if not sonichosts:
        logger.error("Failed to initialize hosts: {}".format(npu_names))
        sys.exit(1)

    failed = False
    with ThreadPoolExecutor(max_workers=len(list(sonichosts))) as executor:
        futures = [
            executor.submit(_startup_one_host, sonichost)
            for sonichost in sonichosts
        ]
        for future in as_completed(futures):
            if not future.result():
                failed = True

    if failed:
        sys.exit(1)

    logger.info("BGP startup and config save completed on all hosts.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Bring up all BGP sessions on DUT hosts in a testbed.")

    parser.add_argument(
        "-i", "--inventory",
        dest="inventory",
        nargs="+",
        help="Ansible inventory file"
    )

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
        help="Log level."
    )

    args = parser.parse_args()
    main(args)
