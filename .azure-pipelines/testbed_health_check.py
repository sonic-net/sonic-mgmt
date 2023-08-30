#!/usr/bin/env python3

"""Script for checking testbed health.

    Example:
        ./testbed_health_check.py -t vms01 -i ../ansible/str --tbfile ../ansible/testbed.yaml
        -o testbed_health_check_result_vms01 --log-level info

    It will print the basic testbed health check result to the console,
    if you specify an output file, it will write to it as well.
"""
import argparse
import logging
import os
import sys
import json

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_localhost, init_testbed_sonichosts  # noqa E402

logger = logging.getLogger(__name__)


class ElastictestCommonResponse:
    def __init__(self, code: int, data: object, errmsg: str):
        self.code = code
        self.data = data
        self.errmsg = errmsg


class TestbedCheckResult(ElastictestCommonResponse):
    pass


def check_bgp_session_state(sonichosts, state="established"):
    """
    Check if the current BGP session state equals the target state.
    Args:
        sonichosts (list): List of SonicHost objects representing the hosts to check.
        state (str, optional): The target state to compare the BGP session state against. Defaults to "established".
    Returns:
        tuple: A tuple containing the following:
            - bool: True if all BGP sessions are in the target state, False otherwise.
            - dict or None: The BGP facts dictionary if there are sessions not in the target state, None otherwise.
            - str or None: An error log message if there are sessions not in the target state, None otherwise.
    """

    bgp_facts = sonichosts[0].bgp_facts()['ansible_facts']

    print(json.dumps(bgp_facts, indent=4))

    neigh_not_ok = []
    for k, v in list(bgp_facts['bgp_neighbors'].items()):
        if v['state'] != state:
            neigh_not_ok.append(f"{k}, {v['state']}")

    errlog = "bgp neighbors that not established: {}".format(neigh_not_ok)

    print(errlog)

    if len(neigh_not_ok) > 0:
        return False, bgp_facts, errlog

    return True, None, None


def check(sonichosts, output=None):
    """
    Perform essential health checks on the given SONiC hosts.
    Args:
        sonichosts (list): List of SONiC hosts to check.
        output (str, optional): Path to the output file where the checking results will be written. Defaults to None.
    Raises:
        Exception: If an error occurs during the checking process.
    """
    try:
        # Define variable to record result
        code = 0
        data = None
        errmsg = ""

        # Testbed health check
        # todo: currently, simply check bgp session state
        bgp_session_state, bgp_facts, errlog = check_bgp_session_state(sonichosts)

        # If testbed is unhealthy
        if not bgp_session_state:
            code = 1
            data = bgp_facts
            errmsg = errlog
            logger.info("Testbed is unhealthy. {}".format(errmsg))
        else:
            logger.info("Testbed is healthy.")

        testbedCheckResult = TestbedCheckResult(code=code, data=data, errmsg=errmsg)

        # If output file is specified, write result to it.
        if output:
            with open(output, "w") as f:
                f.write(json.dumps(testbedCheckResult.__dict__, separators=(",", ":")))
                f.close()

    except Exception as e:
        logger.error("Failed to check. {}".format(e))
        sys.exit(1)


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


def main(args):
    logger.info("Validating arguments")
    validate_args(args)

    logger.info("Initializing hosts")
    localhost = init_localhost(args.inventory, options={"verbosity": args.verbosity})
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile, options={"verbosity": args.verbosity}
    )

    if not localhost or not sonichosts:
        sys.exit(1)

    logger.info("Checking")
    check(sonichosts, args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for checking testbed health.")

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
        help="Output to the specified file."
    )

    args = parser.parse_args()
    main(args)
