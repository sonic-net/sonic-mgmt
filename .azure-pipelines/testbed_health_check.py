#!/usr/bin/env python3

"""Script for checking testbed health.

    Example:
        ./testbed_health_check.py -t vms01 -i ../ansible/str --tbfile ../ansible/testbed.yaml
        -o testbed_health_check_result_vms01 --log-level info

    It will log the basic testbed health check result to the console,
    if you specify an output file, it will write to it as well.
"""
import argparse
import logging
import os
import sys
import json
from datetime import datetime

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_localhost, init_testbed_sonichosts  # noqa E402
from devutil.devices.ansible_hosts import HostsUnreachable, RunAnsibleModuleFailed  # noqa E402

logger = logging.getLogger(__name__)


def get_timestamp_utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


class ElastictestCommonResponse:
    def __init__(self, code: int, timestamp: str = get_timestamp_utcnow(), errmsg: list = None, data: object = None):
        """
        Initialize an instance of the ElastictestCommonResponse class.

        Args:
            code: int. The return code. '0' indicates success, while any other value indicates failure.
            timestamp: str. The timestamp when this response object was generated. Default is utcnow().
            errmsg: list. A list of error messages if the check failed.
            data: object. The check result.
        """
        self.code = code
        self.timestamp = timestamp
        self.errmsg = errmsg
        self.data = data


class TestbedCheckResult(ElastictestCommonResponse):
    pass


class TestbedConditionalCheckFailed(Exception):
    pass


class TestbedUnhealthy(Exception):
    pass


class TestbedHealthCheck:
    """
    Testbed health check class
    """

    def __init__(self, sonichosts, output_file: str = None):
        """
        Initialize an instance of the TestbedHealthCheck class.

        Args:
            sonichosts (list): A list of Sonic hosts to perform health checks on.
            output_file (str, optional): The output file to store the health check results. Defaults to None.
        """
        self.sonichosts = sonichosts
        self.check_result = TestbedCheckResult(code=0, errmsg=[], data={})
        self.output_file = output_file

    def run_check(self):
        try:

            self.conditional_check()

            # Check if critical containers are running
            self.check_critical_containers_running()

            # Check bgp sessions
            self.check_bgp_session_state()

            # Check interfaces status
            self.check_interface_status_of_up_ports()

            logger.info("Check finished. Testbed is healthy.")

        except TestbedConditionalCheckFailed as e:
            # catch exception: TestbedConditionalCheckFailed
            logger.info("Testbed conditional check failed, skip check current testbed health: {}".format(e))
            # Currently, if the testbed conditional check fails, skip it and consider it healthy.
            self.check_result.code = 0
            self.check_result.data = str(e)

        except TestbedUnhealthy as e:
            # catch exception: TestbedUnhealthy
            self.check_result.code = 1
            logger.info("Check finished. Testbed is unhealthy: {}".format(e))

        except HostsUnreachable as e:
            # catch exception: HostsUnreachable
            logger.info("Host unreachable: {}".format(e))
            self.check_result.code = 2
            self.check_result.errmsg = ["Host unreachable."]
            self.check_result.data = str(e)

        except RunAnsibleModuleFailed as e:
            # catch exception: RunAnsibleModuleFailed
            logger.info("Run ansible module failed: {}".format(e))
            self.check_result.code = 3
            self.check_result.errmsg = ["Run ansible module failed."]
            self.check_result.data = str(e)

        except Exception as e:
            # catch other exceptions
            logger.info("An error occurred: {}".format(e))
            self.check_result.code = 4
            self.check_result.errmsg = ["An error occurred."]
            self.check_result.data = str(e)

        finally:
            # If output file is specified, write result to it.
            if self.output_file:
                with open(self.output_file, "w") as f:
                    f.write(json.dumps(self.check_result.__dict__, separators=(",", ":")))

    def conditional_check(self):
        """
        Perform conditional check before checking testbeds health.
        Currently, if failed, regard it as healthy and skip.
        """

        logger.info("======================= conditional_check starts =======================")

        failed = False
        errmsg = ""

        # Retrieve the basic facts of the DUTs
        duts_basic_facts = self.sonichosts.dut_basic_facts()

        for dut_name, single_dut_basic_facts in duts_basic_facts.items():

            # Get the basic facts of one DUT
            dut_basic_facts = single_dut_basic_facts["ansible_facts"]["dut_basic_facts"]

            # todo: Skip multi_asic check on multi_asic dut now because currently not support get asic object
            if dut_basic_facts["is_multi_asic"]:
                errmsg = "Not support to perform checks on multi-asic DUT now."
                logger.info(errmsg)
                failed = True
                break

        logger.info("======================= conditional_check ends =======================")

        if failed:
            raise TestbedConditionalCheckFailed(errmsg)

    def check_bgp_session_state(self, state="established"):
        """
        Check if the current BGP session state equals the target state.

        Args:
            state: str. The target state to compare the BGP session state against. Defaults to "established".
        """

        failed = False
        bgp_facts_on_hosts = {}

        logger.info("======================= check_bgp_session_state starts =======================")

        for sonichost in self.sonichosts:

            hostname = sonichost.hostname

            logger.info("----------------------- check_bgp_session_state on [{}] -----------------------".format(
                hostname))

            # Retrieve BGP facts for the Sonic host
            bgp_facts = sonichost.bgp_facts()['ansible_facts']

            bgp_facts_on_hosts[hostname] = bgp_facts

            # Check BGP session state for each neighbor
            neigh_not_ok = []
            for k, v in list(bgp_facts['bgp_neighbors'].items()):
                if v['state'] != state:
                    neigh_not_ok.append(f"{k}, {v['state']}")

            errlog = "BGP neighbors that not established on {}: {}".format(hostname, neigh_not_ok)

            logger.info(errlog)

            if len(neigh_not_ok) > 0:
                # Set failed to True if any BGP neighbors are not established
                failed = True
                # Add errlog to check result errmsg
                self.check_result.errmsg.append(errlog)

        # Set the check result
        self.check_result.data["bgp_facts_on_hosts"] = bgp_facts_on_hosts

        logger.info("======================= check_bgp_session_state ends =======================")

        if failed:
            raise TestbedUnhealthy(self.check_result.errmsg)

    def check_interface_status_of_up_ports(self):
        """
        Check the status of up ports on a list of SonicHost objects representing the DUTs.
        """

        failed = False
        interface_facts_on_hosts = {}

        logger.info("======================= check_interface_status_of_up_ports starts =======================")

        for sonichost in self.sonichosts:

            hostname = sonichost.hostname
            logger.info(
                "----------------------- check_interface_status_of_up_ports on [{}] -----------------------".format(
                    hostname))

            # Retrieve the configuration facts for the DUT
            cfg_facts = sonichost.config_facts(host=hostname, source='running')['ansible_facts']

            # Get a list of up ports from the configuration facts
            up_ports = [p for p, v in list(cfg_facts['PORT'].items()) if v.get('admin_status', None) == 'up']

            logger.info('up_ports: {}'.format(up_ports))

            # Retrieve the interface facts for the up ports
            interface_facts = sonichost.interface_facts(up_ports=up_ports)['ansible_facts']

            interface_facts_on_hosts[hostname] = interface_facts

            errlog = 'ansible_interface_link_down_ports on {}: {}'.format(
                hostname, interface_facts['ansible_interface_link_down_ports'])

            logger.info(errlog)

            # Check if there are any link down ports in the interface facts
            if len(interface_facts['ansible_interface_link_down_ports']) > 0:
                # Set failed to True if any BGP neighbors are not established
                failed = True
                # Add errlog to check result errmsg
                self.check_result.errmsg.append(errlog)

        # Set the check result
        self.check_result.data["interface_facts_on_hosts"] = interface_facts_on_hosts

        logger.info("======================= check_interface_status_of_up_ports ends =======================")

        if failed:
            raise TestbedUnhealthy(self.check_result.errmsg)

    def check_critical_containers_running(self, critical_containers: list = None):
        """
        Check if critical containers are running on a list of SonicHost objects representing the DUTs.

        Args:
            critical_containers: list. A list of critical container names to check. Default is None.
        """

        # Set default critical containers to check
        if not critical_containers:
            critical_containers = ["syncd", "swss", "bgp"]

        failed = False

        logger.info("======================= check_critical_containers_running starts =======================")

        for sonichost in self.sonichosts:

            hostname = sonichost.hostname
            logger.info(
                "----------------------- check_critical_containers_running on [{}] -----------------------".format(
                    hostname))

            # Get the list of running containers on the host
            running_containers = sonichost.shell(r"docker ps -f 'status=running' --format \{\{.Names\}\}")[
                'stdout_lines']

            for critical_container in critical_containers:

                # If the critical container is not running, add an error log
                if critical_container not in running_containers:
                    # Set failed to True if any critical containers not running
                    failed = True
                    # Log the error
                    errlog = "{} is not running on {}.".format(critical_container, hostname)
                    logger.info(errlog)
                    # Add errlog to check result errmsg
                    self.check_result.errmsg.append(errlog)

        logger.info("======================= check_critical_containers_running ends =======================")

        if failed:
            raise TestbedUnhealthy(self.check_result.errmsg)


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
    testbedHealthCheck_instance = TestbedHealthCheck(sonichosts=sonichosts, output_file=args.output)
    testbedHealthCheck_instance.run_check()


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
