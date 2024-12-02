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
from netaddr import valid_ipv4

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_host, init_localhost, init_testbed_sonichosts  # noqa E402
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


class SkipCurrentTestbed(Exception):
    pass


class TestbedUnhealthy(Exception):
    pass


class HostInitFailed(Exception):
    pass


class TestbedHealthChecker:
    """
    Testbed health check class
    """

    def __init__(self, inventory, testbed_name, testbed_file, log_verbosity, output_file: str = None):
        """

        Args:
            inventory: (str). inventory.
            testbed_name: (str). testbed name.
            testbed_file: (str). testbed file.
            log_verbosity: (str). log verbosity.
            output_file: (str, optional). The output file to store the health check results. Defaults to None.
        """

        self.localhost = None
        self.sonichosts = None
        self.duts_basic_facts = None
        self.is_multi_asic = False

        self.inventory = inventory
        self.testbed_name = testbed_name
        self.testbed_file = testbed_file
        self.log_verbosity = log_verbosity
        self.output_file = output_file

        self.check_result = TestbedCheckResult(code=0, errmsg=[], data={})

    def init_hosts(self):

        logger.info("======================= init_hosts starts =======================")

        # Init localhost
        self.localhost = init_localhost(self.inventory, options={"verbosity": self.log_verbosity})
        if not self.localhost:
            raise HostInitFailed("localhost is None. Please check inventory.")

        self.sonichosts = init_testbed_sonichosts(
            self.inventory, self.testbed_name, testbed_file=self.testbed_file,
            options={"verbosity": self.log_verbosity}
        )
        if not self.sonichosts:
            raise HostInitFailed("sonichosts is None. Please check testbed name/file/inventory.")

        self.duts_basic_facts = self.sonichosts.dut_basic_facts()
        self.is_multi_asic = self.duts_basic_facts[self.sonichosts[0].hostname][
            "ansible_facts"]["dut_basic_facts"]["is_multi_asic"]

        logger.info("======================= init_hosts ends =======================")

    def pre_check(self):
        """
            Perform essential pre-check before checking testbeds health.
        """

        logger.info("======================= pre_check starts =======================")

        # Retrieve the connection graph facts of localhost
        conn_graph_facts = self.localhost.conn_graph_facts(hosts=self.sonichosts.hostnames,
                                                           filepath=os.path.join(ansible_path, "files"))

        # Check hosts reachability
        hosts_reachable = True

        for sonichost in self.sonichosts:

            # Check sonichost reachability
            is_reachable, result = sonichost.reachable()
            logger.info(result)

            if not is_reachable:
                hosts_reachable = False
                logger.info("sonichost {} is unreachable.".format(sonichost.hostname))
                self.check_result.errmsg.append("sonichost {} is unreachable.".format(sonichost.hostname))
                self.check_result.data[sonichost.hostname] = result

            dut_device_conn = conn_graph_facts["ansible_facts"]["device_conn"][sonichost.hostname]

            peer_devices = [dut_device_conn[port]["peerdevice"] for port in dut_device_conn]
            peer_devices = list(set(peer_devices))

            for fanout_hostname in peer_devices:
                # Check fanouthost reachability

                # Create fanouthost instance.
                fanouthost = init_host(inventories=self.inventory, host_pattern=fanout_hostname)

                # If sonic fannout, update ssh vars
                is_sonic = self.localhost.get_host_vars(fanout_hostname).get("os", "eos") == "sonic"

                if is_sonic:
                    # Use fanouthost to read the variables.
                    fanout_sonic_user = fanouthost.get_host_visible_var(fanouthost.hostname, "fanout_sonic_user")
                    fanout_sonic_password = fanouthost.get_host_visible_var(fanouthost.hostname,
                                                                            "fanout_sonic_password")
                    fanouthost.vm.extra_vars.update(
                        {"ansible_ssh_user": fanout_sonic_user, "ansible_ssh_password": fanout_sonic_password})

                is_reachable, result = fanouthost.reachable()

                logger.info(result)

                if not is_reachable:
                    hosts_reachable = False
                    logger.info("fanouthost {} is unreachable.".format(fanout_hostname))
                    self.check_result.errmsg.append("fanouthost {} is unreachable.".format(fanout_hostname))
                    self.check_result.data[fanout_hostname] = result

        if not hosts_reachable:
            raise HostsUnreachable(self.check_result.errmsg)

        # Verify mgmt-ipv4 address exists
        config_db_file = "/etc/sonic/config_db.json"
        ipv4_not_exists_hosts = []

        for sonichost in self.sonichosts:

            rst = sonichost.shell(f"jq '.MGMT_INTERFACE' {config_db_file}", module_ignore_errors=True).get("stdout",
                                                                                                           None)

            # If valid stdout
            if rst is not None and rst.strip() != "":

                mgmt_interface = json.loads(rst)

                ipv4_exists = False

                # Use list() to make a copy of mgmt_interface.keys() to avoid
                for key in list(mgmt_interface):
                    ip_addr = key.split("|")[1]
                    ip_addr_without_mask = ip_addr.split('/')[0]
                    if ip_addr:
                        is_ipv4 = valid_ipv4(ip_addr_without_mask)
                        if is_ipv4:
                            ipv4_exists = True
                            break

                if not ipv4_exists:
                    ipv4_not_exists_hosts.append(sonichost.hostname)
                    logger.info("{} does not have mgmt-ipv4 address.".format(sonichost.hostname))
                    self.check_result.errmsg.append("{} does not have mgmt-ipv4 address.".format(sonichost.hostname))

        if len(ipv4_not_exists_hosts) > 0:
            raise HostsUnreachable(self.check_result.errmsg)

        # TODO: Refactor the following code to specify a "leader" T2 Testbed and skip the check on "followers"
        # Retrieve the basic facts of the DUTs
        duts_basic_facts = self.sonichosts.dut_basic_facts()

        for dut_name, single_dut_basic_facts in duts_basic_facts.items():

            # Get the basic facts of one DUT
            dut_basic_facts = single_dut_basic_facts["ansible_facts"]["dut_basic_facts"]

            # todo: Skip multi_asic check on multi_asic dut now because currently not support get asic object
            if dut_basic_facts["is_multi_asic"]:
                errmsg = "Not support to perform checks on multi-asic DUT now."
                logger.info(errmsg)

                raise SkipCurrentTestbed(errmsg)

        logger.info("======================= pre_check ends =======================")

    def run_check(self):
        try:

            self.init_hosts()

            self.pre_check()

            # Check if critical containers are running
            self.check_critical_containers_running()

            # Check bgp sessions
            self.check_bgp_session_state()

            # Check interfaces status
            self.check_interface_status_of_up_ports()

            logger.info("Check finished. Testbed is healthy.")

        except HostInitFailed as e:
            logger.info("Init hosts failed: {}".format(e))
            self.check_result.code = -1
            self.check_result.errmsg = ["Init hosts failed."]
            self.check_result.data = str(e)

        except SkipCurrentTestbed as e:
            # catch exception: SkipCurrentTestbed
            logger.info("Skip check current testbed health: {}".format(e))
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
            if not self.check_result.errmsg:
                self.check_result.errmsg = ["Host unreachable"]
            if not self.check_result.data:
                self.check_result.data = str(e)

        except RunAnsibleModuleFailed as e:
            # catch exception: RunAnsibleModuleFailed
            logger.info("Run ansible module failed: {}".format(e))
            self.check_result.code = 3
            self.check_result.errmsg = ["Run ansible module failed."]
            self.check_result.data = str(e)

        except Exception as e:
            # catch other exceptions
            logger.info(repr(e))
            self.check_result.code = 4
            self.check_result.errmsg = [repr(e)]
            self.check_result.data = None

        finally:
            # If output file is specified, write result to it.
            if self.output_file:
                with open(self.output_file, "w") as f:
                    f.write(json.dumps(self.check_result.__dict__, separators=(",", ":")))

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
            if (self.is_multi_asic and
                    self.duts_basic_facts[sonichost.hostname]["ansible_facts"]["dut_basic_facts"]["is_supervisor"]):
                logger.info("Skip check_bgp_session_state on Supervisor.")
                continue

            hostname = sonichost.hostname

            logger.info("----------------------- check_bgp_session_state on [{}] -----------------------".format(
                hostname))

            # Retrieve BGP facts for the Sonic host
            if self.is_multi_asic:
                bgp_facts = {}
                host_asics_list = self.duts_basic_facts[sonichost.hostname][
                    "ansible_facts"]["dut_basic_facts"]["asic_presence_list"]

                for instance_id in host_asics_list:
                    bgp_facts[instance_id] = sonichost.bgp_facts(instance_id=instance_id)['ansible_facts']
            else:
                bgp_facts = sonichost.bgp_facts()['ansible_facts']

            bgp_facts_on_hosts[hostname] = bgp_facts

            # Check BGP session state for each neighbor
            neigh_not_ok = []
            if self.is_multi_asic:
                for instance_id in bgp_facts:
                    for k, v in list(bgp_facts[instance_id]['bgp_neighbors'].items()):
                        if v['state'] != state:
                            neigh_not_ok.append(f"{k}, {v['state']}")
            else:
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
            if (self.is_multi_asic and
                    self.duts_basic_facts[sonichost.hostname]["ansible_facts"]["dut_basic_facts"]["is_supervisor"]):
                logger.info("Skip check_interface_status_of_up_ports on Supervisor.")
                continue

            hostname = sonichost.hostname
            logger.info(
                "----------------------- check_interface_status_of_up_ports on [{}] -----------------------".format(
                    hostname))

            # 1. Retrieve the configuration facts for the DUT
            # 2. Get a list of up ports from the configuration facts
            # 3. Retrieve the interface facts for the up ports
            if self.is_multi_asic:
                host_asics_list = self.duts_basic_facts[sonichost.hostname][
                    "ansible_facts"]["dut_basic_facts"]["asic_presence_list"]

                interface_facts = {}
                for asic_id in host_asics_list:
                    cfg_facts_of_asic = sonichost.config_facts(
                        host=hostname, source='running', namespace='asic{}'.format(asic_id)
                    )['ansible_facts']

                    up_ports = [
                        p for p, v in list(cfg_facts_of_asic['PORT'].items())
                        if v.get('admin_status', None) == 'up'
                    ]

                    logger.info('up_ports: {}'.format(up_ports))
                    interface_facts_of_asic = sonichost.interface_facts(
                        up_ports=up_ports, namespace='asic{}'.format(asic_id)
                    )['ansible_facts']

                    interface_facts[asic_id] = interface_facts_of_asic
                    if hostname not in interface_facts_on_hosts:
                        interface_facts_on_hosts[hostname] = {}

                    interface_facts_on_hosts[hostname][asic_id] = interface_facts

                    errlog = 'ansible_interface_link_down_ports on asic{} of {}: {}'.format(
                        asic_id, hostname, interface_facts[asic_id]['ansible_interface_link_down_ports'])

                    logger.info(errlog)

                    # Check if there are any link down ports in the interface facts
                    if len(interface_facts[asic_id]['ansible_interface_link_down_ports']) > 0:
                        # Set failed to True if any BGP neighbors are not established
                        failed = True
                        # Add errlog to check result errmsg
                        self.check_result.errmsg.append(errlog)

            else:
                cfg_facts = sonichost.config_facts(host=hostname, source='running')['ansible_facts']
                up_ports = [p for p, v in list(cfg_facts['PORT'].items()) if v.get('admin_status', None) == 'up']
                logger.info('up_ports: {}'.format(up_ports))
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
            host_asics_list = []
            if self.is_multi_asic:
                host_asics_list = self.duts_basic_facts[sonichost.hostname][
                    "ansible_facts"]["dut_basic_facts"]["asic_presence_list"]

            hostname = sonichost.hostname
            logger.info(
                "----------------------- check_critical_containers_running on [{}] -----------------------".format(
                    hostname))

            # Get the list of running containers on the host
            running_containers = sonichost.shell(r"docker ps -f 'status=running' --format \{\{.Names\}\}")[
                'stdout_lines']

            containers_to_check = critical_containers
            if self.is_multi_asic:
                if self.duts_basic_facts[sonichost.hostname]["ansible_facts"]["dut_basic_facts"]["is_supervisor"]:
                    containers_to_check = [
                        "{}{}".format(container, asic)
                        for asic in host_asics_list for container in critical_containers if container != "bgp"
                    ]
                else:
                    containers_to_check = [
                        "{}{}".format(container, asic)
                        for asic in host_asics_list for container in critical_containers
                    ]

            for critical_container in containers_to_check:

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

    logger.info("Checking")
    testbed_health_checker = TestbedHealthChecker(inventory=args.inventory, testbed_name=args.testbed_name,
                                                  testbed_file=args.tbfile, log_verbosity=args.verbosity,
                                                  output_file=args.output)
    testbed_health_checker.run_check()


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
