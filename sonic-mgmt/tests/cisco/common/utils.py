import pytest
import ipaddr
import logging
import os

from collections import namedtuple

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_require, pytest_assert

logger = logging.getLogger(__name__)

ROOT_DIR = "/root"
CISCO_DIR = "cisco"


class CheckEnvironment:
    _is_sim = None

    @staticmethod
    def is_sim(duthost):
        if CheckEnvironment._is_sim is None:
            result = duthost.command("dmidecode")
            if 'QEMU' in result["stdout"]:
                CheckEnvironment._is_sim = True
                logging.info("In simulation env")
            else:
                CheckEnvironment._is_sim = False
                logging.info("In hardware env")
        return CheckEnvironment._is_sim


@pytest.fixture(scope="session", autouse=True)
def copy_cisco_directory(ptfhost):
    """
        Copies cisco directory to PTF host.
        This copying follows the concept of copying the saitest for
        qos test in sonic-mgmt.
        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
        Returns:
            None
    """
    logger.info("Copy cisco directory to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=CISCO_DIR, dest=ROOT_DIR)

    yield

    logger.info("Delete cisco directory from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, CISCO_DIR), state="absent")


@pytest.fixture(scope='module')
def skip_if_sim(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Skip the test if its a simulation environment
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pytest_require(not CheckEnvironment.is_sim(duthost),
                   'Test not supported in SIM environment')


@pytest.fixture(scope='module')
def skip_if_not_sim(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Skip the test if its not simulation environment
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    pytest_require(CheckEnvironment.is_sim(duthost),
                   'Test is supported only in SIM environment')


def verify_command_result(result, cmd):
    # Raise an AssertionError if "stdout" is empty
    assert result["stdout"], "No output for {}".format(cmd)

    # Check if "Traceback" is present in result["stdout"]
    traceback_found = "Traceback" in result["stdout"]
    # Raise an AssertionError if "Traceback" is found
    assert not traceback_found, "Traceback found in {}".format(cmd)


class IPRoutes:
    """
    Program IP routes with next hops on to the DUT
    """
    def __init__(self, duthost, asic):
        self.arp_list = []
        self.asic = asic
        self.duthost = duthost

        fileloc = os.path.join(os.path.sep, "tmp")
        self.filename = os.path.join(fileloc, "static_ip.sh")
        self.ip_nhops = []
        self.IP_NHOP = namedtuple("IP_NHOP", "prefix nhop")

    def add_ip_route(self, ip_route, nhop_path_ips):
        """
        Add IP route with ECMP paths
        """
        # add IP route, nhop to list
        self.ip_nhops.append(self.IP_NHOP(ip_route, nhop_path_ips))

    def program_routes(self):
        """
        Create a file with static ip route add commands, copy file
        to DUT and run it from DUT
        """
        with open(self.filename, "w") as fn:
            for ip_nhop in self.ip_nhops:

                ip_route = "sudo {} ip route add {}".format(
                    self.asic.ns_arg, ip_nhop.prefix
                )
                ip_nhop_str = ""

                for ip in ip_nhop.nhop:
                    ip_nhop_str += "nexthop via {} ".format(ip)

                ip_cmd = "{} {}".format(ip_route, ip_nhop_str)
                fn.write(ip_cmd + "\n")

        fn.close()
        # copy file to DUT and run it on DUT
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
        result = self.duthost.shell(self.filename)
        pytest_assert(
            result["rc"] == 0,
            "IP add failed on duthost:{}".format(self.filename)
        )

    def delete_routes(self):
        """
        Create a file with static ip route del commands, copy file
        to DUT and run it from DUT
        """
        with open(self.filename, "w") as fn:
            for ip_nhop in self.ip_nhops:
                ip_route = "sudo {} ip route del {}".format(self.asic.ns_arg, ip_nhop.prefix)
                fn.write(ip_route + "\n")

        fn.close()
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
            os.remove(self.filename)
        except:  # noqa: E722
            pass


class Arp:
    """
    Create IP interface and create a list of ARPs with given IP,
    MAC parameters
    """
    def __init__(self, duthost, asic, count, iface, ip=ipaddr.IPAddress("172.16.0.0"), mac="C0:FF:EE:00"):
        IP_MAC = namedtuple("IP_MAC", "ip mac")
        self.iface = iface
        self.ip_mac_list = []
        self.duthost = duthost
        self.asic = asic
        self.if_addr = "{}/16".format(ip + 3)

        fileloc = os.path.join(os.path.sep, "tmp")
        self.filename = os.path.join(fileloc, "static_arp.sh")

        # create a list of IP-MAC bindings
        for i in range(11, count + 11):
            moff1 = "{0:x}".format(i // 255)
            moff2 = "{0:x}".format(i % 255)

            self.ip_mac_list.append(IP_MAC(
                "{}".format(ip + i),
                "{}:{}:{}".format(mac, moff1.zfill(2), moff2.zfill(2))
            ))

    def arps_add(self):
        """
        Create a file with static arp add commands, copy file
        to DUT and run it from DUT
        """

        # add IP address to the eth interface
        ip_iface = "ip address add {} dev {}".format(self.if_addr, self.iface)
        logger.info("IF ADDR ADD {}".format(ip_iface))
        result = self.asic.command(ip_iface)
        pytest_assert(result["rc"] == 0, ip_iface)

        arp_cmd = "sudo {} arp -s {} {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.ip_mac_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip, ip_mac.mac)
                fn.write(cmd + "\n")

        fn.close()
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
        result = self.duthost.shell(self.filename)
        pytest_assert(
            result["rc"] == 0,
            "arp add failed on duthost:{}".format(self.filename)
        )

    def arps_del(self):
        """
        Create a file with static arp del commands, copy file
        to DUT and run it from DUT
        """
        arp_cmd = "sudo {} arp -d {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.ip_mac_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip)
                fn.write(cmd + "\n")

        fn.close()
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
            os.remove(self.filename)
        except:  # noqa: E722
            pass

    def clean_up(self):
        # delete static ARPs
        self.arps_del()

        # del IP address from the eth interface
        ip_iface = "ip address del {} dev {}".format(self.if_addr, self.iface)
        logger.info("IF ADDR DEL {}".format(ip_iface))
        try:
            self.asic.command(ip_iface)
        except:  # noqa: E722
            pass


def get_crm_info(duthost, asic):
    """
    get CRM info
    """
    get_group_stats = ("{} COUNTERS_DB HMGET CRM:STATS"
                       " crm_stats_nexthop_group_used"
                       " crm_stats_nexthop_group_available"
                       " crm_stats_nexthop_group_member_used"
                       " crm_stats_nexthop_group_member_available").format(asic.sonic_db_cli)
    pytest_assert(wait_until(25, 5, 0, lambda: (len(duthost.command(get_group_stats)["stdout_lines"]) >= 2)),
                  get_group_stats)

    result = duthost.command(get_group_stats)
    pytest_assert(result["rc"] == 0 or len(result["stdout_lines"]) < 2, get_group_stats)

    crm_info = {
        "used_nhop_grp": int(result["stdout_lines"][0]),
        "available_nhop_grp": int(result["stdout_lines"][1]),
        "used_nhop_grp_mem": int(result["stdout_lines"][2]),
        "available_nhop_grp_mem": int(result["stdout_lines"][3])
    }

    get_polling = '{} CONFIG_DB HMGET "CRM|Config" "polling_interval"'.format(
        asic.sonic_db_cli
    )
    result = duthost.command(get_polling)
    pytest_assert(result["rc"] == 0, get_polling)

    crm_info.update({
        "polling": int(result["stdout_lines"][0])
    })

    return crm_info


# code from doc.python.org to generate combinations
# This is used to create unique nexthop groups
def combinations(iterable, r):
    # combinations('ABCD', 2) --> AB AC AD BC BD CD
    # combinations(range(4), 3) --> 012 013 023 123
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return
    indices = list(range(r))
    yield tuple(pool[i] for i in indices)
    while True:
        for i in reversed(list(range(r))):
            if indices[i] != i + n - r:
                break
        else:
            return
        indices[i] += 1
        for j in range(i + 1, r):
            indices[j] = indices[j - 1] + 1
        yield tuple(pool[i] for i in indices)
