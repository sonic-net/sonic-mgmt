import os
import pytest
import logging

from jinja2 import Template
from natsort import natsorted


logger = logging.getLogger(__name__)

ROOT_DIR = "/root"
OPT_DIR = "/opt"
SUPERVISOR_CONFIG_DIR = "/etc/supervisor/conf.d/"
SCRIPTS_SRC_DIR = "scripts/"
TEMPLATES_DIR = "templates/"
ACS_TESTS = "acstests"
PTF_TESTS = "ptftests"
SAI_TESTS = "saitests"
ARP_RESPONDER_PY = "arp_responder.py"
ICMP_RESPONDER_PY = "icmp_responder.py"
ICMP_RESPONDER_CONF_TEMPL = "icmp_responder.conf.j2"
CHANGE_MAC_ADDRESS_SCRIPT = "scripts/change_mac.sh"
REMOVE_IP_ADDRESS_SCRIPT = "scripts/remove_ip.sh"


@pytest.fixture(scope="session", autouse=True)
def copy_acstests_directory(ptfhost):
    """
        Copys ACS tests directory to PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Copy ACS test files to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=ACS_TESTS, dest=ROOT_DIR)

    yield

    logger.info("Delete ACS test files from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, ACS_TESTS), state="absent")


@pytest.fixture(scope="session", autouse=True)
def copy_ptftests_directory(ptfhost):
    """
        Copys PTF tests directory to PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Copy PTF test files to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=PTF_TESTS, dest=ROOT_DIR)

    yield

    logger.info("Delete PTF test files from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, PTF_TESTS), state="absent")


@pytest.fixture(scope="session", autouse=True)
def copy_saitests_directory(ptfhost):
    """
        Copys SAI tests directory to PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Copy SAI test files to PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=SAI_TESTS, dest=ROOT_DIR)

    yield

    logger.info("Delete SAI test files from PTF host '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(ROOT_DIR, SAI_TESTS), state="absent")


@pytest.fixture(scope="session", autouse=True)
def change_mac_addresses(ptfhost):
    """
        Change MAC addresses (unique) on PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            None
    """
    logger.info("Change interface MAC addresses on ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.script(CHANGE_MAC_ADDRESS_SCRIPT)


@pytest.fixture(scope="session", autouse=True)
def remove_ip_addresses(ptfhost):
    """
        Remove existing IP addresses on PTF host.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
        Returns:
            None
    """
    logger.info("Remove existing IPs on ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.script(REMOVE_IP_ADDRESS_SCRIPT)

    yield

    logger.info("Remove IPs to restore ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.script(REMOVE_IP_ADDRESS_SCRIPT)


@pytest.fixture(scope="session", autouse=True)
def copy_arp_responder_py(ptfhost):
    """
        Copy arp_responder to PTF container.

        Args:
            ptfhost (AnsibleHost): Packet Test Framework (PTF)
        Returns:
            None
    """
    logger.info("Copy arp_responder.py to ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ARP_RESPONDER_PY), dest=OPT_DIR)

    yield

    logger.info("Delete arp_responder.py from ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.file(path=os.path.join(OPT_DIR, ARP_RESPONDER_PY), state="absent")


@pytest.fixture(scope='class')
def ptf_portmap_file(duthosts, rand_one_dut_hostname, ptfhost):
    """
        Prepare and copys port map file to PTF host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
            ptfhost (AnsibleHost): Packet Test Framework (PTF)

        Returns:
            filename (str): returns the filename copied to PTF host
    """
    duthost = duthosts[rand_one_dut_hostname]
    intfInfo = duthost.show_interface(command = "status")['ansible_facts']['int_status']
    portList = natsorted([port for port in intfInfo if port.startswith('Ethernet')])
    portMapFile = "/tmp/default_interface_to_front_map.ini"
    with open(portMapFile, 'w') as file:
        file.write("# ptf host interface @ switch front port name\n")
        file.writelines(
            map(
                    lambda (index, port): "{0}@{1}\n".format(index, port),
                    enumerate(portList)
                )
            )

    ptfhost.copy(src=portMapFile, dest="/root/")

    yield "/root/{}".format(portMapFile.split('/')[-1])


@pytest.fixture(scope="session", autouse=True)
def run_icmp_responder(duthost, ptfhost, tbinfo):
    """Run icmp_responder.py over ptfhost."""
    logger.debug("Copy icmp_responder.py to ptfhost '{0}'".format(ptfhost.hostname))
    ptfhost.copy(src=os.path.join(SCRIPTS_SRC_DIR, ICMP_RESPONDER_PY), dest=OPT_DIR)

    logging.debug("Start running icmp_responder")
    templ = Template(open(os.path.join(TEMPLATES_DIR, ICMP_RESPONDER_CONF_TEMPL)).read())
    ptf_indices = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]
    vlan_intfs = duthost.get_vlan_intfs()
    icmp_responder_args = " ".join("-i eth%s" % ptf_indices[_] for _ in vlan_intfs)
    ptfhost.copy(
        content=templ.render(icmp_responder_args=icmp_responder_args),
        dest=os.path.join(SUPERVISOR_CONFIG_DIR, "icmp_responder.conf")
    )
    ptfhost.shell("supervisorctl update")
    ptfhost.shell("supervisorctl start icmp_responder")

    yield

    logging.debug("Stop running icmp_responder")
    ptfhost.shell("supervisorctl stop icmp_responder")
