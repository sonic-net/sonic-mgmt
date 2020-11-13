import os
from natsort import natsorted
import pytest
import logging

logger = logging.getLogger(__name__)

ROOT_DIR = "/root"
OPT_DIR = "/opt"
SCRIPTS_SRC_DIR = "scripts/"
ACS_TESTS = "acstests"
PTF_TESTS = "ptftests"
SAI_TESTS = "saitests"
ARP_RESPONDER_PY = "arp_responder.py"
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
