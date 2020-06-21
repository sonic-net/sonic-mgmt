import os
import pytest
import logging

logger = logging.getLogger(__name__)

ROOT_DIR = "/root"
ACS_TESTS = "acstests"
PTF_TESTS = "ptftests"
SAI_TESTS = "saitests"
CHANGE_MAC_ADDRESS_SCRIPT = "scripts/change_mac.sh"

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
