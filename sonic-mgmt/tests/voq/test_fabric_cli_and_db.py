import pytest
from tests.common.helpers.assertions import pytest_assert
import logging
import random
logger = logging.getLogger(__name__)
# This test only runs on t2 systems.
pytestmark = [
    pytest.mark.topology('t2')
]

# There are 12 asic on Supervisor now.
# Initialize the reference data dictionary for sup.
num_asics = 12

# Set the number of links to test for each test. If all
# links are tested these tests can take almost an hour!
num_links_to_test = 6

# This test iterates over the fabric links on a linecard
# It isolates and unisolates each fabric link. Each time the
# state of the link is changed the state is checked in both
# CONFIG_DB and APPL_DB.
# The values in CONFIG_DB are updated by the fabric CLI commands
# and the values in APPL_DB are updated by the fabric manager
# daemon.


def test_fabric_cli_isolate_linecards(duthosts, enum_frontend_dut_hostname):
    """compare the CLI output with the reference data"""
    allPortsList = []

    duthost = duthosts[enum_frontend_dut_hostname]
    logger.info("duthost: {}".format(duthost.hostname))

    # Testing on Linecards
    num_asics = duthost.num_asics()
    logger.info("num_asics: {}".format(num_asics))
    for asic in range(num_asics):
        cmd = "show fabric reachability"
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        asicName = "asic{}".format(asic)
        logger.info(asicName)
        if num_asics > 1:
            asicNamespaceOption = "-n {}".format(asicName)
        else:
            asicNamespaceOption = ""

        # Create list of ports
        for line in cmd_output:
            if not line:
                continue
            tokens = line.split()
            if not tokens[0].isdigit():
                continue

            # tokens: [localPort, remoteModule, remotLink, localLinkStatus]
            localPort = tokens[0]
            allPortsList.append(localPort)

        # To test a few of the links
        portList = []
        while len(portList) < num_links_to_test:
            randomPort = random.choice(allPortsList)
            if randomPort not in portList:
                portList.append(randomPort)

        # Test each fabric link
        for localPort in portList:
            logger.info("localPort {}".format(localPort))
            # continue
            # Get the current isolation status of the port
            cmd = "sonic-db-cli {} CONFIG_DB hget 'FABRIC_PORT|Fabric{}' isolateStatus".format(asicNamespaceOption,
                                                                                               localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            originalIsolateStatus = tokens[0]
            pytest_assert(
                originalIsolateStatus == "True" or originalIsolateStatus == "False",
                "Port {} CONFIG_DB initial isolateStatus is True, expected False".format(localPort))

            # If the port is isolated then temporarily unisolate it
            if originalIsolateStatus == "True":
                cmd = "sudo config fabric port unisolate {} {}".format(localPort, asicNamespaceOption)
                cmd_output = duthost.shell(cmd, module_ignore_errors=True)
                stderr_output = cmd_output["stderr"]
                pytest_assert(
                      len(stderr_output) <= 0, "command: {} failed, error: {}".format(cmd, stderr_output))

            # Check the isolateStatus in CONFIG_DB
            cmd = "sonic-db-cli {} CONFIG_DB hget 'FABRIC_PORT|Fabric{}' isolateStatus".format(asicNamespaceOption,
                                                                                               localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT|Fabric{} isolateStatus not found in CONFIG_DB".format(localPort))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "False",
                  "Port {} CONFIG_DB initial isolateStatus is True, expected False".format(localPort))

            # Check the isolateStatus in APPL_DB
            cmd = "sonic-db-cli {} APPL_DB hget 'FABRIC_PORT_TABLE:Fabric{}' isolateStatus".format(asicNamespaceOption,
                                                                                                   localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            pytest_assert(
                  len(tokens) > 0, "FABRIC_PORT_TABLE:Fabric{} isolateStatus not found in APPL_DB".format(localPort))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "False",
                  "Port {} APPL_DB initial isolateStatus is True, expected False".format(localPort))

            # Isolate the port
            cmd = "sudo config fabric port isolate {} {}".format(localPort, asicNamespaceOption)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)
            stderr_output = cmd_output["stderr"]
            pytest_assert(
                  len(stderr_output) <= 0, "command: {} failed, error: {}".format(cmd, stderr_output))

            # Check the isolateStatus in CONFIG_DB
            cmd = "sonic-db-cli {} CONFIG_DB hget 'FABRIC_PORT|Fabric{}' isolateStatus".format(asicNamespaceOption,
                                                                                               localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT|Fabric{} isolateStatus not found in CONFIG_DB".format(localPort))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "True",
                  "Port {} CONFIG_DB initial isolateStatus is True, expected False".format(localPort))

            # Check the isolateStatus in APPL_DB
            cmd = "sonic-db-cli {} APPL_DB hget 'FABRIC_PORT_TABLE:Fabric{}' isolateStatus".format(asicNamespaceOption,
                                                                                                   localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT_TABLE:Fabric{} isolateStatus not found in APPL_DB".format(localPort))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "True",
                  "Port {} APPL_DB initial isolateStatus is True, expected False".format(localPort))

            # If the port was originally not isolsated then restore it
            if originalIsolateStatus == "False":
                cmd = "sudo config fabric port unisolate {} {}".format(localPort, asicNamespaceOption)
                cmd_output = duthost.shell(cmd, module_ignore_errors=True)
                stderr_output = cmd_output["stderr"]
                pytest_assert(
                      len(stderr_output) <= 0,
                      "command: {} failed, error: {}".format(cmd, stderr_output))


# This test iterates over the fabric links on each asic
# on the supervisor.
# It isolates and unisolates each fabric link. Each time the
# state of the link is changed the state is checked in both
# CONFIG_DB and APPL_DB.
# The values in CONFIG_DB are updated by the fabric CLI commands
# and the values in APPL_DB are updated by the fabric manager
# daemon.


def test_fabric_cli_isolate_supervisor(duthosts, enum_supervisor_dut_hostname):
    """compare the CLI output with the reference data for each asic"""

    duthost = duthosts[enum_supervisor_dut_hostname]
    logger.info("duthost: {}".format(duthost.hostname))
    num_asics = duthost.num_asics()
    logger.info("num_asics: {}".format(num_asics))
    for asic in range(num_asics):
        allPortsList = []
        portList = []
        asicName = "asic{}".format(asic)
        logger.info(asicName)

        # Create list of ports
        cmd = "show fabric reachability -n asic{}".format(asic)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        for line in cmd_output:
            if not line:
                continue
            tokens = line.split()
            # (localPort,  remoteModule, remotePort, status)
            if not tokens[0].isdigit():
                continue
            localPort = tokens[0]
            allPortsList.append(localPort)

        # To test a few of the links
        portList = []
        while len(portList) < num_links_to_test:
            randomPort = random.choice(allPortsList)
            if randomPort not in portList:
                portList.append(randomPort)

        # Test each fabric link
        for localPort in portList:
            logger.info("local port {}".format(localPort))
            # continue

            # Get the current isolation status of the port
            cmd = "sonic-db-cli -n {} CONFIG_DB hget 'FABRIC_PORT|Fabric{}' isolateStatus".format(asicName, localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            originalIsolateStatus = tokens[0]
            pytest_assert(
                  originalIsolateStatus == "True" or originalIsolateStatus == "False",
                  "Port {} CONFIG_DB initial isolateStatus is True, expected False".format(localPort))
            logger.debug("originalIsolateStatus: {}".format(originalIsolateStatus))

            # If the port is isolated then temporarily unisolate it
            if originalIsolateStatus == "True":
                cmd = "sudo config fabric port unisolate {} -n {}".format(localPort, asicName)
                cmd_output = duthost.shell(cmd, module_ignore_errors=True)
                stderr_output = cmd_output["stderr"]
                pytest_assert(
                      len(stderr_output) <= 0,
                      "command: {} failed, error: {}".format(cmd, stderr_output))

            # Check the isolateStatus in CONFIG_DB
            cmd = "sonic-db-cli -n {} CONFIG_DB hget 'FABRIC_PORT|Fabric{}' isolateStatus".format(asicName, localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            originalIsolateStatus = tokens[0]
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT|Fabric{} isolateStatus not found in CONFIG_DB, {} ".format(localPort, asicName))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "False",
                  "Port {} CONFIG_DB initial isolateStatus is '{}', expected False".format(localPort, isolateStatus))

            # Check the isolateStatus in APPL_DB
            cmd = "sonic-db-cli -n {} APPL_DB hget 'FABRIC_PORT_TABLE:Fabric{}' isolateStatus".format(asicName,
                                                                                                      localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            originalIsolateStatus = tokens[0]
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT_TABLE:Fabric{} isolateStatus not found in APPL_DB, {} ".format(localPort, asicName))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "False",
                  "Port {} APPL_DB initial isolateStatus is '{}', expected False".format(localPort, isolateStatus))

            # Isolate the port
            cmd = "sudo config fabric port isolate {} -n {}".format(localPort, asicName)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)
            stderr_output = cmd_output["stderr"]
            pytest_assert(
                  len(stderr_output) <= 0,
                  "command: {} failed, error: {}".format(cmd, stderr_output))

            # Check the isolateStatus in CONFIG_DB
            cmd = "sonic-db-cli -n {} CONFIG_DB hget 'FABRIC_PORT|Fabric{}' isolateStatus".format(asicName, localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            originalIsolateStatus = tokens[0]
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT|Fabric{} isolateStatus not found in CONFIG_DB, {} ".format(localPort, asicName))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "True",
                  "Port {} CONFIG_DB initial isolateStatus is '{}', expected False".format(localPort, isolateStatus))

            # Check the isolateStatus in APPL_DB
            cmd = "sonic-db-cli -n {} APPL_DB hget 'FABRIC_PORT_TABLE:Fabric{}' isolateStatus".format(asicName,
                                                                                                      localPort)
            cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
            tokens = cmd_output[0].split()
            originalIsolateStatus = tokens[0]
            pytest_assert(
                  len(tokens) > 0,
                  "FABRIC_PORT_TABLE:Fabric{} isolateStatus not found in APPL_DB, {} ".format(localPort, asicName))
            isolateStatus = tokens[0]
            pytest_assert(
                  isolateStatus == "True",
                  "Port {} APPL_DB initial isolateStatus is '{}', expected False".format(localPort, isolateStatus))

            # If the port was originally not isolsated then restore it
            if originalIsolateStatus == "False":
                cmd = "sudo config fabric port unisolate {} -n {}".format(localPort, asicName)
                cmd_output = duthost.shell(cmd, module_ignore_errors=True)
                stderr_output = cmd_output["stderr"]
                pytest_assert(
                      len(stderr_output) <= 0,
                      "command: {} failed, error: {}".format(cmd, stderr_output))
