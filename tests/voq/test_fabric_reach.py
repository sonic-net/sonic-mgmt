import pytest
from tests.common.helpers.assertions import pytest_assert
import logging
import yaml

logger = logging.getLogger(__name__)
# This test only runs on t2 systems.
pytestmark = [
    pytest.mark.topology('t2')
]

localModule = 0
supervisorAsicBase = 1
supReferenceData = {}
linecardModule = []


# Try to get the reference data, and if the reference data files
# not updated, error out the test rather than fail it.
@pytest.fixture()
def refData(duthosts):
    # Get hwSku for Fabriccards from the supervisor.
    if len(duthosts.supervisor_nodes) == 0:
        logger.info("Please run the test on modular systems")
        return {}
    duthost = duthosts.supervisor_nodes[0]
    logger.info("duthost: {}".format(duthost.hostname))
    fabric_sku = None
    fabric_sku = duthost.facts['hwsku']
    pytest_assert(fabric_sku, "Need to add hwSku information for sup")

    # Check reference data found, error out the test.
    referenceData = {}
    for duthost in duthosts.frontend_nodes:
        slot = duthost.facts['slot_num']
        lc_sku = duthost.facts['hwsku']
        fileName = lc_sku + "_" + fabric_sku + "_" + "LC" + str(slot) + ".yaml"
        f = open("voq/fabric_data/{}".format(fileName))
        pytest_assert(f, "Need to update expected data for {}".format(fileName))
        referenceData[slot] = yaml.safe_load(f)
    return referenceData


# Try to load the setup information for supvisor.
@pytest.fixture()
def supData(duthosts):
    if len(duthosts.supervisor_nodes) == 0:
        logger.info("Please run the test on modular systems")
        return {}
    duthost = duthosts.supervisor_nodes[0]
    logger.info("duthost: {}".format(duthost.hostname))
    fabric_sku = None
    fabric_sku = duthost.facts['hwsku']
    fileName = fabric_sku + ".yaml"
    f = open("voq/fabric_data/{}".format(fileName))
    pytest_assert(f, "Need to update expected data for {}".format(fileName))
    supData = yaml.safe_load(f)
    f.close()
    return supData


# Added a function to setup fabric links reference data for sup.
def supRefData(duthosts):
    # supReferenceData has the expected data for sup
    global supReferenceData
    keys = []
    if len(duthosts.supervisor_nodes) == 0:
        logger.info("Please run the test on modular systems")
        return
    duthost = duthosts.supervisor_nodes[0]

    logger.info("duthost: {}".format(duthost.hostname))
    num_asics = duthost.num_asics()
    logger.info("num_asics: {}".format(num_asics))
    for asic in range(num_asics):
        keys.append('asic' + str(asic))
    supReferenceData = {key: {} for key in keys}

# This test checks the output of the "show fabric reachability" command
# on one linecard. It is called once for each linecard in the chassis.
# It loads the reference data for the linecard, runs the CLI command,
# and compares the output.


def test_fabric_reach_linecards(duthosts, enum_frontend_dut_hostname,
                                refData, supData):
    """compare the CLI output with the reference data"""
    global localModule
    global supervisorAsicBase
    global supReferenceData
    global linecardModule

    if not supReferenceData:
        supRefData(duthosts)
    # supReferenceData has the expected data
    if len(duthosts.supervisor_nodes) == 0:
        logger.info("Please run the test on modular systems")
        return
    duthost = duthosts.supervisor_nodes[0]
    logger.info("duthost: {}".format(duthost.hostname))

    # Load the reference data file.
    duthost = duthosts[enum_frontend_dut_hostname]
    logger.info("duthost: {}".format(duthost.hostname))
    slot = duthost.facts['slot_num']
    referenceData = refData[slot]

    # base module Id for asics on supervisor
    supervisorAsicBase = int(supData['moduleIdBase'])
    # the number of ASICs on each fabric card of a supervisor
    asicPerSlot = int(supData['asicPerSlot'])

    # Testing on Linecards
    num_asics = duthost.num_asics()
    for asic in range(num_asics):
        asicName = "asic{}".format(asic)
        if num_asics > 1:
            cmd = "show fabric reachability -n {}".format(asicName)
        else:
            cmd = "show fabric reachability"
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        asicReferenceData = referenceData[asicName]
        for line in cmd_output:
            if not line:
                continue
            tokens = line.split()
            if not tokens[0].isdigit():
                continue

            # tokens: [localPort, remoteModule, remotLink, localLinkStatus]
            # Example output: ['0', '304', '171', 'up']
            localPortName = int(tokens[0])
            remoteModule = tokens[1]
            remotePort = tokens[2]
            pytest_assert(localPortName in asicReferenceData,
                          "Reference port data for {} not found!".format(localPortName))
            referencePortData = asicReferenceData[localPortName]

            remoteSlot = int(referencePortData['peer slot'])
            remoteAsic = int(referencePortData['peer asic'])
            remoteMod = supervisorAsicBase + (remoteSlot - 1)*2 + remoteAsic
            referenceRemoteModule = str(remoteMod)
            referenceRemotePort = referencePortData['peer lk']
            pytest_assert(remoteModule == referenceRemoteModule,
                          "Remote module mismatch for port {}"
                          .format(localPortName))
            pytest_assert(remotePort == referenceRemotePort,
                          "Remote port mismatch for port {}"
                          .format(localPortName))

            # build reference data for sup: supReferenceData
            fabricAsic = 'asic' + str(remoteMod - supervisorAsicBase)
            lkData = {'peer slot': slot, 'peer lk': localPortName, 'peer asic': asic, 'peer mod': localModule}
            if localModule not in linecardModule:
                linecardModule.append(localModule)
            supReferenceData[fabricAsic].update({referenceRemotePort: lkData})
        # the module number increased by number of asics per slot.
        localModule += asicPerSlot

# This test checks the output of the "show fabric reachability -n asic<n>"
# command. It is only called one time and it iterates over all of the
# asics. The number of asics is in the duthost data for the supervisor.
# This number is typically reported as eighteen even though the
# supervisor cards typically have twelve fabric asics. The test
# checks if each asic is in the reference data and skips those that
# are not present.
# It loads the reference data for the supervisor, runs the CLI command,
# and compares the output.


def test_fabric_reach_supervisor(duthosts, enum_supervisor_dut_hostname, refData):
    """compare the CLI output with the reference data for each asic"""

    global supReferenceData
    # supReferenceData has the expected data
    duthost = duthosts[enum_supervisor_dut_hostname]
    logger.info("duthost: {}".format(duthost.hostname))
    num_asics = duthost.num_asics()
    logger.info("num_asics: {}".format(num_asics))
    for asic in range(num_asics):
        asicName = "asic{}".format(asic)
        logger.info(asicName)
        cmd = "show fabric reachability -n asic{}".format(asic)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        asicReferenceData = supReferenceData[asicName]
        for line in cmd_output:
            if not line:
                continue
            tokens = line.split()
            if not tokens[0].isdigit():
                continue
            localPortName = tokens[0]
            remoteModule = int(tokens[1])
            remotePort = int(tokens[2])
            if remoteModule not in linecardModule:
                logger.info("The linecard is not inserted or down.")
                continue
            pytest_assert(localPortName in asicReferenceData,
                          "Reference port data for {} not found!".format(localPortName))
            referencePortData = asicReferenceData[localPortName]
            referenceRemoteModule = referencePortData['peer mod']
            referenceRemotePort = referencePortData['peer lk']
            pytest_assert(remoteModule == referenceRemoteModule,
                          "Remote module mismatch for asic {}, port {}"
                          .format(asicName, localPortName))
            pytest_assert(remotePort == referenceRemotePort,
                          "Remote port mismatch for asic {}, port {}"
                          .format(asicName, localPortName))
