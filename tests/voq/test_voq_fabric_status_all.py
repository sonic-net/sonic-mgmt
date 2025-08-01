from tests.common.helpers.assertions import pytest_assert
import logging
import pytest
import yaml

logger = logging.getLogger(__name__)

# This test only runs on t2 systems.
pytestmark = [
    pytest.mark.topology('t2')
]

# This test checks the fabric link status.
# It loads the reference data for a linecard,
# and runs the CLI command to get the link status
# on the system and compares the output.


# Try to get the reference data. If the reference data files
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


# Get the slot number of inserted Fabric cards
@pytest.fixture()
def fabricSlots(duthosts):
    # Get the slot number of inserted fabric cards.
    if len(duthosts.supervisor_nodes) == 0:
        logger.info("Please run the test on modular systems")
        return {}
    duthost = duthosts.supervisor_nodes[0]
    totalAsics = duthost.num_asics()
    fabricslots = []
    for i in range(totalAsics):
        key = 'CHASSIS_FABRIC_ASIC_TABLE|asic' + str(i)

        cmd = "sonic-db-cli CHASSIS_STATE_DB hget '{}' 'name'".format(key)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        slot = cmd_output[0]
        if slot.startswith("FABRIC-CARD"):
            slot = slot.lstrip("FABRIC-CARD")
            slotNum = int(slot) + 1
            if slotNum not in fabricslots:
                fabricslots.append(slotNum)
    return fabricslots


# Test fabric link status
def test_voq_fabric_link_status(duthosts, refData, fabricSlots):
    """Check if the fabric serdes links are all up
    """
    logger.info("Checking fabric serdes links")

    # The test needs to run on a modular system.
    if len(duthosts.supervisor_nodes) == 0:
        logger.info("Please run the test on modular systems")
        return
    duthost = duthosts.supervisor_nodes[0]

    # Test fabric links status in Linecards, and get the expected link
    # information for Fabriccards.
    keys = []

    # Get the number of asics on supervisor.
    totalAsics = duthost.num_asics()
    for i in range(totalAsics):
        keys.append('asic' + str(i))
    supReferenceData = {key: {} for key in keys}
    linecardModule = []
    localModule = 0
    asicPerSlot = 2

    for duthost in duthosts.frontend_nodes:
        num_asics = duthost.num_asics()
        for asic in range(num_asics):
            if localModule not in linecardModule:
                linecardModule.append(localModule)
            localModule += asicPerSlot

    # skip supervisors, on Linecards now:
    for duthost in duthosts.frontend_nodes:
        slot = duthost.facts['slot_num']
        referenceData = refData[slot]
        output_cli = duthost.shell("show fabric counters port")['stdout_lines']
        logger.info(duthost.facts['hwsku'])
        logger.info(duthost.facts['slot_num'])

        # Test fabric link status
        asicData = {}
        for link in output_cli:
            content = link.split()
            if not content:
                continue
            # Example cli output (first three fields:
            # asic, link, status, ...
            # [u'0', u'0', u'up',...]
            if content[0].isnumeric():
                linkKey = duthost.hostname + "-" + str(content[0]) + "-" + str(content[1])
                logger.info("Testing : {}".format(linkKey))
                # check:

                asic = "asic" + content[0]
                lk = int(content[1])
                status = content[2]

                if asic not in referenceData:
                    pytest_assert(False, "{} is not expected to be up.".format(asic))
                if lk not in referenceData[asic]:
                    pytest_assert(status.lower() != 'up',
                                  "link {} is not expected to be up.".format(lk))
                    logger.info("Skip udpating the information as this is designed to be down")
                    continue

                # update link information on suppervisor
                lkData = {'peer slot': slot, 'peer lk': lk, 'peer asic': asic}
                fabricLk = referenceData[asic][lk]['peer lk']
                fabricSlot = int(referenceData[asic][lk]['peer slot'])
                asicId = int(referenceData[asic][lk]['peer asic'])
                asicId = (fabricSlot - 1) * 2 + asicId
                fabricAsic = 'asic' + str(asicId)

                asicData.update({fabricLk: lkData})
                logger.info("Fabric: {}".format(fabricAsic))
                logger.info(" data: {}".format(asicData))
                supReferenceData[fabricAsic].update({fabricLk: lkData})

                if status.lower() != 'up':
                    if fabricSlot in fabricSlots:
                        logger.info("link {}. is expected to be up.".format(linkKey))
                        pytest_assert(status.lower() == 'up',
                                      "link {}. is expected to be up.".format(linkKey))
            else:
                logger.info("Header line {}".format(content))

    # Testing fabric link status on the supervisor

    for duthost in duthosts.supervisor_nodes:
        slot = duthost.facts['slot_num']

        output_cli = duthost.shell("show fabric counters port")['stdout_lines']
        logger.info("Checking fabric link status on sup:")
        logger.info(duthost.facts['hwsku'])
        logger.info(duthost.facts['slot_num'])

        for link in output_cli:
            content = link.split()
            if not content:
                continue
            if content[0].isnumeric():
                linkKey = duthost.hostname + "-" + str(content[0]) + "-" + str(content[1])
                # print linkKey, and check if this is expected to be up
                logger.info("Testing: {}".format(linkKey))

                asic = "asic" + content[0]
                lk = content[1]
                status = content[2]

                if asic not in supReferenceData:
                    pytest_assert(False, "{} is not expected to be up.".format(asic))
                if lk not in supReferenceData[asic]:
                    if status.lower() == 'down':
                        continue
                    else:
                        # check link status
                        cmd = "sonic-db-cli -n {} STATE_DB hget 'FABRIC_PORT_TABLE|PORT{}' REMOTE_MOD".format(asic, lk)
                        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
                        logger.info(cmd_output)
                        module = cmd_output[0]
                        if module not in linecardModule:
                            continue
                        pytest_assert(False, "link {} is not expected to be up.".format(lk))
                pytest_assert(status.lower() == 'up',
                              "link {}. is expected to be up.".format(linkKey))
