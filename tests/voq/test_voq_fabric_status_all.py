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


def test_voq_fabric_link_status(duthosts):
    """Check if the fabric serdes links are all up
    """
    logger.info("Checking fabric serdes links")

    # Get hwSku for Fabriccards from the supervisor.
    fabric_sku = None
    for duthost in duthosts:
        if duthost.facts['slot_num'] < 3:
            fabric_sku = duthost.facts['hwsku']
            break
    pytest_assert(fabric_sku, "Need to add hwSku information for sup")

    # Test fabric links status in Linecards, and get the expected link
    # information for Fabriccards.
    keys = []
    # There are 12 asic on Supervisor now.
    totalAsics = 12
    for i in range(totalAsics):
        keys.append('asic' + str(i))
    supReferenceData = {key: {} for key in keys}

    for duthost in duthosts:
        slot = duthost.facts['slot_num']
        if slot < 3:
            # skip supervisors
            continue
        lc_sku = duthost.facts['hwsku']
        fileName = lc_sku + "_" + fabric_sku + "_" + "LC" + str(slot) + ".yaml"
        f = open("voq/fabric_data/{}".format(fileName))
        pytest_assert(f, "Need to update expected data for {}".format(fileName))
        referenceData = yaml.load(f)
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
                    pytest_assert(False, "link {} is not expected to be up.".format(lk))
                pytest_assert(status.lower() == 'up',
                              "link {}. is expected to be up.".format(lk))

                #update link information on suppervisor
                lkData = {'peer slot': slot, 'peer lk': lk, 'peer asic': asic}
                fabricLk = referenceData[asic][lk]['peer lk']
                fabricSlot = referenceData[asic][lk]['peer slot']
                asicId = int(referenceData[asic][lk]['peer asic'])
                asicId = (fabricSlot - 1) * 2 + asicId
                fabricAsic = 'asic' + str(asicId)

                asicData.update({fabricLk: lkData})
                logger.info("Fabric: {}".format(fabricAsic))
                logger.info(" data: {}".format(asicData))
                supReferenceData[fabricAsic].update({fabricLk: lkData})
            else:
                logger.info("Header line {}".format(content))

    # Testing fabric link status on the supervisor

    for duthost in duthosts:
        slot = duthost.facts['slot_num']
        if slot >= 3:
            # skip Linecards that checked already
            continue

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
                        pytest_assert(False, "link {} is not expected to be up.".format(lk))
                pytest_assert(status.lower() == 'up',
                              "link {}. is expected to be up.".format(lk))
