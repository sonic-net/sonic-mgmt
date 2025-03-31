import pytest
import logging

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.disable_loganalyzer,
]

MINIGRAPH = "/etc/sonic/minigraph.xml"
MINIGRAPH_BACKUP = "/etc/sonic/minigraph.xml.bak"
GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_BACKUP = "/etc/sonic/golden_config_db.json.bak"
NGS_BASE_URL = "https://ngstest.trafficmanager.net/netgraph/ReadDeviceMinigraph?hostname="
NDM_BASE_URL = "https://ndm.network-test-bl6p.bl6p.ap.gbl/ndm/api/ReadDeviceConfiguration"
firmware_version = "SONiC.20240532.08"


def file_exists_on_dut(duthost, filename):
    """
    Check if a file exists on the DUT.

    Args:
        duthost: The DUT host object.
        filename: The name of the file to check.

    Returns:
        bool: True if the file exists, False otherwise.
    """
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)


def backup_minigraph_and_golden_config(duthost):
    minigraph_stat = duthost.stat(path=MINIGRAPH)
    if not minigraph_stat["stat"]["exists"]:
        logger.warning(f"{MINIGRAPH} does not exist on {duthost.hostname}, skipping backup.")
    else:
        logger.info("Backup minigraph {} to {} on {}".format(
            MINIGRAPH, MINIGRAPH_BACKUP, duthost.hostname))
        duthost.shell("sudo cp {} {}".format(MINIGRAPH, MINIGRAPH_BACKUP))

    golden_config_stat = duthost.stat(path=GOLDEN_CONFIG)
    if not golden_config_stat["stat"]["exists"]:
        logger.warning(f"{GOLDEN_CONFIG} does not exist on {duthost.hostname}, skipping backup.")
    else:
        logger.info("Backup golden config {} to {} on {}".format(
            GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP, duthost.hostname))
        duthost.shell("sudo cp {} {}".format(GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP))


def download_minigraph_and_golden_config(duthost, creds):
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    logger.info("Download minigraph on {} through {}".format(duthost.hostname, https_proxy))
    try:
        result = duthost.shell(
            "sudo curl -k -x {} -o {} {}".format(
                https_proxy, MINIGRAPH, NGS_BASE_URL + duthost.hostname
            )
        )
        if result['rc'] != 0:
            raise Exception("Failed to download minigraph. Error: {}".format(result['stderr']))
    except Exception as e:
        logger.error("Error downloading minigraph: {}".format(e))
        raise

    logger.info("Download golden config on {}".format(duthost.hostname))
    try:
        result = duthost.shell(
            (
                "sudo curl -k -x {} -o {} \"{}\" "
                "-d 'configType=CurrentVerifiedSonicState&hostname={}&OverrideDynamicData="
                "{{\"{}\":{{\"SwitchFirmware\":\"{}\"}}}}' "
                "-G -H \"Content-Type: application/json\""
            ).format(
                https_proxy,
                GOLDEN_CONFIG,
                NDM_BASE_URL,
                duthost.hostname,
                duthost.hostname,
                firmware_version,
            )
        )
        if result['rc'] != 0:
            raise Exception("Failed to download golden config. Error: {}".format(result['stderr']))
    except Exception as e:
        logger.error("Error downloading golden config: {}".format(e))
        raise


def restore_minigraph_and_golden_config(duthost):
    logger.info("Restore minigraph {} from {} on {}".format(
        MINIGRAPH, MINIGRAPH_BACKUP, duthost.hostname))
    duthost.shell("sudo cp {} {}".format(MINIGRAPH_BACKUP, MINIGRAPH))

    logger.info("Restore golden config {} from {} on {}".format(
        GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP, duthost.hostname))
    duthost.shell("sudo cp {} {}".format(GOLDEN_CONFIG_BACKUP, GOLDEN_CONFIG))


def config_reload_minigraph_with_rendered_golden_config(duthost):
    logger.info("Reload minigraph with rendered golden config")
    duthost.shell("sudo config load_minigraph --override_config -y")
    duthost.shell("sudo config save -y")


@pytest.fixture(scope="module")
def setup_env(duthosts, tbinfo, creds):
    """
    Setup/teardown
    Args:
        duthost: DUT.
        golden_config_exists_on_dut: Check if golden config exists on DUT.
    """
    # Prepare for all DUTs
    for duthost in duthosts:
        if not duthost.is_multi_asic:
            pytest.skip("Skip test on single asic platforms as it is designed for multi asic.")

        topo_type = tbinfo["topo"]["type"]
        if topo_type not in ["t2"]:
            pytest.skip("Skip test on single asic platforms as it is designed for multi asic.")

        # Ensure that the golden config exists on the DUT
        if not file_exists_on_dut(duthost, GOLDEN_CONFIG):
            pytest.skip("Golden config does not exist on DUT. Skip the test.")

        # Ensure that the minigraph exists on the DUT
        if not file_exists_on_dut(duthost, MINIGRAPH):
            pytest.skip("Minigraph does not exist on DUT. Skip the test.")

        # Backup minigraph and golden config
        backup_minigraph_and_golden_config(duthost)

        # Download minigraph and golden config
        download_minigraph_and_golden_config(duthost, creds)

        # load minigraph with override golden config
        config_reload_minigraph_with_rendered_golden_config(duthost)

    yield

    # Cleanup for all DUTs
    for duthost in duthosts:
        # Restore minigraph and golden config
        restore_minigraph_and_golden_config(duthost)
        config_reload_minigraph_with_rendered_golden_config(duthost)


def test_golden_config_yang_validation_check(duthosts, rand_one_dut_hostname, setup_env):
    duthost = duthosts[rand_one_dut_hostname]
    if not duthost.is_multi_asic:
        pytest.skip("Skip this test on single-asic platforms, \
                    since test NGS has not supported single-asic yet.")

    try:
        # Prepare a empty list to a file and test apply-patch
        duthost.shell("echo '[]' > /tmp/empty_list.json")
        result = duthost.shell("sudo config apply-patch /tmp/empty_list.json")

        # Log all output
        logger.info("Command output: {}".format(result['stdout']))
        logger.info("Command error: {}".format(result['stderr']))

        # check shell command return code and output
        if result['rc'] != 0:
            AssertionError("Golden config failed YANG validation. Error: {}".format(result['stderr']))
    except Exception as e:
        pytest.fail("Failed to apply-patch due to: {}".format(e))
