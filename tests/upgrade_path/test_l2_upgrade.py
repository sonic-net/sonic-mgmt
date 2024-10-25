import pytest
import logging

from tests.common import config_reload, reboot
from tests.common.gu_utils import (
    create_checkpoint,
    delete_checkpoint,
    rollback_or_reload,
)
from tests.common.helpers.upgrade_helpers import check_sonic_version, install_sonic
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

logger = logging.getLogger(__name__)

CONFIG_DB = "/etc/sonic/config_db.json"


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for each loopback interface test.
    rollback to check if it goes back to starting config

    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def get_from_and_to_image(request):
    """
    Get the from and to image for the test case from input options.
    See conftest.py for the options.

    Args:
        request: The request object from the test case.

    Returns:
        tuple: A tuple containing the from and to image.
    """
    from_image = request.config.getoption("base_image_list")
    to_image = request.config.getoption("target_image_list")
    return from_image, to_image


def test_l2_config_and_upgrade(
    duthosts, localhost, rand_one_dut_hostname, get_from_and_to_image, tbinfo
):
    """
    Test the database migration from one image to another.

    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
        get_from_and_to_image: The fixture returns the from and to image.
        tbinfo: The testbed information.
    """
    duthost = duthosts[rand_one_dut_hostname]
    from_image, to_image = get_from_and_to_image
    mgmt_fact = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_mgmt_interface"]

    logger.info(
        "Test l2 configuration while upgrating from {} to {}".format(
            from_image, to_image
        )
    )
    # Install base image
    logger.info("Installing {}".format(from_image))
    install_sonic(duthost, from_image, tbinfo)

    logger.info("Configuring L2 switch mode.")
    L2_INIT_CFG = "/tmp/l2_init_config.json"
    duthost.shell(
        "sudo sonic-cfggen --preset l2 -p -H -k {} > {}".format(
            duthost.facts["hwsku"], L2_INIT_CFG
        )
    )
    MGMT_CFG = "/tmp/mgmt_cfg.json"
    gen_mgmt_cfg = """
    echo '
    {{
        "MGMT_INTERFACE": {{
            "eth0|{}/{}": {{
                "gwaddr": "{}"
            }}
        }},
        "DEVICE_METADATA": {{
            "localhost": {{
                "hostname": "{}"
            }}
        }},
        "MGMT_PORT": {{
            "eth0": {{
                "admin_status": "up",
                "alias": "eth0"
            }}
        }}
    }}' > {}
    """.format(
        mgmt_fact["addr"],
        mgmt_fact["prefixlen"],
        mgmt_fact["gwaddr"],
        duthost.hostname,
        MGMT_CFG,
    )
    duthost.shell(gen_mgmt_cfg)
    duthost.shell(
        "sudo jq -s '.[0] * .[1]' {} {} > {}".format(L2_INIT_CFG, MGMT_CFG, CONFIG_DB)
    )
    config_reload(duthost)
    wait_critical_processes(duthost)

    # Install target image
    target_version = install_sonic(duthost, to_image, tbinfo)
    # This is a hack! install_sonic deletes /host/old_config/config_db.json if minigraph.xml exists to
    # force the next reboot to load minigraph from scratch, which defeats the purpose of this test (to test
    # db migration during upgrade). So we need to restore the config_db.json file here.
    duthost.shell("cp /etc/sonic/config_db.json /host/old_config/config_db.json")

    # Upgrade to target image
    logger.info("Upgrading to {}".format(to_image))
    reboot(duthost, localhost, reboot_type="cold")

    # Check no hardcoded table is present in the new config_db.json
    logger.info("Upgraded from {} to {} is successful".format(from_image, to_image))
    check_sonic_version(duthost, target_version)
    for table in ["TELEMETRY", "RESTAPI"]:
        assert (
            # Use "|| true" to ignore non-zero return code, which is expected.
            int(duthost.shell("grep -c {} /etc/sonic/config_db.json || true".format(table))["stdout"]) == 0
        )
