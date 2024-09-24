"""
Tests related to L2 configuration
"""
import logging
import pytest

from tests.common import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert

CONFIG_DB = '/etc/sonic/config_db.json'
CONFIG_DB_BAK = '/etc/sonic/config_db.json.bak'
TARGET_IMG_LOCALHOST = '/var/tmp/target_sonic_localhost.bin'
TARGET_IMG_DUTHOST = '/var/tmp/target_sonic_duthost.bin'

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_l2_config_and_upgrade(request, duthosts, rand_one_dut_hostname, localhost):
    """
    @summary: A testcase that verifies DB migrator does not add bad data.
        1. Cold reboot.
        2. Configure switch into L2 mode.
        3. Install a new image.
        4. Reboot into the new image. DB migrator does its work.
        5. Verify.

    Args:
        request: From pytest.
        duthosts: set of DUTs.
        rand_one_duthostname: sample a random DUT.
        localhost: localhost object.
        tbinfo: testbed info
    """
    # Setup.
    duthost = duthosts[rand_one_dut_hostname]
    hwsku = duthost.facts["hwsku"]

    # Get target image path:
    target_image = request.config.getoption('target_image', default=None)
    if target_image is None:
        pytest.skip("Skipping test due to missing --target_image.")
    init_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']

    # Step 1: Reboot.
    reboot(duthost, localhost, reboot_type="cold")

    # Step 2: Configure DUT into L2 mode.
    # Save original config
    duthost.shell("sudo cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))
    # Perform L2 configuration
    l2_cfg = "sudo sonic-cfggen --preset l2 -p -H -k {}" \
        " | sudo config load /dev/stdin -y".format(hwsku)
    duthost.shell(l2_cfg)
    duthost.shell("sudo config qos reload --no-dynamic-buffer")
    duthost.shell("sudo config save -y")

    # Step 3: Install new image and reboot.
    init_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
    logger.info("Init image: {}".format(init_img))
    localhost.get_url(url=target_image, dest=TARGET_IMG_LOCALHOST)
    duthost.copy(src=TARGET_IMG_LOCALHOST, dest=TARGET_IMG_DUTHOST)
    duthost.shell("sudo sonic-installer install -y {}".format(TARGET_IMG_DUTHOST))
    reboot(duthost, localhost, reboot_type="cold")
    new_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
    logger.info("New image: {}".format(new_img))

    # Step 4: Verifies no config fro minigraph is written into ConfigDB.
    try:
        for table in ["TELEMETRY", "RESTAPI", "DEVICE_METADATA"]:
            count = int(duthost.shell('redis-cli --scan --pattern "{}*" | wc -l'.format(table))['stdout'])
            pytest_assert(count == 0, "{} table is not empty!".format(table))
    except Exception:
        raise
    finally:
        # Restore from L2 and new images, restore image first.
        duthost.shell("sudo sonic-installer set-next-boot {}".format(init_img))
        reboot(duthost, localhost, reboot_type="cold")
        cur_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
        logger.info("Current image: {}".format(cur_img))
        duthost.shell("sudo cp {} {}".format(CONFIG_DB_BAK, CONFIG_DB))
        config_reload(duthost)
        duthost.shell("sudo rm {}".format(CONFIG_DB_BAK))
