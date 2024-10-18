"""
Tests related to L2 configuration
"""
import logging
import pytest

from tests.common import reboot
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.upgrade_helpers import install_sonic

CONFIG_DB = '/etc/sonic/config_db.json'
CONFIG_DB_BAK = '/etc/sonic/config_db.json.bak'
TARGET_IMG_LOCALHOST = '/var/tmp/target_sonic_localhost.bin'
TARGET_IMG_DUTHOST = '/var/tmp/target_sonic_duthost.bin'

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


def test_l2_config_and_upgrade(request, duthosts, rand_one_dut_hostname, localhost, tbinfo):
    """
    @summary: A testcase that verifies DB migrator does not add unnecessary data.

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
    mgmt_fact = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_mgmt_interface"]
    source_image = request.config.getoption('source_image', default=None)
    target_image = request.config.getoption('target_image', default=None)
    
    # Step 1: (Install source image and) reboot
    if source_image:
        install_sonic(duthost, source_image, tbinfo)
    reboot(duthost, localhost, reboot_type="cold")
    init_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']

    # Step 2: Install target image
    if target_image:
        # This API does not work in L2 configured switch.
        install_sonic(duthost, target_image, tbinfo)

    def _verify_config_db(duthost):
        for table in ["TELEMETRY", "RESTAPI"]:
            # grep returns 1 when there is no match, use || true to override that.
            count = int(duthost.shell('sonic-db-cli CONFIG_DB KEYS "{}|*" | grep -c "^{}" || true'.format(table, table))['stdout'])
            pytest_assert(count == 0, "{} table is not empty!".format(table))

    # Step 3: Configure DUT into L2 mode.
    # Save original config
    duthost.shell("sudo cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))
    # Perform L2 configuration
    init_cfg = '''
    cat <<EOF | sudo config reload /dev/stdin -y
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
        }}
    }}
    '''.format(mgmt_fact["addr"], mgmt_fact["prefixlen"], mgmt_fact["gwaddr"], duthost.hostname)
    duthost.shell(init_cfg)
    l2_cfg = "sudo sonic-cfggen --preset l2 -p -H -k {}" \
        " | sudo config load /dev/stdin -y".format(hwsku)
    duthost.shell(l2_cfg)
    duthost.shell("sudo config qos reload --no-dynamic-buffer")
    duthost.shell("sudo config save -y")
    try:
        _verify_config_db(duthost)
    except pytest.fail.Exception as e:
        pytest.skip("Unable to clear minigraph table when setting up L2 config for current image. Skipping the test.")

    # Step 4: Reboot to target image.
    reboot(duthost, localhost, reboot_type="cold")
    new_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
    logger.info("New image: {}".format(new_img))

    # Step 5: Verifies no config from minigraph is written into ConfigDB.
    try:
        _verify_config_db(duthost)
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
