"""
Tests related to L2 configuration
"""
import logging
import pytest

from tests.common import reboot, config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.upgrade_helpers import install_sonic

CONFIG_DB = '/etc/sonic/config_db.json'
CONFIG_DB_BAK = '/etc/sonic/config_db.json.bak'
MINIGRAPH = '/etc/sonic/minigraph.xml'
MINIGRAPH_BAK = '/etc/sonic/minigraph.xml.bak'

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


def test_l2_config_and_upgrade(request, duthosts, rand_one_dut_hostname, localhost, tbinfo):
    """
    @summary: A testcase that verifies DB migrator does not add unnecessary data during upgrade.

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
    if target_image is None:
        pytest.skip("Must specify a target image through --target_image. Skipping the test.")
    
    # Step 1: (Install source image and) reboot
    if source_image:
        install_sonic(duthost, source_image, tbinfo)
    reboot(duthost, localhost, reboot_type="cold")
    init_img = duthost.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "')['stdout']

    def _verify_config_db(duthost):
        for table in ["TELEMETRY", "RESTAPI"]:
            # grep returns 1 when there is no match, use || true to override that.
            count = int(duthost.shell('grep -c {} /etc/sonic/config_db.json || true'.format(table))['stdout'])
            pytest_assert(count == 0, "{} table is not empty!".format(table))

    # Step 2: Configure DUT into L2 mode.
    # Save original config
    duthost.shell("sudo cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))
    # Perform L2 configuration
    L2_INIT_CFG_FILE = '/tmp/init_l2_cfg.json'
    MGMT_CFG_FILE = '/tmp/mgmt_cfg.json'
    L2_CFG_FILE = '/tmp/l2_cfg.json'
    gen_l2_cfg = "sudo sonic-cfggen --preset l2 -p -H -k {} > {}".format(hwsku, L2_INIT_CFG_FILE)
    duthost.shell(gen_l2_cfg)
    gen_mgmt_cfg = '''
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
    '''.format(mgmt_fact["addr"], mgmt_fact["prefixlen"], mgmt_fact["gwaddr"], duthost.hostname, MGMT_CFG_FILE)
    duthost.shell(gen_mgmt_cfg)
    duthost.shell("jq -s '.[0] * .[1]' {} {} > {}".format(L2_INIT_CFG_FILE, MGMT_CFG_FILE, L2_CFG_FILE))
    duthost.shell("sudo cp {} {}".format(L2_CFG_FILE, CONFIG_DB))
    config_reload(duthost)
    wait_critical_processes(duthost)
    try:
        _verify_config_db(duthost)
    except pytest.fail.Exception as e:
        pytest.skip("Unable to clear minigraph table when setting up L2 config for current image. Skipping the test.")

    # Step 3: Install target image.
    if target_image:
        # This is a hack: install_sonic thinks the device is configured with minigraph if minigraph.xml is present 
        # in the old config and will attempt to force the device to load_minigraph after reboot.
        # Remove old minigraph.xml to prevent that.
        # See ansible/library/reduce_and_add_sonic_images.py
        minigraph_back_up = True
        duthost.shell("sudo mv {} {}".format(MINIGRAPH, MINIGRAPH_BAK))
        # After configuration to L2 switch, target no longer support url download.
        install_sonic(duthost, target_image, tbinfo)

    # Step 4: Reboot to target image.
    reboot(duthost, localhost, reboot_type="cold")

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
        if minigraph_back_up:
            duthost.shell("sudo cp {} {}".format(MINIGRAPH_BAK, MINIGRAPH))
            duthost.shell("sudo rm {}".format(MINIGRAPH_BAK))
        