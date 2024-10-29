"""
Tests related to L2 configuration
"""

import logging
import pytest

from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.helpers.assertions import pytest_assert

CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BAK = "/etc/sonic/config_db.json.bak"
DUT_IMG_PATH = "/tmp/dut-sonic-img.bin"
LOCALHOST_IMG_PATH = "/tmp/localhost-sonic-img.bin"

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]


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
    duthost.shell("sudo cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))

    yield

    duthost.shell("sudo cp {} {}".format(CONFIG_DB_BAK, CONFIG_DB))
    config_reload(duthost)
    wait_critical_processes(duthost)
    duthost.shell("sudo rm -f {}".format(CONFIG_DB_BAK))


def is_table_empty(duthost, table):
    """
    @summary: Verify a table is empty.

    Args:
        duthost: DUT host object.
        table: Table name to verify.
    """
    # grep returns 1 when there is no match, use || true to override that.
    count = int(
        duthost.shell(
            'sonic-db-cli CONFIG_DB KEYS "{}|*" | grep -c {} || true'.format(
                table, table
            )
        )["stdout"]
    )
    return count == 0


def test_no_hardcoded_minigraph(duthosts, rand_one_dut_hostname, tbinfo):
    """
    @summary: A testcase asserts no hardcoded minigraph config is imported to config_db during L2 configuration.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: The fixture returns a randomly selected DuT.
        tbinfo: The testbed information. Needed for configuring management interface.

    """
    # Setup.
    duthost = duthosts[rand_one_dut_hostname]
    if is_table_empty(duthost, "TELEMETRY") or is_table_empty(duthost, "RESTAPI"):
        pytest.skip("TELEMETRY or RESTAPI table is empty. Please load minigraph first.")

    hwsku = duthost.facts["hwsku"]
    mgmt_fact = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_mgmt_interface"]

    # Step 2: Configure DUT into L2 mode.
    # Save original config
    duthost.shell("sudo cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))
    # Perform L2 configuration
    L2_INIT_CFG_FILE = "/tmp/init_l2_cfg.json"
    MGMT_CFG_FILE = "/tmp/mgmt_cfg.json"
    L2_CFG_FILE = "/tmp/l2_cfg.json"
    gen_l2_cfg = "sudo sonic-cfggen --preset l2 -p -H -k {} > {}".format(
        hwsku, L2_INIT_CFG_FILE
    )
    duthost.shell(gen_l2_cfg)
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
        MGMT_CFG_FILE,
    )
    duthost.shell(gen_mgmt_cfg)
    duthost.shell(
        "jq -s '.[0] * .[1]' {} {} > {}".format(
            L2_INIT_CFG_FILE, MGMT_CFG_FILE, L2_CFG_FILE
        )
    )
    duthost.shell("sudo cp {} {}".format(L2_CFG_FILE, CONFIG_DB))
    config_reload(duthost)
    wait_critical_processes(duthost)

    # Verify no minigraph config is present.
    for table in ["TELEMETRY", "RESTAPI"]:
        pytest_assert(
            is_table_empty(duthost, table), "{} table is not empty!".format(table)
        )
