from tests.common.snappi_tests.snappi_fixtures import (                           # noqa: F401
    snappi_api, snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from tests.snappi_tests.bgp.files.bgp_convergence_helper import run_rib_in_convergence_test
from tests.common.fixtures.conn_graph_facts import (                        # noqa: F401
    conn_graph_facts, fanout_graph_facts)
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
import time
import json
import logging
import os
import tempfile
import pytest
import yaml

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]

# Test parameters (not from files)
MULTIPATH = 1
CONVERGENCE_TEST_ITERATIONS = 1
NUMBER_OF_ROUTES = 250000
RIB_TIMEOUT = 50

CONTAINER = 'swss'
ORCHAGENT_PATH = "/usr/bin/orchagent.sh"
CONFIG_DB_BACKUP_PATH = "/etc/sonic/config_db_rib_combo_v1_backup.json"

_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


def _load_fine_tunings():
    yml_path = os.path.join(_FILES_DIR, 'fine-tunings.yml')
    with open(yml_path, 'r') as f:
        return yaml.safe_load(f)


def _load_bk_pairs():
    """Load (bulk, batch) pairs from bk_values.json.
    Each pair is [bulk_value, batch_value] for orchagent -b and -k.
    Supports legacy: single list -> same value for both; or bulk_values+batch_values -> zip.
    """
    json_path = os.path.join(_FILES_DIR, 'bk_values.json')
    with open(json_path, 'r') as f:
        data = json.load(f)
    if isinstance(data, list):
        return [[v, v] for v in data]
    if 'pairs' in data:
        return data['pairs']
    return list(zip(data['bulk_values'], data['batch_values']))

# To load fine-tuning parameters from files/fine-tunings.yml file.
try:
    _FINE_TUNINGS = _load_fine_tunings() or {}
except Exception:
    _FINE_TUNINGS = {}

# To load bk-values from files/bk_values.json file if present,else load following defaults.
try:
    _BK_PAIRS = _load_bk_pairs()
except Exception:
    _BK_PAIRS = [['default', 'default'], [5000, 5000], [10000, 10000], [15000, 15000], [20000, 20000]]

PROFILE_NAMES = [
    name for name, cfg in _FINE_TUNINGS.items()
    if isinstance(cfg, dict) and 'DEVICE_METADATA' in cfg
]
if not PROFILE_NAMES:
    PROFILE_NAMES = ['_no_profile_']


def _apply_bk_value(duthost, bulk_value, batch_value):
    logger.info('Applying bulk (b):%s, batch (k):%s', bulk_value, batch_value)
    duthost.shell(
        "docker exec -i {} cp {} {}.bak".format(CONTAINER, ORCHAGENT_PATH, ORCHAGENT_PATH)
    )
    if bulk_value != 'default' or batch_value != 'default':
        duthost.shell(
            r"docker exec -i {} sed -i 's/ORCHAGENT_ARGS+=\"-b 1024 \"/ORCHAGENT_ARGS+=\"-b {} -k {} \"/' {}".format(
                CONTAINER, bulk_value, batch_value, ORCHAGENT_PATH
            )
        )


def _revert_bk_value(duthost):
    logger.info('Reverting orchagent.sh from backup')
    duthost.shell(
        "docker exec -i {} cp {}.bak {}".format(CONTAINER, ORCHAGENT_PATH, ORCHAGENT_PATH),
        module_ignore_errors=True
    )


def _get_config_db(duthost):
    out = duthost.shell("cat /etc/sonic/config_db.json")['stdout']
    return json.loads(out)


def _apply_config_db_profile(duthost, profile_config, original_config):
    config = json.loads(json.dumps(original_config))
    if 'DEVICE_METADATA' not in config:
        config['DEVICE_METADATA'] = {}
    if 'localhost' not in config['DEVICE_METADATA']:
        config['DEVICE_METADATA']['localhost'] = {}
    meta = profile_config.get('DEVICE_METADATA', {}).get('localhost', {})
    config['DEVICE_METADATA']['localhost'].update(meta)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=4)
        tmp_path = f.name
    try:
        duthost.copy(src=tmp_path, dest='/etc/sonic/config_db.json')
    finally:
        os.unlink(tmp_path)


def _revert_config_db(duthost):
    duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(CONFIG_DB_BACKUP_PATH))
    duthost.shell("sudo config reload -y")
    pytest_assert(
        wait_until(360, 10, 1, duthost.critical_services_fully_started),
        "Not all critical services are fully started after config revert"
    )
    duthost.shell("sudo rm -f {}".format(CONFIG_DB_BACKUP_PATH), module_ignore_errors=True)


@pytest.fixture
def dut_ready_for_rib_combo(duthost, localhost, profile_name, bulk_value, batch_value):
    """
    Setup: save config_db backup on DUT, apply profile, apply bulk/batch (-b/-k), reboot, wait.
    Teardown: revert config_db from backup, revert orchagent.
    Memory utilization plugin captures before_test after this setup (same boot as after_test).
    """
    if profile_name == '_no_profile_':
        pytest.skip("No valid profiles in fine-tunings.yml")

    profile_config = _FINE_TUNINGS[profile_name]
    original_config = _get_config_db(duthost)
    duthost.shell("sudo cp /etc/sonic/config_db.json {}".format(CONFIG_DB_BACKUP_PATH))

    logger.info('Fixture: applying profile=%s, bulk_value=%s, batch_value=%s',
                profile_name, bulk_value, batch_value)
    _apply_config_db_profile(duthost, profile_config, original_config)
    _apply_bk_value(duthost, bulk_value, batch_value)
    logger.info('Fixture: rebooting DUT')
    reboot(duthost, localhost, reboot_type='cold', return_after_reconnect=True)
    pytest_assert(
        wait_until(360, 10, 1, duthost.critical_services_fully_started),
        "Not all critical services are fully started"
    )

    yield

    # Added sleep of 2 mins so that revert config has time in case of pytest.skip
    time.sleep(120)
    logger.info('Fixture teardown: reverting config_db and orchagent')
    _revert_config_db(duthost)
    _revert_bk_value(duthost)


@pytest.mark.parametrize('profile_name', PROFILE_NAMES)
@pytest.mark.parametrize('bulk_value,batch_value', _BK_PAIRS)
@pytest.mark.parametrize('route_type', ['IPv4', 'IPv6', 'IPv4v6'])
def test_rib_route_opt_perf(snappi_api,                    # noqa: F811
                            duthost,
                            tgen_ports,                 # noqa: F811
                            conn_graph_facts,           # noqa: F811
                            fanout_graph_facts,         # noqa: F811
                            dut_ready_for_rib_combo,    # fixture: apply profile + bulk/batch + reboot
                            profile_name,
                            bulk_value,
                            batch_value,
                            memory_utilization,
                            route_type,):
    """
    Run RIB-IN convergence test for one (profile, bulk_value, batch_value, route_type).
    DUT is already prepared by dut_ready_for_rib_combo (same boot); memory_utilization
    before/after are from the same boot and comparable.

    This allows tests.common.plugins.memory_utilization to capture before_test (after
    fixture setup/reboot) and after_test (after convergence test) on the same boot,
    giving a meaningful memory delta.

    Profiles and (bulk, batch) pairs are parameterized from files/fine-tunings.yml and
    files/bk_values.json (pairs; same as test_bgp_rib_in_combo).

    """
    if profile_name == '_no_profile_':
        pytest.skip("No valid profiles in fine-tunings.yml")

    if route_type == 'IPv4v6':
        pytest.skip("Skipping test for route_type IPv4v6")

    memory_monitors, memory_values = memory_utilization
    monitor = memory_monitors[duthost.hostname]

    # Override thresholds for this test (before teardown runs)
    for name, cmd, memory_params, memory_check_fn in monitor.commands:
        if name == 'frr_bgp':
            if 'used' in memory_params:
                memory_params['used']['memory_high_threshold'] = {"type": "value", "value": 512}
                continue
        if name == 'top':
            if 'bgpd' in memory_params:
                memory_params['bgpd']['memory_increase_threshold'] = {"type": "value", "value": 512}
            if 'zebra' in memory_params:
                memory_params['zebra']['memory_increase_threshold'] = {"type": "value", "value": 512}
            continue
        if name == 'free':
            if 'used' in memory_params:
                memory_params['used']['memory_increase_threshold'] = {"type": "percentage", "value": "30%"}  # or another limit
            continue 

    logger.info('Profile=%s, bulk_value=%s, batch_value=%s, route_type=%s',
                profile_name, bulk_value, batch_value, route_type)

    logger.info('Running RIB-IN convergence test')

    run_rib_in_convergence_test(snappi_api,
                                duthost,
                                tgen_ports,
                                CONVERGENCE_TEST_ITERATIONS,
                                MULTIPATH,
                                NUMBER_OF_ROUTES,
                                route_type,
                                timeout=RIB_TIMEOUT,
                                skip_cleanup=True)
