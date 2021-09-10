import pytest
import logging
from jinja2 import Template

logger = logging.getLogger(__name__)


def _backup_and_restore_config_db(duts, scope='function'):
    """Back up the existing config_db.json file and restore it once the test ends.

    Some cases will update the running config during the test and save the config
    to be recovered aftet reboot. In such a case we need to backup config_db.json before
    the test starts and then restore it after the test ends.
    """
    CONFIG_DB = "/etc/sonic/config_db.json"
    CONFIG_DB_BAK = "/etc/sonic/config_db.json.before_test_{}".format(scope)

    if type(duts) is not list:
        duthosts = [duts]
    else:
        duthosts = duts

    for duthost in duthosts:
        logger.info("Backup {} to {} on {}".format(CONFIG_DB, CONFIG_DB_BAK, duthost.hostname))
        duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))

    yield

    for duthost in duthosts:
        logger.info("Restore {} with {} on {}".format(CONFIG_DB, CONFIG_DB_BAK, duthost.hostname))
        duthost.shell("mv {} {}".format(CONFIG_DB_BAK, CONFIG_DB))


@pytest.fixture(scope="module")
def backup_and_restore_config_db_on_duts(duthosts):
    """
    A module level fixture to backup and restore config_db.json on all duts
    """
    for func in _backup_and_restore_config_db(duthosts, "module"):
        yield func


@pytest.fixture
def backup_and_restore_config_db(duthosts, rand_one_dut_hostname):
    """Back up and restore config DB at the function level."""
    duthost = duthosts[rand_one_dut_hostname]
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost, "function"):
        yield func


@pytest.fixture(scope="module")
def backup_and_restore_config_db_module(duthosts, rand_one_dut_hostname):
    """Back up and restore config DB at the module level."""
    duthost = duthosts[rand_one_dut_hostname]
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost, "module"):
        yield func

@pytest.fixture(scope="session")
def backup_and_restore_config_db_session(duthosts):

    for func in _backup_and_restore_config_db(duthosts, "session"):
        yield func


def _disable_route_checker(duthost):
    """
        Some test cases will add static routes for test, which may trigger route_checker
        to report error. This function is to disable route_checker before test, and recover it
        after test.

        Args:
            duthost: DUT fixture
    """
    duthost.command('monit stop routeCheck', module_ignore_errors=True)
    yield
    duthost.command('monit start routeCheck', module_ignore_errors=True)


@pytest.fixture
def disable_route_checker(duthosts, rand_one_dut_hostname):
    """
    Wrapper for _disable_route_checker, function level
    """
    duthost = duthosts[rand_one_dut_hostname]
    for func in _disable_route_checker(duthost):
        yield func


@pytest.fixture(scope='module')
def disable_route_checker_module(duthosts, rand_one_dut_hostname):
    """
    Wrapper for _disable_route_checker, module level
    """
    duthost = duthosts[rand_one_dut_hostname]
    for func in _disable_route_checker(duthost):
        yield func

@pytest.fixture(scope='module')
def disable_fdb_aging(duthost):
    """
    Disable fdb aging by swssconfig.
    The original config will be recovered after running test.
    """
    switch_config = """[
    {
        "SWITCH_TABLE:switch": {
            "ecmp_hash_seed": "0",
            "lag_hash_seed": "0",
            "fdb_aging_time": "{{ aging_time }}"
        },
        "OP": "SET"
    }
    ]"""
    TMP_SWITCH_CONFIG_FILE = "/tmp/switch_config.json"
    DST_SWITCH_CONFIG_FILE = "/switch_config.json"
    switch_config_template = Template(switch_config)
    duthost.copy(content=switch_config_template.render(aging_time=0),
                 dest=TMP_SWITCH_CONFIG_FILE)
    # Generate and load config with swssconfig
    cmds = [
        "docker cp {} swss:{}".format(TMP_SWITCH_CONFIG_FILE, DST_SWITCH_CONFIG_FILE),
        "docker exec -i swss swssconfig {}".format(DST_SWITCH_CONFIG_FILE)
    ]
    duthost.shell_cmds(cmds=cmds)
 
    yield
    # Recover default aging time
    DEFAULT_SWITCH_CONFIG_FILE = "/etc/swss/config.d/switch.json"
    cmds = [
        "docker exec -i swss rm {}".format(DST_SWITCH_CONFIG_FILE),
        "docker exec -i swss swssconfig {}".format(DEFAULT_SWITCH_CONFIG_FILE)
    ]
    duthost.shell_cmds(cmds=cmds)
    duthost.file(path=TMP_SWITCH_CONFIG_FILE, state="absent")
