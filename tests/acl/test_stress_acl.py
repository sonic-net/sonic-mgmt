import logging
import pytest
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

LOOP_TIMES_LEVEL_MAP = {
    'debug': 10,
    'basic': 500,
    'confident': 5000
}

# Template json file used to test scale rules
STRESS_ACL_TABLE_TEMPLATE = "acl/templates/acltb_test_stress_acl_table.j2"
STRESS_ACL_RULE_TEMPLATE = "acl/templates/acltb_test_stress_acl_rules.j2"
STRESS_ACL_BASH_TEMPLATE = "acl/templates/acltb_test_stress_acl.sh"
STRESS_ACL_TABLE_JSON_FILE = "/tmp/acltb_test_stress_acl_table.json"
STRESS_ACL_RULE_JSON_FILE = "/tmp/acltb_test_stress_acl_rules.json"
STRESS_ACL_BASH_FILE = "/tmp/acltb_test_stress_acl.sh"
STRESS_ACL_BASH_LOG_FILE = "/tmp/acltb_test_stress_acl.log"

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_RULE_FAILED_RE = ".*Failed to create ACL rule.*"


@pytest.fixture(scope='module')
def setup_stress_acl_table(rand_selected_dut):
    # Define a custom table type CUSTOM_TYPE by loading a json configuration
    rand_selected_dut.template(src=STRESS_ACL_TABLE_TEMPLATE, dest=STRESS_ACL_TABLE_JSON_FILE)
    rand_selected_dut.shell("sonic-cfggen -j {} -w".format(STRESS_ACL_TABLE_JSON_FILE))
    # Create an ACL table and bind to Vlan1000 interface
    cmd_create_table = "config acl add table STRESS_ACL L3 -s ingress -p PortChannel101"
    cmd_remove_table = "config acl remove table STRESS_ACL"
    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="stress_acl")
    loganalyzer.load_common_config()

    try:
        logger.info("Creating ACL table STRESS_ACL with type L3")
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
        # Ignore any other errors to reduce noise
        loganalyzer.ignore_regex = [r".*"]
        with loganalyzer:
            rand_selected_dut.shell(cmd_create_table)
    except LogAnalyzerError as err:
        # Cleanup Config DB if table creation failed
        logger.error("ACL table creation failed, attempting to clean-up...")
        rand_selected_dut.shell(cmd_remove_table)
        raise err

    yield
    logger.info("Removing ACL table STRESS_ACL")
    # Remove ACL table
    rand_selected_dut.shell(cmd_remove_table)


@pytest.fixture(scope='module')
def setup_stress_acl_rules(rand_selected_dut, setup_stress_acl_table):
    # Copy and load acl rules
    rand_selected_dut.template(src=STRESS_ACL_RULE_TEMPLATE, dest=STRESS_ACL_RULE_JSON_FILE)
    cmd_add_rules = "sonic-cfggen -j {} -w".format(STRESS_ACL_RULE_JSON_FILE)
    cmd_rm_rules = "acl-loader delete STRESS_ACL"

    loganalyzer = LogAnalyzer(ansible_host=rand_selected_dut, marker_prefix="stress_acl")
    loganalyzer.match_regex = [LOG_EXPECT_ACL_RULE_FAILED_RE]
    try:
        logger.info("Creating ACL rules in STRESS_ACL")
        with loganalyzer:
            rand_selected_dut.shell(cmd_add_rules)
    except LogAnalyzerError as err:
        # Cleanup Config DB if failed
        logger.error("ACL rule creation failed, attempting to clean-up...")
        rand_selected_dut.shell(cmd_rm_rules)
        raise err
    yield
    # Remove testing rules
    logger.info("Removing testing ACL rules")
    rand_selected_dut.shell(cmd_rm_rules)


def test_acl_add_del_stress(rand_selected_dut, setup_stress_acl_rules, get_function_conpleteness_level,
                            toggle_all_simulator_ports_to_rand_selected_tor):   # noqa F811

    rand_selected_dut.shell("config acl add table -p PortChannel101,PortChannel102,PortChannel103,PortChannel104 \
                            IP_STRESS_ACL L3")
    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = 'debug'
    loop_time = LOOP_TIMES_LEVEL_MAP[normalized_level]

    with open(STRESS_ACL_BASH_TEMPLATE, 'r') as f:
        file_data = ""
        for line in f:
            if "loop_times=" in line:
                line = "loop_times={}\n".format(loop_time)
            file_data += line
    with open(STRESS_ACL_BASH_TEMPLATE, 'w') as f:
        f.write(file_data)

    rand_selected_dut.template(src=STRESS_ACL_BASH_TEMPLATE, dest=STRESS_ACL_BASH_FILE)
    rand_selected_dut.shell("bash {} > {}".format(STRESS_ACL_BASH_FILE, STRESS_ACL_BASH_LOG_FILE))
    rand_selected_dut.fetch(src=STRESS_ACL_BASH_LOG_FILE, dest="logs/")

    cmd_remove_table = "config acl remove table STRESS_ACL"
    rand_selected_dut.shell(cmd_remove_table)

    logger.info("End")
