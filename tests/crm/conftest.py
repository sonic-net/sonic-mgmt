import pytest
import time
import json
import logging

from test_crm import RESTORE_CMDS, CRM_POLLING_INTERVAL
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)


def pytest_runtest_teardown(item, nextitem):
    """ called after ``pytest_runtest_call``.

    :arg nextitem: the scheduled-to-be-next test item (None if no further
                   test item is scheduled).  This argument can be used to
                   perform exact teardowns, i.e. calling just enough finalizers
                   so that nextitem only needs to call setup-functions.
    """
    failures = []
    crm_threshold_name = RESTORE_CMDS.get("crm_threshold_name")
    restore_cmd = "bash -c \"sonic-db-cli CONFIG_DB hset 'CRM|Config' {threshold_name}_threshold_type percentage \
    && sonic-db-cli CONFIG_DB hset 'CRM|Config' {threshold_name}_high_threshold {high} \
    && sonic-db-cli CONFIG_DB hset 'CRM|Config' {threshold_name}_low_threshold {low}\""
    if item.rep_setup.passed and not item.rep_call.skipped:
        # Restore CRM threshods
        if crm_threshold_name:
            crm_thresholds = item.funcargs["crm_thresholds"]
            cmd = restore_cmd.format(threshold_name=crm_threshold_name, high=crm_thresholds[crm_threshold_name]["high"],
                low=crm_thresholds[crm_threshold_name]["low"])
            logger.info("Restore CRM thresholds. Execute: {}".format(cmd))
            # Restore default CRM thresholds
            item.funcargs["duthost"].command(cmd)

        test_name = item.function.func_name
        duthosts = item.funcargs['duthosts']
        hostname = item.funcargs['enum_rand_one_per_hwsku_frontend_hostname']
        dut = None
        if duthosts and hostname: # unable to test hostname in duthosts
            dut = duthosts[hostname]

        if not dut:
            dut = item.funcargs['duthost']
            logger.warning('fallback to use duthost {} instead from {} {}'.format(dut.hostname, duthosts, hostname))
            hostname = dut.hostname

        logger.info("Execute test cleanup: dut {} {}".format(hostname, json.dumps(RESTORE_CMDS, indent=4)))
        # Restore DUT after specific test steps
        # Test case name is used to mitigate incorrect cleanup if some of tests was failed on cleanup step and list of
        # cleanup commands was not cleared
        for cmd in RESTORE_CMDS[test_name]:
            logger.info(cmd)
            try:
                dut.shell(cmd)
            except RunAnsibleModuleFail as err:
                failures.append("Failure during command execution '{command}':\n{error}".format(command=cmd,
                    error=str(err)))

        RESTORE_CMDS[test_name] = []

        if RESTORE_CMDS["wait"]:
            logger.info("Waiting {} seconds to process cleanup...".format(RESTORE_CMDS["wait"]))
            time.sleep(RESTORE_CMDS["wait"])

        if failures:
            message = "\n".join(failures)
            pytest.fail(message)


@pytest.fixture(scope="module", autouse=True)
def crm_thresholds(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cmd = "sonic-db-cli CONFIG_DB hget \"CRM|Config\" {threshold_name}_{type}_threshold"
    crm_res_list = ["ipv4_route", "ipv6_route", "ipv4_nexthop", "ipv6_nexthop", "ipv4_neighbor",
        "ipv6_neighbor", "nexthop_group_member", "nexthop_group", "acl_counter", "acl_entry", "fdb_entry"]
    res = {}
    for item in crm_res_list:
        high = duthost.command(cmd.format(threshold_name=item, type="high"))["stdout_lines"][0]
        low = duthost.command(cmd.format(threshold_name=item, type="low"))["stdout_lines"][0]
        res[item] = {}
        res[item]["high"] = high
        res[item]["low"] = low

    return res


@pytest.fixture(scope="function", autouse=True)
def crm_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, enum_frontend_asic_index):
    """ Return tuple of two DUT interfaces """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    if len(mg_facts["minigraph_portchannel_interfaces"]) >= 4:
        crm_intf1 = mg_facts["minigraph_portchannel_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_portchannel_interfaces"][2]["attachto"]
    else:
        crm_intf1 = mg_facts["minigraph_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_interfaces"][2]["attachto"]
    yield (crm_intf1, crm_intf2)


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """ Set CRM polling interval to 1 second """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))["stdout"]
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


@pytest.fixture(scope="module")
def collector(duthosts, rand_one_dut_hostname):
    """ Fixture for sharing variables beatween test cases """
    duthost = duthosts[rand_one_dut_hostname]
    data = {}
    for asic in duthost.asics:
        data[asic.asic_index] = {}

    yield data
