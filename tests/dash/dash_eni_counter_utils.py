from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
import logging
import ast
import pytest


logger = logging.getLogger(__name__)
ENI_COUNTER_POLL_INTERVAL = 1000  # 1 second
ENI_COUNTER_READY_MAX_TIME = 10  # 10 seconds


def get_eni_counter_status(dpuhost):
    cmd_get_eni_counter_status = "sonic-db-cli FLEX_COUNTER_DB HGETALL FLEX_COUNTER_GROUP_TABLE:ENI_STAT_COUNTER"

    eni_counter_status = ast.literal_eval(dpuhost.shell(cmd_get_eni_counter_status)['stdout'])
    logger.info(f"counter eni name map:{eni_counter_status} ")
    return eni_counter_status


def set_eni_counter_status(dpuhost, status):
    cmd_enable_eni_counter = f"sudo counterpoll eni {status}"
    dpuhost.shell(cmd_enable_eni_counter)


def set_eni_counter_interval(dpuhost, interval):
    cmd_enable_eni_counter = f"sudo counterpoll eni interval {interval}"
    dpuhost.shell(cmd_enable_eni_counter)


def get_eni_counter_oid(dpuhost, eni):

    cmd_get_counter_eni_name_map = "sonic-db-cli COUNTERS_DB HGETALL 'COUNTERS_ENI_NAME_MAP'"

    counter_eni_name_map = dpuhost.shell(cmd_get_counter_eni_name_map)['stdout']
    counter_eni_name_map = ast.literal_eval(counter_eni_name_map)
    logger.info(f"counter eni name map:{counter_eni_name_map} ")
    return counter_eni_name_map[eni]


def get_eni_counters(dpuhost, eni_counter_oid):
    cmd_get_eni_counter = f"sonic-db-cli COUNTERS_DB hgetall COUNTERS:{eni_counter_oid}"
    dash_counter_dict = dpuhost.shell(cmd_get_eni_counter)['stdout']
    dash_counter_dict = ast.literal_eval(dash_counter_dict)
    return dash_counter_dict


def verify_eni_counter(eni_counter_check_point_dict, eni_counter_before_sending_pkt, eni_counter_after_sending_pkt):
    with allure.step("Verify eni counter"):
        eni_counter_mismatch_expected_diff = {}

        logger.info(f"eni_counter_check_point_dict:{eni_counter_check_point_dict}")
        for eni_counter_key, expected_diff_value in eni_counter_check_point_dict.items():
            after_value = int(eni_counter_after_sending_pkt.get(eni_counter_key))
            before_value = int(eni_counter_before_sending_pkt.get(eni_counter_key))
            if after_value - before_value != expected_diff_value:
                eni_counter_mismatch_expected_diff[eni_counter_key] = {"before": before_value, "after": after_value}
        assert not eni_counter_mismatch_expected_diff, \
            f"The eni counter change does not meet the expected one. " \
            f"eni_counter_mismatch_expected_diff: {eni_counter_mismatch_expected_diff}"
        return True


@pytest.fixture(scope="module")
def eni_counter_setup(dpuhost):
    original_eni_counter_status = get_eni_counter_status(dpuhost)
    if original_eni_counter_status.get("FLEX_COUNTER_STATUS") != "enable":
        logger.info("enable eni counter")
        set_eni_counter_status(dpuhost, "enable")

    logger.info(f"set eni counter interval: {ENI_COUNTER_POLL_INTERVAL}")
    set_eni_counter_interval(dpuhost, ENI_COUNTER_POLL_INTERVAL)

    yield

    logger.info(f"set eni counter interval: {original_eni_counter_status.get('POLL_INTERVAL')}")
    set_eni_counter_interval(dpuhost, original_eni_counter_status.get('POLL_INTERVAL'))

    if original_eni_counter_status.get("FLEX_COUNTER_STATUS") != "enable":
        logger.info("enable eni counter")
        set_eni_counter_status(dpuhost, "disable")
