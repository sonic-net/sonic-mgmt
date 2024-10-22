import pytest
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.bgp.constants import TS_NORMAL, TS_MAINTENANCE, TS_INCONSISTENT, TS_NO_NEIGHBORS


def verify_traffic_shift_per_asic(host, outputs, match_result, asic_index):
    prefix = "BGP{} : ".format(
        asic_index) if asic_index != DEFAULT_ASIC_ID else ''
    result_str = "{}{}".format(prefix, match_result)
    if result_str in outputs:
        return True
    else:
        false = False
        return false


def verify_traffic_shift(host, outputs, match_result):
    for asic_index in host.get_frontend_asic_ids():
        if verify_traffic_shift_per_asic(host, outputs, TS_NO_NEIGHBORS, asic_index):
            continue
        if not verify_traffic_shift_per_asic(host, outputs, match_result, asic_index):
            return "ERROR"

    return match_result


def get_traffic_shift_state(host, cmd="TSC"):
    outputs = host.shell(cmd)['stdout_lines']
    if verify_traffic_shift(host, outputs, TS_NORMAL) != "ERROR":
        return TS_NORMAL
    if verify_traffic_shift(host, outputs, TS_MAINTENANCE) != "ERROR":
        return TS_MAINTENANCE
    if verify_traffic_shift(host, outputs, TS_INCONSISTENT) != "ERROR":
        return TS_INCONSISTENT
    pytest.fail("{} return unexpected state {}".format(cmd, "ERROR"))


# API to check if the image has support for BGP_DEVICE_GLOBAL table in the configDB
def check_tsa_persistence_support(duthost):
    # For multi-asic, check DB in one of the namespaces
    asic_index = 0 if duthost.is_multi_asic else DEFAULT_ASIC_ID
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    sonic_db_cmd = "sonic-db-cli {}".format("-n " +
                                            namespace if namespace else "")
    tsa_in_configdb = duthost.shell('{} CONFIG_DB HGET "BGP_DEVICE_GLOBAL|STATE" "tsa_enabled"'.format(sonic_db_cmd),
                                    module_ignore_errors=False)['stdout_lines']
    if not tsa_in_configdb:
        return False
    return True


def check_traffic_shift_state(duthost, state):
    if state != get_traffic_shift_state(duthost):
        return False
    else:
        return True
