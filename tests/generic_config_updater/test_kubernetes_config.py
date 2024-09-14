import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload


pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


# K8S config
K8SEMPTYCONFIG = []
K8SHALFCONFIG = [
    '"KUBERNETES_MASTER": {\n'
    '        "SERVER": {}\n'
    '    }'
]
K8SFULLCONFIG = [
    '"KUBERNETES_MASTER": {\n'
    '        "SERVER": {\n'
    '            "disable": "false",\n'
    '            "ip": "k8svip.ap.gbl"\n'
    '        }\n'
    '    }'
]
K8SFULLCONFIG2 = [
    '"KUBERNETES_MASTER": {\n'
    '        "SERVER": {\n'
    '            "disable": "false",\n'
    '            "ip": "k8svip2.ap.gbl"\n'
    '        }\n'
    '    }'
]
K8SEMPTYIPCONFIG = [
    '"KUBERNETES_MASTER": {\n'
    '        "SERVER": {\n'
    '            "disable": "true",\n'
    '            "ip": ""\n'
    '        }\n'
    '    }'
]


# K8S config patch
K8SEMPTYTOHALFPATCH = [
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER",
        "value": {"SERVER": {}}
    }
]
K8SHALFTOWRONGIPPATCH = [
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER/SERVER/disable",
        "value": "true"
    },
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER/SERVER/ip",
        "value": ""
    }
]
K8SHALFTOFULLPATCH = [
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER/SERVER/disable",
        "value": "false"
    },
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER/SERVER/ip",
        "value": "k8svip.ap.gbl"
    }
]
K8SFULLTOHALFPATCH = [
    {
        "op": "remove",
        "path": "/KUBERNETES_MASTER/SERVER/ip"
    },
    {
        "op": "remove",
        "path": "/KUBERNETES_MASTER/SERVER/disable"
    }
]
K8SHALFTOEMPTYPATCH = [
    {
        "op": "remove",
        "path": "/KUBERNETES_MASTER"
    }
]
K8SEMPTYTOFULLPATCH = [
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER",
        "value": {"SERVER": {"disable": "false", "ip": "k8svip.ap.gbl"}}
    }
]
K8SFULLTOFULLPATCH = [
    {
        "op": "replace",
        "path": "/KUBERNETES_MASTER/SERVER/ip",
        "value": "k8svip2.ap.gbl"
    }
]
K8SFULLTOWRONGIPPATCH = [
    {
        "op": "replace",
        "path": "/KUBERNETES_MASTER/SERVER/ip",
        "value": ""
    },
    {
        "op": "replace",
        "path": "/KUBERNETES_MASTER/SERVER/disable",
        "value": "true"
    }
]
K8SFULLTOEMPTYPATCH = [
    {
        "op": "remove",
        "path": "/KUBERNETES_MASTER"
    }
]
K8SEMPTYTOWRONGIPPATCH = [
    {
        "op": "add",
        "path": "/KUBERNETES_MASTER",
        "value": {"SERVER": {"disable": "true", "ip": ""}}
    }
]
K8SWRONGIPTOFULLPATCH = [
    {
        "op": "replace",
        "path": "/KUBERNETES_MASTER/SERVER/ip",
        "value": "k8svip.ap.gbl"
    },
    {
        "op": "replace",
        "path": "/KUBERNETES_MASTER/SERVER/disable",
        "value": "false"
    }
]


EMPTYK8STABLE = ()
FULLK8STABLE = ("k8svip.ap.gbl", "false")
FULLK8STABLE2 = ("k8svip2.ap.gbl", "false")
WRONGIPK8STABLE = ("", "true")


# Succeed and fail flag
SUCCEED = "SUCCEED"
FAIL = "FAIL"


test_data_1 = [
    (K8SEMPTYTOHALFPATCH, K8SHALFCONFIG, EMPTYK8STABLE, SUCCEED),
    (K8SHALFTOWRONGIPPATCH, K8SHALFCONFIG, EMPTYK8STABLE, FAIL),
    (K8SHALFTOFULLPATCH, K8SFULLCONFIG, FULLK8STABLE, SUCCEED),
    (K8SFULLTOHALFPATCH, K8SHALFCONFIG, EMPTYK8STABLE, SUCCEED),
    (K8SHALFTOEMPTYPATCH, K8SEMPTYCONFIG, EMPTYK8STABLE, SUCCEED),
    (K8SEMPTYTOFULLPATCH, K8SFULLCONFIG, FULLK8STABLE, SUCCEED),
    (K8SFULLTOFULLPATCH, K8SFULLCONFIG2, FULLK8STABLE2, SUCCEED),
    (K8SFULLTOWRONGIPPATCH, K8SFULLCONFIG2, FULLK8STABLE2, FAIL),
    (K8SFULLTOEMPTYPATCH, K8SEMPTYCONFIG, EMPTYK8STABLE, SUCCEED),
    (K8SEMPTYTOWRONGIPPATCH, K8SEMPTYCONFIG, EMPTYK8STABLE, FAIL),
]


test_data_2 = [
    (K8SWRONGIPTOFULLPATCH, K8SEMPTYIPCONFIG, WRONGIPK8STABLE, FAIL),
]


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """
    Setup/teardown fixture for k8s config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    original_k8s_config = get_k8s_runningconfig(duthost)
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
        current_k8s_config = get_k8s_runningconfig(duthost)
        pytest_assert(
            set(original_k8s_config) == set(current_k8s_config),
            "k8s config are not suppose to change after test org: {}, cur: {}"
            .format(original_k8s_config, current_k8s_config)
        )

    finally:
        delete_checkpoint(duthost)


def get_k8s_runningconfig(duthost):
    """ Get k8s config from running config
    Sample output: K8SEMPTYCONFIG, K8SHALFCONFIG, K8SFULLCONFIG
    """
    cmds = "show runningconfiguration all"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    k8s_pattern = r'"KUBERNETES_MASTER":\s*{\s*.*(?:\s*.*\s*.*\s*)?\s*}\s*}'
    k8s_config = re.findall(k8s_pattern, output['stdout'])

    return k8s_config


def get_k8s_table(duthost):
    """ Get k8s config from CONFIG_DB by show kube server config
    """
    cmds = 'show kube server config'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))
    k8s_table = output['stdout']

    empty_table = 'Kubernetes server is not configured'
    if k8s_table == empty_table:
        return ()
    else:
        table_config_list = k8s_table.split('\n')[-1].split()
        if len(table_config_list) == 4:
            vip, _, _, diable = table_config_list
        elif len(table_config_list) == 3:
            vip = ""
            _, _, diable = table_config_list

    return (vip, diable)


def k8s_config_cleanup(duthost):
    """ Clean up k8s config to avoid conflict
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "KUBERNETES_MASTER|*" | xargs -r sonic-db-cli CONFIG_DB del'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "k8s config cleanup failed.")


def k8s_empty_ip_config_setup(duthost):
    """ Set up k8s config with empty ip
    """
    cmds = 'sonic-db-cli CONFIG_DB hmset "KUBERNETES_MASTER|SERVER" "disable" "true" "ip" ""'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "k8s config setup failed.")


def k8s_config_update(duthost, test_data):
    """ Update k8s config
    """
    for num, (json_patch, target_config, target_table, expected_result) in enumerate(test_data):
        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)

            if expected_result == SUCCEED:
                expect_op_success(duthost, output)
            elif expected_result == FAIL:
                expect_op_failure(output)

            k8s_config = get_k8s_runningconfig(duthost)
            pytest_assert(
                k8s_config == target_config,
                f"Failed to run num.{num+1} test case to update k8s config."
            )

            k8s_table = get_k8s_table(duthost)
            pytest_assert(
                k8s_table == target_table,
                f"Failed to run num.{num+1} test case to update k8s table."
            )

        finally:
            delete_tmpfile(duthost, tmpfile)


def test_k8s_config_patch_apply(rand_selected_dut):
    """ Test suite for k8s config update
    """
    k8s_config_cleanup(rand_selected_dut)
    k8s_config_update(rand_selected_dut, test_data_1)
    k8s_empty_ip_config_setup(rand_selected_dut)
    k8s_config_update(rand_selected_dut, test_data_2)
    k8s_config_cleanup(rand_selected_dut)
