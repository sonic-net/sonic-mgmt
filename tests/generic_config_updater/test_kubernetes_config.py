import logging
import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload


pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


# K8S config
K8SEMPTYCONFIG = []
K8SHALFCONFIG = ['"KUBERNETES_MASTER": {\n        "SERVER": {}\n    }']
K8SFULLCONFIG = ['"KUBERNETES_MASTER": {\n        "SERVER": {\n            "disable": "false",\n            "ip": "k8svip.ap.gbl"\n        }\n    }']
K8SFULLCONFIG2 = ['"KUBERNETES_MASTER": {\n        "SERVER": {\n            "disable": "false",\n            "ip": "k8svip2.ap.gbl"\n        }\n    }']


# K8S config patch
K8SEMPTYTOHALFPATCH = [{"op": "add", "path": "/KUBERNETES_MASTER", "value": {"SERVER": {}}}]
K8SHALFTOFULLPATCH = [{"op": "add", "path": "/KUBERNETES_MASTER/SERVER/disable", "value": "false"},
                    {"op": "add", "path": "/KUBERNETES_MASTER/SERVER/ip", "value": "k8svip.ap.gbl"}]
K8SFULLTOHALFPATCH = [{"op": "remove", "path": "/KUBERNETES_MASTER/SERVER/ip"},
                    {"op": "remove", "path": "/KUBERNETES_MASTER/SERVER/disable"}]
K8SHALFTOEMPTYPATCH = [{"op": "remove", "path": "/KUBERNETES_MASTER"}]
K8SEMPTYTOFULLPATCH = [{"op": "add", "path": "/KUBERNETES_MASTER", "value": {"SERVER": {"disable": "false", "ip": "k8svip.ap.gbl"}}}]
K8SFULLTOFULLPATCH = [{"op": "replace", "path": "/KUBERNETES_MASTER/SERVER/ip", "value": "k8svip2.ap.gbl"}]
K8SFULLTOEMPTYPATCH = [{"op": "remove", "path": "/KUBERNETES_MASTER"}]

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


def k8s_config_cleanup(duthost):
    """ Clean up k8s config to avoid conflict
    """
    cmds = 'sonic-db-cli CONFIG_DB keys "KUBERNETES_MASTER|*" | xargs -r sonic-db-cli CONFIG_DB del'
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "k8s config cleanup failed.")


def k8s_config_update(duthost):
    """ Update k8s config
    """

    test_data = {
        0: (K8SEMPTYTOHALFPATCH, K8SHALFCONFIG),
        1: (K8SHALFTOFULLPATCH, K8SFULLCONFIG),
        2: (K8SFULLTOHALFPATCH, K8SHALFCONFIG),
        3: (K8SHALFTOEMPTYPATCH, K8SEMPTYCONFIG),
        4: (K8SEMPTYTOFULLPATCH, K8SFULLCONFIG),
        5: (K8SFULLTOFULLPATCH, K8SFULLCONFIG2),
        6: (K8SFULLTOEMPTYPATCH, K8SEMPTYCONFIG)
    }

    for num, (json_patch, target_config) in test_data.items():
        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)

            k8s_config = get_k8s_runningconfig(duthost)
            pytest_assert(
                k8s_config == target_config,
                f"Failed to run num.{num+1} test case to update k8s config."
            )

        finally:
            delete_tmpfile(duthost, tmpfile)


def test_k8s_tc1_test_config(rand_selected_dut):
    """ Test suite for k8s config update
    """
    k8s_config_cleanup(rand_selected_dut)
    k8s_config_update(rand_selected_dut)


