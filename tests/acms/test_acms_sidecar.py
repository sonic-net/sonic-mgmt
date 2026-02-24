import os
import re
import json
import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.yang_utils import run_yang_validation
from tests.acms.helper import container_name, sidecar_container_name
from tests.common.helpers.dut_utils import migrate_container_systemd

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_UPGRADE_PARAMETERS_FILE = os.path.realpath(os.path.join(os.path.dirname(__file__),
                                                     "../container_upgrade/parameters.json"))
ACMS_SIDECAR_IMAGE = "docker-acms-sidecar:latest"
ACMS_IMAGE = "docker-acms:latest"
GET_CONFIGDB_CNAME_CMD = "sonic-db-cli CONFIG_DB hget 'RESTAPI|certs' client_crt_cname"
SET_CONFIGDB_CNAME_CMD = "sonic-db-cli CONFIG_DB HSET 'RESTAPI|certs' client_crt_cname '{}'"
RESTART_RESTAPI_CMD = "sudo systemctl restart restapi"
SONIC_RESTAPI_YANG = "/usr/local/yang-models/sonic-restapi.yang"
DOCKER_ACMS_SIDECAR = "docker-acms-sidecar"
DOCKER_ACMS = "docker-acms"

V1_EXPECTED_CNAME = "client.restapi.sonic.gbl,vnetds.prod.int.azure-int.net"
V2_ENV_CNAME = ("client.restapi.sonic.gbl,vnetds.prod.int.azure-int.net,"
                "sonicrestclient.vnet.core.windows.net,"
                "*.ri.slb.core.windows.net,"
                "sonicrestapi.oneboot.windows.net,"
                "timesync.public.pilotfish.azure.net")


def get_parameters(docker_container):
    """Load docker run parameters from container_upgrade parameters."""
    with open(CONTAINER_UPGRADE_PARAMETERS_FILE, "r") as f:
        parameters = json.load(f)
    return parameters[docker_container]["parameters"]


def run_acms_sidecar(duthost, env_vars, acms_sidecar_parameters):
    """
    Stop any existing sidecar, start a new one with the given env vars,
    and wait for it to be ready.
    """
    env_args = " ".join(f"-e {k}={v}" for k, v in env_vars.items())

    cmd = (f"docker run -d {acms_sidecar_parameters} {env_args} "
           f"--name {sidecar_container_name} {ACMS_SIDECAR_IMAGE}")

    duthost.command(f"docker stop {sidecar_container_name}", module_ignore_errors=True)
    duthost.command(f"docker rm {sidecar_container_name}", module_ignore_errors=True)
    out = duthost.command(cmd)
    pytest_assert(out["rc"] == 0, "Failed to start acms-sidecar container")


def run_acms(duthost, acms_parameters):
    """
    Stop any existing acms container, start a new one with the given parameters,
    and wait for it to be ready.
    """
    cmd = (f"docker run -d {acms_parameters} "
           f"--name {container_name} {ACMS_IMAGE}")

    duthost.command(f"docker stop {container_name}", module_ignore_errors=True)
    duthost.command(f"docker rm {container_name}", module_ignore_errors=True)
    out = duthost.command(cmd)
    pytest_assert(out["rc"] == 0, "Failed to start acms container")


@pytest.fixture(scope='function')
def setup_restapi_config_db(duthosts, rand_one_dut_hostname):
    """Set ConfigDB RESTAPI|certs|client_crt_cname to V1 baseline before and after each test."""
    duthost = duthosts[rand_one_dut_hostname]

    duthost.shell(SET_CONFIGDB_CNAME_CMD.format(V1_EXPECTED_CNAME))
    duthost.shell(RESTART_RESTAPI_CMD)
    run_yang_validation(duthost, "setup setup_restapi_config_db")
    configdb_cname = duthost.shell(GET_CONFIGDB_CNAME_CMD)["stdout"]
    pytest_assert(configdb_cname == V1_EXPECTED_CNAME,
                  "Unexpected RESTAPI|certs client_crt_cname in ConfigDB during setup")

    yield

    duthost.shell(SET_CONFIGDB_CNAME_CMD.format(V1_EXPECTED_CNAME))
    run_yang_validation(duthost, "teardown setup_restapi_config_db")
    duthost.shell(RESTART_RESTAPI_CMD)
    configdb_cname = duthost.shell(GET_CONFIGDB_CNAME_CMD)["stdout"]
    pytest_assert(configdb_cname == V1_EXPECTED_CNAME,
                  "Unexpected RESTAPI|certs client_crt_cname in ConfigDB during teardown")


@pytest.fixture(scope='function')
def setup_yang_model(duthosts, rand_one_dut_hostname):
    """
    For V2 tests: backup the restapi yang model before sidecar runs.
    The sidecar will patch the yang model at runtime to support wildcard patterns.
    Restores the original yang model on teardown.
    """
    duthost = duthosts[rand_one_dut_hostname]

    duthost.command(f"sudo cp {SONIC_RESTAPI_YANG} {SONIC_RESTAPI_YANG}.bak")

    yield

    duthost.command(f"sudo cp {SONIC_RESTAPI_YANG}.bak {SONIC_RESTAPI_YANG}")
    duthost.command(f"sudo rm -f {SONIC_RESTAPI_YANG}.bak")


def test_v1_configdb_yang_validated(duthosts,
                                    rand_one_dut_hostname,
                                    verify_acms_containers_running,
                                    setup_restapi_config_db):
    """
    V1 mode: sidecar overwrites ConfigDB cname with env value.
    Uses the original built-in restapi yang model (no wildcard support needed).

    Setup:
      - IS_V1_ENABLED=True
      - RESTAPI_CLIENT_CNAME_ACTION_ENABLED=True
      - RESTAPI_CLIENT_CNAME="client.restapi.sonic.gbl,vnetds.prod.int.azure-int.net"
      - ConfigDB RESTAPI|certs|client_crt_cname set to V1 baseline

    Expect:
      - ConfigDB cname matches V1_EXPECTED_CNAME after sidecar runs
      - YANG validation passes with the original yang model
    """
    duthost = duthosts[rand_one_dut_hostname]
    acms_sidecar_parameters = get_parameters(DOCKER_ACMS_SIDECAR)
    acms_parameters = get_parameters(DOCKER_ACMS)

    env_vars = {
        "IS_V1_ENABLED": "True",
        "RESTAPI_CLIENT_CNAME_ACTION_ENABLED": "True",
        "RESTAPI_CLIENT_CNAME": V1_EXPECTED_CNAME,
    }

    run_acms_sidecar(duthost, env_vars, acms_sidecar_parameters)
    migrate_container_systemd(duthost, container_name, acms_parameters)

    configdb_cname = duthost.shell(GET_CONFIGDB_CNAME_CMD)["stdout"]
    pytest_assert(configdb_cname == V1_EXPECTED_CNAME,
                  f"V1: Expected ConfigDB cname '{V1_EXPECTED_CNAME}', got '{configdb_cname}'")

    result = run_yang_validation(duthost, "v1-post-acms-sidecar")
    pytest_assert(not result['failed'],
                  f"V1: YANG validation failed after sidecar: {result.get('error', '')}")


def test_v2_action_disabled_dry_run_yang_validated(duthosts,
                                                   rand_one_dut_hostname,
                                                   verify_acms_containers_running,
                                                   setup_restapi_config_db,
                                                   setup_yang_model):
    """
    V2 mode with action disabled: sidecar runs in dry-run mode.
    Uses the original built-in restapi yang model.

    Setup:
      - IS_V1_ENABLED=False
      - RESTAPI_CLIENT_CNAME_ACTION_ENABLED=False
      - RESTAPI_CLIENT_CNAME includes wildcards
      - ConfigDB RESTAPI|certs|client_crt_cname set to V1 baseline

    Behavior:
      - Sidecar logs what would be changed but does NOT modify ConfigDB

    Expect:
      - ConfigDB cname remains at V1 baseline (unchanged)
      - YANG validation passes (ConfigDB was not modified)
    """
    duthost = duthosts[rand_one_dut_hostname]
    acms_sidecar_parameters = get_parameters(DOCKER_ACMS_SIDECAR)
    acms_parameters = get_parameters(DOCKER_ACMS)

    env_vars = {
        "IS_V1_ENABLED": "False",
        "RESTAPI_CLIENT_CNAME_ACTION_ENABLED": "False",
        "RESTAPI_CLIENT_CNAME": V2_ENV_CNAME,
    }

    run_acms_sidecar(duthost, env_vars, acms_sidecar_parameters)
    run_acms(duthost, acms_parameters)

    # Verify sidecar patched the yang model to support wildcard patterns
    yang_content = duthost.shell(f"cat {SONIC_RESTAPI_YANG}")["stdout"]
    crt_cname_match = re.search(
        r"leaf\s+client_crt_cname\s*\{[^}]*pattern\s+'([^']+)'",
        yang_content, re.DOTALL
    )
    pytest_assert(crt_cname_match is not None,
                  "V2: client_crt_cname leaf not found in yang model after sidecar run")
    pytest_assert("*" in crt_cname_match.group(1),
                  f"V2: Yang model pattern does not support wildcards. "
                  f"Pattern: {crt_cname_match.group(1)}")

    configdb_cname = duthost.shell(GET_CONFIGDB_CNAME_CMD)["stdout"]
    pytest_assert(configdb_cname == V1_EXPECTED_CNAME,
                  f"V2 dry-run: ConfigDB cname should remain unchanged. "
                  f"Expected '{V1_EXPECTED_CNAME}', got '{configdb_cname}'")

    result = run_yang_validation(duthost, "v2-dry-run-post-acms-sidecar")
    pytest_assert(not result['failed'],
                  f"V2 dry-run: YANG validation failed after sidecar: {result.get('error', '')}")


def test_v2_configdb_yang_validated(duthosts,
                                    rand_one_dut_hostname,
                                    verify_acms_containers_running,
                                    setup_restapi_config_db,
                                    setup_yang_model):
    """
    V2 mode: sidecar appends missing CNs from env to ConfigDB (additive merge)
    and patches the restapi yang model to support wildcard patterns.

    Setup:
      - IS_V1_ENABLED=False
      - RESTAPI_CLIENT_CNAME_ACTION_ENABLED=True
      - RESTAPI_CLIENT_CNAME includes wildcards (e.g. *.ri.slb.core.windows.net)
      - Yang model backed up (setup_yang_model fixture); sidecar patches it at runtime
      - ConfigDB RESTAPI|certs|client_crt_cname set to V1 baseline

    Expect:
      - Yang model client_crt_cname pattern includes wildcard (*) after sidecar runs
      - ConfigDB cname is a superset of V2_ENV_CNAME values after sidecar runs
      - YANG validation passes with the sidecar-patched yang model
    """
    duthost = duthosts[rand_one_dut_hostname]
    acms_sidecar_parameters = get_parameters(DOCKER_ACMS_SIDECAR)
    acms_parameters = get_parameters(DOCKER_ACMS)

    env_vars = {
        "IS_V1_ENABLED": "False",
        "RESTAPI_CLIENT_CNAME_ACTION_ENABLED": "True",
        "RESTAPI_CLIENT_CNAME": V2_ENV_CNAME,
    }

    run_acms_sidecar(duthost, env_vars, acms_sidecar_parameters)
    run_acms(duthost, acms_parameters)

    # Verify sidecar patched the yang model to support wildcard patterns
    yang_content = duthost.shell(f"cat {SONIC_RESTAPI_YANG}")["stdout"]
    crt_cname_match = re.search(
        r"leaf\s+client_crt_cname\s*\{[^}]*pattern\s+'([^']+)'",
        yang_content, re.DOTALL
    )
    pytest_assert(crt_cname_match is not None,
                  "V2: client_crt_cname leaf not found in yang model after sidecar run")
    pytest_assert("*" in crt_cname_match.group(1),
                  f"V2: Yang model pattern does not support wildcards. "
                  f"Pattern: {crt_cname_match.group(1)}")

    configdb_cname = duthost.shell(GET_CONFIGDB_CNAME_CMD)["stdout"]
    configdb_cn_set = {cn.strip() for cn in configdb_cname.split(",") if cn.strip()}
    env_cn_set = {cn.strip() for cn in V2_ENV_CNAME.split(",") if cn.strip()}
    pytest_assert(env_cn_set.issubset(configdb_cn_set),
                  f"V2: ConfigDB cname missing expected CNs. "
                  f"Expected superset of {env_cn_set}, got {configdb_cn_set}")

    result = run_yang_validation(duthost, "v2-post-acms-sidecar")
    pytest_assert(not result['failed'],
                  f"V2: YANG validation failed after sidecar: {result.get('error', '')}")


def test_v1_action_disabled_golden_config_yang_validated(duthosts,
                                                         rand_one_dut_hostname,
                                                         verify_acms_containers_running,
                                                         setup_restapi_config_db):
    """
    V1 mode with action disabled: sidecar falls back to golden config.
    Uses the original built-in restapi yang model.

    Setup:
      - IS_V1_ENABLED=True
      - RESTAPI_CLIENT_CNAME_ACTION_ENABLED=False
      - ConfigDB RESTAPI|certs|client_crt_cname set to V1 baseline

    Behavior:
      - Sidecar reads RESTAPI|certs|client_crt_cname from golden_config_db.json
      - If golden config value differs from ConfigDB, sidecar overwrites ConfigDB
      - If golden config is missing or matches, no change

    Expect:
      - ConfigDB cname is either the golden config value or unchanged baseline
      - YANG validation passes (golden config value is valid in original yang model)
    """
    duthost = duthosts[rand_one_dut_hostname]
    acms_sidecar_parameters = get_parameters(DOCKER_ACMS_SIDECAR)
    acms_parameters = get_parameters(DOCKER_ACMS)

    env_vars = {
        "IS_V1_ENABLED": "True",
        "RESTAPI_CLIENT_CNAME_ACTION_ENABLED": "False",
        "RESTAPI_CLIENT_CNAME": V1_EXPECTED_CNAME,
    }

    run_acms_sidecar(duthost, env_vars, acms_sidecar_parameters)
    migrate_container_systemd(duthost, container_name, acms_parameters)

    configdb_cname = duthost.shell(GET_CONFIGDB_CNAME_CMD)["stdout"]
    logger.info(f"V1 action-disabled: ConfigDB cname after sidecar: {configdb_cname}")
    pytest_assert(len(configdb_cname) > 0,
                  "V1 action-disabled: ConfigDB cname should not be empty")

    result = run_yang_validation(duthost, "v1-action-disabled-post-acms-sidecar")
    pytest_assert(not result['failed'],
                  f"V1 action-disabled: YANG validation failed after sidecar: {result.get('error', '')}")
