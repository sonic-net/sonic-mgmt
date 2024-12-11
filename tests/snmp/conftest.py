import pytest
from tests.common.utilities import wait_until
import shutil
import yaml

from tests.common.gu_utils import create_checkpoint, rollback

SETUP_ENV_CP = "test_setup_checkpoint"


@pytest.fixture(scope="module", autouse=True)
def setup_check_snmp_ready(duthosts, localhost):
    for duthost in duthosts:
        assert wait_until(300, 20, 0, duthost.is_service_fully_started,
                          "snmp"), "SNMP service is not running"

        # creating checkpoint before any configuration changes
        create_checkpoint(duthost, SETUP_ENV_CP)

        snmp_config_path = "/etc/sonic/snmp.yml"

        # copy snmp.yml to ucs
        output = duthost.shell("sudo find /etc/sonic -name 'snmp.yml'")
        filename = output["stdout"].split("\n")

        if snmp_config_path in filename:
            ret = duthost.fetch(src=snmp_config_path, dest=".")
            ret_bin = ret.get("dest", None)
            shutil.copyfile(ret_bin, "snmp/snmp.yml")
        else:
            assert False, f'{snmp_config_path} does not exist'

        # configure snmp for every host
        full_snmp_comm_list = ['snmp_rocommunity', 'snmp_rocommunities', 'snmp_rwcommunity', 'snmp_rwcommunities']
        with open('./snmp/snmp.yml', 'r') as yaml_file:
            yaml_snmp_info = yaml.load(yaml_file, Loader=yaml.FullLoader)

        # get redis output for SNMP_COMMUNITY & SNMP_LOCATION
        snmp_comm_redis_keys = check_redis_output(duthost, 'SNMP_COMMUNITY')
        snmp_comm_redis_vals = list(map(extract_redis_keys, snmp_comm_redis_keys))
        snmp_location_redis_keys = check_redis_output(duthost, 'SNMP|LOCATION')
        snmp_location_redis_vals = list(map(extract_redis_keys, snmp_location_redis_keys))

        for comm_type in full_snmp_comm_list:
            if comm_type in yaml_snmp_info.keys():
                if comm_type.startswith('snmp_rocommunities'):
                    for community in yaml_snmp_info[comm_type]:
                        if community not in snmp_comm_redis_vals:
                            duthost.shell(f"sudo config snmp community add {community} 'ro'")  # set snmp cli

                elif comm_type.startswith('snmp_rocommunity'):
                    community = yaml_snmp_info[comm_type]
                    if community not in snmp_comm_redis_vals:
                        duthost.shell(f"sudo config snmp community add {community} 'ro'")  # set snmp cli

                elif comm_type.startswith('snmp_rwcommunities'):
                    for community in yaml_snmp_info[comm_type]:
                        if community not in snmp_comm_redis_vals:
                            duthost.shell(f"sudo config snmp community add {community} 'rw'")  # set snmp cli

                elif comm_type.startswith('snmp_rwcommunity'):
                    community = yaml_snmp_info[comm_type]
                    if community not in snmp_comm_redis_vals:
                        duthost.shell(f"sudo config snmp community add {community} 'rw'")  # set snmp cli

        yaml_snmp_location = yaml_snmp_info.get('snmp_location')
        if yaml_snmp_location:
            if 'LOCATION' not in snmp_location_redis_vals:
                duthost.shell(f'sudo config snmp location add {yaml_snmp_location}')  # set snmp cli

    yield

    for duthost in duthosts:
        # rollback configuration
        rollback(duthost, SETUP_ENV_CP)

    # remove snmp files downloaded
    local_command = "find ./snmp/ -type f -name 'snmp.yml' -exec rm -f {} +"
    localhost.shell(local_command)


def extract_redis_keys(item):
    return item.split('|')[1]


def check_redis_output(duthost, key):
    snmp_redis_keys = duthost.shell(f"redis-cli -n 4 keys '{key}*'")
    if snmp_redis_keys["stdout"] == "":
        return []
    else:
        snmp_redis_keys = snmp_redis_keys["stdout"].split("\n")
        return snmp_redis_keys


@pytest.fixture(scope="module", autouse=True)
def enable_queue_counterpoll_type(duthosts):
    for duthost in duthosts:
        duthost.command('counterpoll queue enable')


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the snmp tests.
    """
    parser.addoption(
        "--percentage",
        action="store",
        default=False,
        help="Set percentage difference for snmp test",
        type=int)
