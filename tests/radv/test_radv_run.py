import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import is_container_running

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

PO2VLAN_DEPLOYMENT_ID = '8'


@pytest.mark.po2vlan
def test_radv_deployment_id(duthost):
    ret = is_container_running(duthost, "radv")
    assert ret is True, "radv container is not running"
    logger.info("Set the deployment id to {} and restart radv".format(PO2VLAN_DEPLOYMENT_ID))
    get_cmd = 'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" "deployment_id"'
    set_cmd = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "deployment_id" "{}"'
    # Need to generate supervisord.conf
    docker_cmd = 'docker exec radv sonic-cfggen -d -t \
/usr/share/sonic/templates/docker-router-advertiser.supervisord.conf.j2,/etc/supervisor/conf.d/supervisord.conf'
    restart_cmd = 'docker restart radv'
    origin_id = duthost.shell(get_cmd)['stdout']
    duthost.shell(set_cmd.format(PO2VLAN_DEPLOYMENT_ID))
    duthost.shell(docker_cmd)
    duthost.shell(restart_cmd)
    assert wait_until(10, 1, 0, is_container_running, duthost, "radv")
    logger.info("Check if radvd process is running")
    ret = duthost.is_service_running("radvd", "radv")
    assert ret is False, "radv service is still running"
    logger.info("Set the deployment id back to {} and restart radv".format(origin_id))
    duthost.shell(set_cmd.format(origin_id))
    duthost.shell(docker_cmd)
    duthost.shell(restart_cmd)
    assert wait_until(10, 1, 0, is_container_running, duthost, "radv")
