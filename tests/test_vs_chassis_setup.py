import pytest
import logging
import os

from tests.common.reboot import reboot
from tests.common.helpers.parallel import parallel_run, reset_ansible_local_tmp
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer
]

@reset_ansible_local_tmp
def reboot_duts(localhost, node=None, results=None):
    reboot(node, localhost, wait=60)

@pytest.fixture(scope="module")
def setup(duthosts, tbinfo, localhost):

    dut_topo_info = tbinfo['topo']['properties']['topology']['DUT']
    if 'vs_chassis' not in dut_topo_info:
        return

    for dut_index, duthost in enumerate(duthosts):
        midplane_ip = dut_topo_info['vs_chassis']['midplane_address'][dut_index]
        midplane_port = "eth{}".format(dut_topo_info['vs_chassis']['midplane_port'][dut_index] + 1)

        # Check if we already have midplane port configuration in rc.local
        try:
            t1 = duthost.shell("sudo grep 'sudo ip addr add {}' /etc/rc.local".format(midplane_ip), executable="/bin/bash")
            logger.info("On {}, midplane IP configuration is already in /etc/rc.local".format(duthost.hostname))
        except:
            # edit rc.local to have midplane ip configured on the midplane port as specified in the topology file
            #    Replace the last line which should start with 'exit 0' with lines to configure and bring up midplane interface followed by exit 0
            logger.info("midplane IP configuration is already in /etc/rc.local not in {}, adding it".format(duthost.hostname))
            duthost.command("sudo sed -i 's/^exit 0/\\nsudo ip addr add {}\/24 dev {}\\nsudo ifconfig {} up\\n\\nexit 0/' /etc/rc.local".format(
                midplane_ip, midplane_port, midplane_port))

        # Add chassis_db
        logger.info("Adding chassisdb.conf on {}".format(duthost.hostname))
        chassis_db_ip = dut_topo_info['vs_chassis']['chassis_db_ip']
        duthost.shell("sudo echo 'chassis_db_address={}' > /tmp/chassisdb.conf".format(chassis_db_ip), executable="/bin/bash")
        if duthost.is_supervisor_node():
            logger.info ("{} is supervisor card, adding config to start chassisdb in chassisdb.conf".format(duthost.hostname))
            duthost.shell("echo 'start_chassis_db=1' >> /tmp/chassisdb.conf", executable="/bin/bash")
            duthost.shell("echo 'lag_id_start=1' >> /tmp/chassisdb.conf", executable="/bin/bash")
            duthost.shell("echo 'lag_id_end=512' >> /tmp/chassisdb.conf", executable="/bin/bash")
            duthost.command("sudo cp /tmp/chassisdb.conf /etc/sonic/")
        duthost.command("sudo cp /tmp/chassisdb.conf /usr/share/sonic/device/x86_64-kvm_x86_64-r0/")

        # scp the config_db's for each card
        logger.info("")
        BASE_DIR = os.path.dirname(os.path.realpath(__file__))
        src_cfg_path = os.path.join(BASE_DIR, "vs_voq_cfgs", "{}_config_db.json".format(duthost.hostname))
        dst_cfg_path = os.path.join(os.sep, "tmp", "config_db.json")
        logger.info("Copying {} to /etc/sonic/config_db.json on {}".format(src_cfg_path, duthost.hostname))
        duthost.copy(src=src_cfg_path, dest=dst_cfg_path)
        duthost.command("sudo cp {} {}".format(dst_cfg_path, "/etc/sonic/config_db.json"))

    logger.info ("Rebooting all the DUTs in parallel")
    parallel_run(reboot_duts, [localhost], {}, duthosts, timeout=240)


# From each frontend node, ping the chassis_db ip address defined in the topology file.
def test_midplane(duthosts, tbinfo, setup):
    dut_topo_info = tbinfo['topo']['properties']['topology']['DUT']
    chassis_db_ip = dut_topo_info['vs_chassis']['chassis_db_ip']

    for duthost in duthosts.frontend_nodes:
        duthost.command ("ping {} -c1".format(chassis_db_ip))


# From each frontend node, validate chassis-db connectivity to supervisor using redis-cli to get keys of table SYSTEM_INTERFACE
def test_chassisdb(duthosts, tbinfo, setup):
    dut_topo_info = tbinfo['topo']['properties']['topology']['DUT']
    chassis_db_ip = dut_topo_info['vs_chassis']['chassis_db_ip']
    for duthost in duthosts.frontend_nodes:
        redis_out = duthost.command("redis-cli -h {} -p 6380 -n 12 keys \"*SYSTEM_INTERFACE*\"".format(chassis_db_ip))['stdout']
        pytest_assert("" != redis_out,
                      "From {} have connectivity to chassis_db on supervisor {} but it does not have any entries for SYSTEM_INTERFACE".format (duthost.hostname, chassis_db_ip))
