import pytest
import pexpect
import logging
import time
import tarfile
import paramiko

from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
from tests.common import config_reload
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from multiprocessing.pool import ThreadPool, TimeoutError
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.utilities import wait_until
from tests.common.reboot import *
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.platform.interface_utils import check_all_interface_information, get_port_map
from tests.common.platform.daemon_utils import check_pmon_daemon_status
import textfsm

pytestmark = [
    pytest.mark.install_image,
    pytest.mark.topology("install"),
]

logger = logging.getLogger(__name__)

DEFAULT_TMOUT = "900"
SET_TMOUT = "10"
IMAGE_LOC = '/tmp/sonic-cisco-8000.bin'
TS_LOC = '/tmp/showts/*'
TS_COPY = '/data/tests/.'
ssh_port = 22
MAX_WAIT_TIME_FOR_INTERFACES = 300
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120
proc_textfsm = "./bgp/templates/show_proc_cpu.template"
bgp_sum_textfsm = "./bgp/templates/bgp_summary.template"

def get_cpu_stats(dut):
    proc_cpu = dut.shell("show processes cpu | head -n 20", module_ignore_errors=True)['stdout']
    proc_mem = dut.shell("show processes memory | head -n 20", module_ignore_errors=True)['stdout']
    proc_sum = dut.shell("show processes summary | grep -v '0.0 0.0'", module_ignore_errors=True)['stdout']
    bgp_cpu = dut.shell("show processes cpu | grep bgp", module_ignore_errors=True)['stdout']
    bgp_v4_sum = dut.shell("show ip bgp summary | grep memory", module_ignore_errors=True)['stdout']
    bgp_v6_sum = dut.shell("show ipv6 bgp summary | grep memory", module_ignore_errors=True)['stdout']
    logger.info("CPU:\n{}\nMemory:\n{}\nSummary:\n{}\nBGP Memory:\n{}\nBGP IPv4:\n{}\nIPv6:\n{}\n"
                .format(proc_cpu, proc_mem, proc_sum, bgp_cpu, bgp_v4_sum, bgp_v6_sum))
    with open(proc_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        parsed_cpu = fsm.ParseText(proc_cpu)[0]

    with open(bgp_sum_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        parsed_ipv4 = fsm.ParseText(bgp_v4_sum)[0]
        parsed_ipv6 = fsm.ParseText(bgp_v6_sum)[0]
    data = [float(parsed_cpu[0]), float(parsed_cpu[1]), float(parsed_cpu[2]),
            float(parsed_ipv4[0]), float(parsed_ipv4[1]), float(parsed_ipv4[2]),
            float(parsed_ipv6[0]), float(parsed_ipv6[1]), float(parsed_ipv6[2])]
    print(data)
    return data

def check_interfaces_and_services(dut, interfaces, xcvr_skip_list,
                                  interfaces_wait_time=MAX_WAIT_TIME_FOR_INTERFACES, reboot_type=None):
    """
    Perform a further check after reboot-cause, including transceiver status, interface status
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    """
    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(dut)

    if dut.is_supervisor_node():
        logging.info("skipping interfaces related check for supervisor")
    else:
        logging.info("Wait {} seconds for all the transceivers to be detected".format(
            interfaces_wait_time))
        result = wait_until(interfaces_wait_time, 20, 0, check_all_interface_information, dut, interfaces,
                            xcvr_skip_list)
        assert result, "Not all transceivers are detected or interfaces are up in {} seconds".format(
            interfaces_wait_time)

        logging.info("Check transceiver status")
        for asic_index in dut.get_frontend_asic_ids():
            # Get the interfaces pertaining to that asic
            interface_list = get_port_map(dut, asic_index)
            interfaces_per_asic = {k: v for k, v in list(
                interface_list.items()) if k in interfaces}
            check_transceiver_basic(
                dut, asic_index, interfaces_per_asic, xcvr_skip_list)

        logging.info("Check pmon daemon status")
        assert check_pmon_daemon_status(dut), "Not all pmon daemons running."

    if dut.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)

    if reboot_type is not None:
        logging.info("Check reboot cause")
        assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, 30, check_reboot_cause, dut, reboot_type), \
            "got reboot-cause failed after rebooted by %s" % reboot_type

        if "201811" in dut.os_version or "201911" in dut.os_version:
            logging.info(
                "Skip check reboot-cause history for version before 202012")
        else:
            logging.info("Check reboot-cause history")
            assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, 0, check_reboot_cause_history, dut,
                              REBOOT_TYPE_HISTOYR_QUEUE), \
                "Check reboot-cause history failed after rebooted by %s" % reboot_type
        if reboot_ctrl_dict[reboot_type]["test_reboot_cause_only"]:
            logging.info(
                "Further checking skipped for %s test which intends to verify reboot-cause only" % reboot_type)
            return


def test_install_image(duthosts,localhost, creds, conn_graph_facts, request, xcvr_skip_list, tbinfo):
    tb_name = tbinfo['conf-name']
    image_loc = request.config.getoption("--image_loc")
    build_id = request.config.getoption("--build_id")
    initImage = dict()
    reload_res = dict()
    copy_res = dict()
    install_res = dict()
    reboot_res = dict()
    collect_techsupport_res = dict()
    pool_list = list()
    pool = ThreadPool()

    print("This is image location: {}".format(image_loc))
    localhost.shell('wget {}'.format(image_loc))
    tar_file = image_loc.split('/')[-1]

    tar = tarfile.open(tar_file)
    filename = tar.getnames()[0] +'/sonic-cisco-8000.bin'

    tar.extract(filename)

    # Clean up /var/dump before show techsupport is run
    for duthost in duthosts:
        logger.info("Clean up /var/dump files")

        try:
            duthost.shell("sudo rm /var/dump/*")
        except:
            pass
        try:
            duthost.shell("mkdir /tmp/showts")
        except:
            pass

    copy_res = dict()
    pool_list = list()
    pool = ThreadPool()
    def image_copy(duthost):
        logger.info("Copy Image {} to {}".format(filename,IMAGE_LOC))
        return duthost.copy(src=filename, dest=IMAGE_LOC)

    logger.info("Copy file to DUT")
    for duthost in duthosts:
        logger.info('In copy async pool loop')
        copy_res[duthost] = pool.apply_async(image_copy, (duthost,))

    ctr = 0
    while True:
        pool_list = []
        for duthost in duthosts:
            print("Image copy results for {} is {}".format(duthost, copy_res[duthost].ready()))
            pool_list.append(copy_res[duthost].ready())
        if False in pool_list and ctr < 30:
            time.sleep(30)
            ctr += 1
        else:
            print("Results for pool list : {}".format(pool_list))
            break

    for duthost in duthosts:
        logger.info("Clean up config_db.json and minigraph files")
        try:
            duthost.shell("sudo rm /etc/sonic/*config*")
        except:
            pass
        try:
            duthost.shell("sudo rm /etc/sonic/minigraph.xml")
        except:
            pass

    pool_list = list()
    pool = ThreadPool()
    def image_install(duthost):
        logger.info("Sonic Install the image on : {}".format(duthost))
        initImage[duthost] = duthost.shell('sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
        return duthost.shell("sudo sonic-installer install --skip_migration -y {}".format(IMAGE_LOC))

    for duthost in duthosts:
        logger.info('In sonic-install async pool loop')
        install_res[duthost] = pool.apply_async(image_install, (duthost,))

    ctr = 0
    while True:
        pool_list = []
        for duthost in duthosts:
            print("Image load results for {} is {}".format(duthost, install_res[duthost].ready()))
            pool_list.append(install_res[duthost].ready())
        if False in pool_list and ctr < 20:
            time.sleep(30)
            ctr += 1
        else:
            print("Results for pool list : {}".format(pool_list))
            break

    for duthost in duthosts:
        logger.info("Clean up core and log files")
        try:
            duthost.shell("sudo rm /var/dump/*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/core/*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/syslog.*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/auth.log.*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/telemetry.log.*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/cron.log.*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/teamd.log.*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/swss/sairedis*rec.*")
        except:
            pass
        try:
            duthost.shell("sudo rm /var/log/swss/swss*rec.*")
        except:
            pass

    for duthost in duthosts:
        logger.info("List the image")
        try:
            duthost.shell("sudo sonic-installer list")
            duthost.shell("sudo sonic-installer cleanup -y")
        except:
            pass

    if 'chassis-packet' in duthosts[0].facts.get('switch_type'):
        for duthost in duthosts:
            if duthost.is_supervisor_node():
                reboot(duthost, localhost, wait=900, timeout=600)
    else:
        for duthost in duthosts:
            reboot(duthost, localhost, wait=600, timeout=300)

    try:
        localhost.shell("rm /data/ansible/deploy.log")
    except:
        pass

    localhost.shell("cd ./../ansible; ./testbed-cli.sh -t testbed.csv deploy-mg {} lab group_vars/lab/secrets.yml > deploy.log".format(tb_name))
    time.sleep(500)
    logger.info("Cleaning up image file from localhost")
    localhost.shell('rm {}'.format(tar_file))
    localhost.shell('rm -rf {}'.format(tar.getnames()[0]))

    for duthost in duthosts:
        check_interfaces_and_services(duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, reboot_type=None)


    for duthost in duthosts:
        logger.info("List the image")
        current_image = duthost.shell('sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
        if build_id not in current_image:
            pytest.fail("Current image: {} is not the expected image: {} to be installed ".format(build_id, current_image))
        else:
            logging.info("##### Successfully installed : {} ######".format(current_image))

    for duthost in duthosts:
        try:
            get_cpu_stats(duthost)
        except:
            logging.info("Looks like we hit some issue during CPU stats collection time")
            pass
