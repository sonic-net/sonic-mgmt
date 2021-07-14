import pytest
import logging
import time
import os
from tests.common.utilities import wait_until

BASE_DIR = os.getcwd()
PARENT_PATH = os.path.abspath(os.path.join(BASE_DIR, os.pardir))
FILENAME_1 = '/usr/lib/python3/dist-packages/platform_ndk/platform_ndk_pb2.py'
FILENAME_2 = '/usr/lib/python3/dist-packages/platform_ndk/platform_ndk_pb2_grpc.py'


@pytest.fixture(scope="session", autouse=True)
def get_latest_protobuff_from_dut(duthosts, localhost):
    """Gets latest protobuff from dut as it is tied to build"""
    logging.info('Copying latest proto buff file from dut to local host')
    path = os.path.join(PARENT_PATH, 'platform_ndk')
    localhost.shell('sshpass -p 123 scp -o  StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q admin@{}:{} {}'
                    .format(duthosts.nodes[0].mgmt_ip, FILENAME_1, path))
    localhost.shell('sshpass -p 123 scp -o  StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q admin@{}:{} {}'
                    .format(duthosts[0].mgmt_ip, FILENAME_2, path))


def start_tcpdump(duthosts, localhost):
    for dut in duthosts:
        mgmt_ip = dut.sonichost.mgmt_ip
        addr = mgmt_ip.split('.')[3]
        output_files_exists = localhost.stat(path = "/output_files")["stat"]["exists"]
        if output_files_exists:
            localhost.shell ("sudo tcpdump -i eth0 host {} and port not 22 -w /output_files/tcpdump_{}.pcapng &".format(mgmt_ip, addr))
        else:
            localhost.shell("sudo tcpdump -i eth0 host {} and port not 22 -w /tmp/tcpdump_{}.pcapng &".format(mgmt_ip, addr))
        logging.info("Started tcpdump on {}".format (mgmt_ip))
    yield
    localhost.shell("sudo pkill tcpdump")

@pytest.fixture(scope="package", autouse=True)
def prepare_dut_for_ndk(duthosts):
    """Prepare dut for NDK testing by stopping pmon docker"""
    stop_pmon_docker(duthosts)
    yield
    start_pmon_docker(duthosts)


def stop_pmon_docker(duthosts):
    """Stop pmon docker """
    for dut in duthosts:
        logging.info('Stopping pmon docker on {}'.format(dut))
        dut.shell('config feature autorestart pmon disabled')
        dut.shell('systemctl disable pmon')
        dut.shell('systemctl stop pmon')

def check_pmon_monit_status(dut):
    """check container checker docker """
    logging.info('Checking status of continer_checker docker on {}'.format(dut))
    output = dut.shell('sudo monit status container_checker')
    return 'pmon' not in output['stdout_lines'][-2]

def start_pmon_docker(duthosts):
    """Starts and verifies pmon docker is up"""
    for dut in duthosts:
        logging.info('Starting pmon docker on dut {}'.format(dut))
        dut.shell('systemctl enable pmon')
        dut.shell('systemctl start pmon')
        dut.shell('config feature autorestart pmon enabled')
        time.sleep(2)
        if not verify_pmon_docker_is_active(dut):
            logging.info('Starting pmon docker on dut {} one more time'.format(dut))
            dut.shell('systemctl enable pmon')
            dut.shell('systemctl start pmon')
            if not verify_pmon_docker_is_active(dut):
                logging.warning('Pmon docker did not start on dut {}'.format(dut))
        logging.info('pmon docker is Active on dut {}'.format(dut))
        logging.info("Polling for 3 minutes for monit container checker to pick up the pmon docker")
        assert (wait_until(180, 2, 0, check_pmon_monit_status, dut),
                "Failed container checker on {}".format(dut))

def verify_pmon_docker_is_active(dut):
    """Verifies pmon docker is Active"""
    logging.info('Verifing pmon docker status on dut {}'.format(dut))
    res = dut.shell('systemctl status pmon')
    if 'Active: active (running)' not in res['stdout']:
        return False

    return True


@pytest.fixture(scope='session', autouse=True)
def install_ndk_debian_package(request, duthosts, localhost):
    ndk_img_url = request.config.getoption("--ndk_image_url")
    if ndk_img_url is not None:
        for duthost in duthosts:
            cmd = 'curl -k --output ndk_1.0-1_amd64.deb --header "PRIVATE-TOKEN: NPxsYvxNFZzpoR6JpS8q" {}'.format(
                ndk_img_url)
            out = duthost.shell(cmd)
            if out['failed']:
                pytest.fail('Failed to install {} package.'.format(ndk_img_url))
            cmd = 'sudo dpkg -i --force-overwrite ndk_1.0-1_amd64.deb'
            out = duthost.shell(cmd)
            if out['failed']:
                pytest.fail('Could not overwrite debian package {}.'.format(ndk_img_url))

            cmd = 'sudo systemctl daemon-reload'
            duthost.shell(cmd)
            cmd = 'sudo systemctl restart nokia-sr-device-mgr.service'
            duthost.shell(cmd)

            cmd = 'sudo systemctl restart nokia-eth-mgr.service'
            duthost.shell(cmd)

            cmd = 'sudo systemctl restart nokia-ndk-qfpga-mgr.service'
            duthost.shell(cmd)


@pytest.fixture(scope="session", autouse=True)
def get_ndk_version(duthosts):
    """
    Returns NDK version running on the dut
    """
    cmd = "sudo /opt/srlinux/bin/sr_platform_ndk_cli -c 'Cli::GetVersionJson'"
    for dut in duthosts:
        out = dut.shell(cmd)
        logging.info("NDK version running on dut {}: {}".format(dut, out['stdout']))
