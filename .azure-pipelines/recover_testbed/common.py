import os
import sys
import logging
import select
import socket
import time
import pexpect
import ipaddress
from constants import OS_VERSION_IN_GRUB, ONIE_ENTRY_IN_GRUB, ONIE_INSTALL_MODEL, \
    ONIE_START_TO_DISCOVERY, SONIC_PROMPT, MARVELL_ENTRY, BOOTING_INSTALL_OS, ONIE_RESCUE_MODEL

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, "../.."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from tests.common.plugins.pdu_controller.pdu_manager import pdu_manager_factory # noqa E402

logger = logging.getLogger(__name__)


def get_pdu_managers(sonichosts, conn_graph_facts):
    """Get PDU managers for all the devices to be upgraded.

    Args:
        sonichosts (SonicHosts): Instance of class SonicHosts
        conn_graph_facts (dict): Connection graph dict.

    Returns:
        dict: A dict of PDU managers. Key is device hostname. Value is the PDU manager object for the device.
    """
    pdu_managers = {}
    device_pdu_links = conn_graph_facts['device_pdu_links']
    device_pdu_info = conn_graph_facts['device_pdu_info']
    for hostname in sonichosts.hostnames:
        pdu_links = device_pdu_links[hostname]
        pdu_info = device_pdu_info[hostname]
        pdu_vars = {}
        for pdu_name in pdu_info.keys():
            pdu_vars[pdu_name] = sonichosts.get_host_visible_vars(pdu_name)

        pdu_managers[hostname] = pdu_manager_factory(hostname, pdu_links, pdu_info, pdu_vars)
    return pdu_managers


def posix_shell_onie(dut_console, mgmt_ip, image_url, is_nexus=False, is_nokia=False, is_celestica=False):
    enter_onie_flag = True
    gw_ip = list(ipaddress.ip_interface(mgmt_ip).network.hosts())[0]

    dut_console.remote_conn.settimeout(0.0)

    while True:
        r, w, e = select.select([dut_console.remote_conn, sys.stdin], [], [])
        if dut_console.remote_conn in r:
            try:
                x = dut_console.remote_conn.recv(65536)
                if len(x) == 0:
                    sys.stdout.write("\r\n*** EOF\r\n")
                    break

                x = x.decode('ISO-8859-9')

                if is_nexus and "loader" in x and ">" in x:
                    dut_console.remote_conn.send('reboot\n')
                    continue

                if is_nokia and enter_onie_flag is True:
                    if MARVELL_ENTRY in x:
                        dut_console.remote_conn.send('\n')
                        continue
                    if "Marvell" in x and ">" in x:
                        dut_console.remote_conn.send('run onie_bootcmd\n')
                        continue

                if OS_VERSION_IN_GRUB in x and enter_onie_flag is True:
                    # Send arrow key "down" here.
                    dut_console.remote_conn.send(b'\x1b[B')
                    continue

                if ONIE_ENTRY_IN_GRUB in x and ONIE_INSTALL_MODEL not in x and ONIE_RESCUE_MODEL not in x:
                    dut_console.remote_conn.send("\n")
                    enter_onie_flag = False

                if ONIE_RESCUE_MODEL in x:
                    dut_console.remote_conn.send(b'\x1b[A')
                    dut_console.remote_conn.send("\n")

                if is_celestica and BOOTING_INSTALL_OS in x:
                    dut_console.remote_conn.send("\n")

                # "ONIE: Starting ONIE Service Discovery"
                if ONIE_START_TO_DISCOVERY in x:
                    dut_console.remote_conn.send("\n")

                    # TODO: Define a function to send command here
                    dut_console.remote_conn.send('onie-discovery-stop\n')
                    dut_console.remote_conn.send("\n")

                    if is_nokia:
                        enter_onie_flag = False
                        dut_console.remote_conn.send('umount /dev/sda2\n')

                    dut_console.remote_conn.send("ifconfig eth0 {} netmask {}".format(mgmt_ip.split('/')[0],
                                                 ipaddress.ip_interface(mgmt_ip).with_netmask.split('/')[1]))
                    dut_console.remote_conn.send("\n")

                    dut_console.remote_conn.send("ip route add default via {}".format(gw_ip))
                    dut_console.remote_conn.send("\n")

                    # Remove the image if it already exists
                    dut_console.remote_conn.send("rm -f {}".format(image_url.split("/")[-1]))
                    dut_console.remote_conn.send("\n")

                    dut_console.remote_conn.send("wget {}".format(image_url))
                    dut_console.remote_conn.send("\n")

                    # Waiting downloading finishing
                    for i in range(5):
                        time.sleep(60)
                        x = dut_console.remote_conn.recv(1024)
                        x = x.decode('ISO-8859-9')
                        # If we see "0:00:00", it means we finish downloading sonic image
                        # Sample output:
                        # sonic-mellanox-202012 100% |*******************************|  1196M  0:00:00 ETA
                        if "0:00:00" in x:
                            break

                    dut_console.remote_conn.send("onie-nos-install {}".format(image_url.split("/")[-1]))
                    dut_console.remote_conn.send("\n")

                if SONIC_PROMPT in x:
                    dut_console.remote_conn.close()

                sys.stdout.write(x)
                sys.stdout.flush()
            except socket.timeout:
                pass
        if sys.stdin in r:
            x = sys.stdin.read(1)
            if len(x) == 0:
                break
            dut_console.remote_conn.send(x)


def posix_shell_aboot(dut_console, mgmt_ip, image_url):
    install_image_flag = True
    gw_ip = list(ipaddress.ip_interface(mgmt_ip).network.hosts())[0]
    dut_console.remote_conn.settimeout(0.0)

    while True:
        r, w, e = select.select([dut_console.remote_conn, sys.stdin], [], [])
        if dut_console.remote_conn in r:
            try:
                x = dut_console.remote_conn.recv(65536)
                if len(x) == 0:
                    sys.stdout.write("\r\n*** EOF\r\n")
                    break

                x = x.decode('ISO-8859-9')

                if install_image_flag:
                    # TODO: We can not exactly determine the string in buffer,
                    # TODO: in the future, maybe we will gather the buffer and then process them
                    # "Press Control-C now to enter Aboot shell"
                    if "Press" in x:
                        dut_console.remote_conn.send("\x03")
                        continue

                    if "Aboot" in x and "#" in x:
                        # TODO: Define a function to send command here
                        dut_console.remote_conn.send("cd /mnt/flash")
                        dut_console.remote_conn.send("\n")
                        time.sleep(1)

                        dut_console.remote_conn.send("ifconfig ma1 {} netmask {}".format(mgmt_ip.split('/')[0],
                                                     ipaddress.ip_interface(mgmt_ip).with_netmask.split('/')[1]))
                        dut_console.remote_conn.send("\n")
                        time.sleep(1)

                        dut_console.remote_conn.send("route add default gw {}".format(gw_ip))
                        dut_console.remote_conn.send("\n")
                        time.sleep(1)

                        dut_console.remote_conn.send("ip route add default via {} dev ma1".format(gw_ip))
                        dut_console.remote_conn.send("\n")
                        time.sleep(1)

                        # Remove image to avoid "File exists" error
                        dut_console.remote_conn.send("rm -f {}".format(image_url.split("/")[-1]))
                        dut_console.remote_conn.send("\n")
                        time.sleep(1)

                        dut_console.remote_conn.send("wget {}".format(image_url))
                        dut_console.remote_conn.send("\n")

                        for i in range(5):
                            time.sleep(60)
                            x = dut_console.remote_conn.recv(1024)
                            x = x.decode('ISO-8859-9')
                            if "ETA" in x:
                                break

                        dut_console.remote_conn.send("echo 'SWI=flash:{}' > boot-config"
                                                     .format(image_url.split("/")[-1]))
                        dut_console.remote_conn.send("\n")

                        dut_console.remote_conn.send("reboot")
                        dut_console.remote_conn.send("\n")

                        install_image_flag = False

                if "login:" in x:
                    dut_console.remote_conn.close()

                sys.stdout.write(x)
                sys.stdout.flush()
            except socket.timeout:
                pass
        if sys.stdin in r:
            x = sys.stdin.read(1)
            if len(x) == 0:
                break
            dut_console.remote_conn.send(x)


def do_power_cycle(sonichost, conn_graph_facts, localhost):
    pdu_managers = get_pdu_managers(sonichost, conn_graph_facts)

    for hostname, pdu_manager in pdu_managers.items():
        logger.info("Turn off power outlets to {}".format(hostname))
        pdu_manager.turn_off_outlet()
        localhost.pause(seconds=30, prompt="Pause between power off/on")

    for hostname, pdu_manager in pdu_managers.items():
        logger.info("Turn on power outlets to {}".format(hostname))
        pdu_manager.turn_on_outlet()


def check_sonic_installer(sonichost, sonic_username, sonic_password, sonic_ip, image_url):
    client = pexpect.spawn('ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                           .format(sonic_username, sonic_ip))
    client.expect("admin@{}'s password:".format(sonic_ip))
    client.sendline(sonic_password)
    client.expect(["admin@sonic", "admin@{}".format(sonichost.hostname)])
    client.sendline("sudo sonic_installer install {}"
                    .format(image_url))
    client.expect("New image will be installed")
    client.close()
