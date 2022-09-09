"""
    Helpful utilities for writing tests for the syslog feature.
"""
import logging
import time
import os


DUT_PCAP_FILEPATH = "/tmp/test_syslog_tcpdump_{vrf}.pcap"
DOCKER_TMP_PATH = "/tmp/"
TCPDUMP_CAPTURE_TIME = 30
# TSHARK_START_TIME should be smaller than TCPDUMP_CAPTURE_TIME
TSHARK_START_TIME = 5 if 5 < TCPDUMP_CAPTURE_TIME else TCPDUMP_CAPTURE_TIME*0.5


def add_syslog_server(dut, syslog_server_ip, source=None, vrf=None, port=None):
    """
    Add syslog server

    Args:
        dut (SonicHost): The target device
        syslog_server_ip (str): Syslog server address
        source (str): Source ip address
        vrf (str): Vrf device (default,mgmt,Vrf-data)
        port (str): Server udp port

    """
    cmd_add_syslog_server = 'sudo config syslog add {} '.format(syslog_server_ip)
    if source:
        cmd_add_syslog_server = "{} --source {} ".format(cmd_add_syslog_server, source)
    if vrf:
        cmd_add_syslog_server = "{} --vrf {} ".format(cmd_add_syslog_server, vrf)
    if port:
        cmd_add_syslog_server = "{} --port {} ".format(cmd_add_syslog_server, port)
    logging.debug("add_syslog_server command is: {}".format(cmd_add_syslog_server))
    return dut.command(cmd_add_syslog_server, module_ignore_errors=True)


def del_syslog_server(dut, syslog_server_ip):
    """
    Del syslog server

    Args:
        dut (SonicHost): The target device
        syslog_server_ip (str): Syslog server ip
    """
    dut.command('sudo config syslog del {} '.format(syslog_server_ip))


def create_vrf(dut, vrf):
    """
    Create Vrf

    Args:
        dut (SonicHost): The target device
        vrf (str): vrf
    """
    dut.command('sudo config vrf add {} '.format(vrf), module_async=True)


def remove_vrf(dut, vrf):
    """
    Remove Vrf

    Args:
        dut (SonicHost): The target device
        vrf (str): vrf
    """
    return dut.command('sudo config vrf del {} '.format(vrf), module_ignore_errors=True)


def bind_interface_to_vrf(dut, vrf, interface):
    """
    Bind interface to the specified vrf

    Args:
        dut (SonicHost): The target device
        vrf (str): vrf
        interface (str): interface
    """
    dut.command('sudo config interface vrf bind {} {} '.format(interface, vrf))


def replace_ip_neigh(dut, neighbour, neigh_mac_addr, dev):
    """
    replace ip neigh

    Args:
        dut (SonicHost): The target device
        neighbour (str): neighbour
        neigh_mac_addr (str): neighbour mac address
        dev (str): device

    """
    dut.command("sudo ip neigh replace {neighbor} lladdr {neigh_mac_addr} dev {dev}".format(
        neighbor=neighbour,
        neigh_mac_addr=neigh_mac_addr,
        dev=dev))


def capture_syslog_packets(dut, tcpdump_cmd):
    """
    Capture syslog packets

    Args:
        dut (SonicHost): The target device
        tcpdump_cmd (str): tcpdump cmd
    Return: filepath
    """
    logging.info("Start tcpdump: {}".format(tcpdump_cmd))

    pcap_file_full_path = tcpdump_cmd.split("-w")[-1].strip()
    dut.shell("sudo rm -f {}".format(pcap_file_full_path))
    tcpdump_task, tcpdump_result = dut.shell(tcpdump_cmd, module_async=True)
    # wait for starting tcpdump
    time.sleep(TSHARK_START_TIME)

    logging.debug("Generating log message from DUT")
    # Generate syslog msgs from the DUT
    logger_info_msg_count = 20
    for i in range(logger_info_msg_count):
        dut.shell("logger --priority INFO ....{}".format("i"))
        time.sleep(0.2)

    # wait for stoping tcpdump
    tcpdump_task.close()
    tcpdump_task.join()
    dut.fetch(src=pcap_file_full_path, dest=DOCKER_TMP_PATH)
    filepath = os.path.join(DOCKER_TMP_PATH, dut.hostname, pcap_file_full_path.lstrip(os.path.sep))
    return filepath


def is_mgmt_vrf_enabled(dut):
    """
    Check mgmt vrf is enabled or not

    Args:
        dut (SonicHost): The target device
    Return: True or False
    """
    show_mgmt_vrf = dut.command("show mgmt-vrf")["stdout"]
    return "ManagementVRF : Disabled" not in show_mgmt_vrf
