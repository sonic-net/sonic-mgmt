"""
    Helpful utilities for writing tests for the syslog feature.
"""
import logging
import time
import os


class syslogUtilsConst:
    DUT_PCAP_FILEPATH = "/tmp/test_syslog_tcpdump_{vrf}_{time}.pcap"
    DOCKER_TMP_PATH = "/tmp/"
    TCPDUMP_CAPTURE_TIME = 50
    # TSHARK_START_TIME should be smaller than TCPDUMP_CAPTURE_TIME
    TSHARK_START_TIME = 5 if 5 < TCPDUMP_CAPTURE_TIME else TCPDUMP_CAPTURE_TIME * 0.5
    PACKETS_NUM = 2


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
    logging.debug("add_syslog_server command is: %s", cmd_add_syslog_server)
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


def check_vrf(dut, vrf):
    """
    Check if Vrf was created

    Args:
        dut (SonicHost): The target device
        vrf (str): vrf
    """
    res = dut.command('sudo show vrf')["stdout"]
    return vrf in res


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


def remove_pcap_file_from_sonic_mgmt(sonic_mgmt_pcap_filepath):
    """
    Remove pcap file from mgmt
    """
    if os.path.exists(sonic_mgmt_pcap_filepath):
        os.remove(sonic_mgmt_pcap_filepath)


def capture_syslog_packets(dut, tcpdump_cmd, logging_data):
    """
    Capture syslog packets

    Args:
        dut (SonicHost): The target device
        tcpdump_cmd (str): tcpdump cmd
    Return: filepath
    """
    logging.info(f"Start tcpdump: {tcpdump_cmd}")

    dut_pcap_filepath = tcpdump_cmd.split("-w")[-1].strip()
    dut.shell("sudo rm -f {}".format(dut_pcap_filepath))
    tcpdump_task, tcpdump_result = dut.shell(tcpdump_cmd, module_async=True)
    # wait for starting tcpdump
    time.sleep(syslogUtilsConst.TSHARK_START_TIME)

    logging.debug("Generating log message from DUT")
    # Generate syslog msgs from the DUT
    default_priority = '--priority CRIT'
    for flag, msg in logging_data:
        for i in range(syslogUtilsConst.PACKETS_NUM):
            dut.shell(f"logger {default_priority} {flag} {msg} {i + 1}")
            time.sleep(0.2)

    # wait for stoping tcpdump
    tcpdump_task.close()
    tcpdump_task.join()

    verify_tcpdump_file_created(dut, dut_pcap_filepath)

    sonic_mgmt_pcap_filepath = os.path.join(syslogUtilsConst.DOCKER_TMP_PATH, dut.hostname,
                                            dut_pcap_filepath.lstrip(os.path.sep))
    # delete previous pcap file from mgmt if exists for clean start
    remove_pcap_file_from_sonic_mgmt(sonic_mgmt_pcap_filepath=sonic_mgmt_pcap_filepath)
    # fetch pcap file from dut to mgmt
    dut.fetch(src=dut_pcap_filepath, dest=syslogUtilsConst.DOCKER_TMP_PATH)
    return sonic_mgmt_pcap_filepath


def verify_tcpdump_file_created(dut, dut_pcap_filepath):
    """
    Verify if tcpdump file was created
    """
    file_check = dut.shell(f"ls -l {dut_pcap_filepath}")
    if file_check['rc'] != 0:
        raise Exception(f"Pcap file was not created: {dut_pcap_filepath}")
