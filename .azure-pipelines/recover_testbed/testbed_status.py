import logging
import ipaddress
from dut_connection import duthost_console, get_alt_passwords, get_ssh_info # noqa E402

logger = logging.getLogger(__name__)


def dut_lose_management_ip(sonichost, conn_graph_facts, localhost, mgmt_ip):
    # Recover DUTs
    logger.info("=====Recover start=====")

    # Set the minimum log level due to the security
    netmiko_logger = logging.getLogger("netmiko")
    default_netmiko_logger_level = netmiko_logger.getEffectiveLevel()
    netmiko_logger.setLevel(logging.INFO)

    dut_console = duthost_console(sonichost, conn_graph_facts)
    gw_ip = list(ipaddress.ip_interface(mgmt_ip).network.hosts())[0]
    brd_ip = ipaddress.ip_interface(mgmt_ip).network.broadcast_address
    try:
        sonic_username, _, _ = get_ssh_info(sonichost)
        sonicadmin_alt_passwords = get_alt_passwords(sonichost)
        dut_console.send_command("echo '{}:{}' | sudo chpasswd".format(sonic_username, sonicadmin_alt_passwords[0]))
        netmiko_logger.setLevel(default_netmiko_logger_level)

        dut_console.send_command("sudo mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")

        dut_console.send_command("sudo ip addr add {} brd {} dev eth0".format(mgmt_ip, brd_ip))
        dut_console.send_command("sudo ip route add default via {}".format(gw_ip))

        dut_console.send_command("sudo config save -y")

    except Exception as e:
        logger.info(e)
    finally:
        logger.info("=====Recover finish=====")
        netmiko_logger.setLevel(default_netmiko_logger_level)
        localhost.pause(seconds=120, prompt="Wait for SONiC initialization")
        dut_console.disconnect()
