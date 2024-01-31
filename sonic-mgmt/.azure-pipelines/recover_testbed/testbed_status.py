import logging
import ipaddress
from dut_connection import duthost_ssh, duthost_console # noqa E402

logger = logging.getLogger(__name__)


def dut_lose_management_ip(sonichost, conn_graph_facts, localhost, mgmt_ip):
    # Recover DUTs
    logger.info("=====Recover start=====")
    dut_console = duthost_console(sonichost, conn_graph_facts, localhost)
    gw_ip = list(ipaddress.ip_interface(mgmt_ip).network.hosts())[0]
    brd_ip = ipaddress.ip_interface(mgmt_ip).network.broadcast_address
    try:
        ret = dut_console.send_command("sudo ip addr add {} brd {} dev eth0".format(mgmt_ip, brd_ip))  # noqa F841
        dut_console.send_command("sudo ip route add default via {}".format(gw_ip))
    except Exception as e:
        logging.info(e)
    finally:
        logger.info("=====Recover finish=====")
        dut_console.disconnect()
