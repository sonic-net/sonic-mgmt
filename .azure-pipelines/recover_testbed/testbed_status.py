import logging
import ipaddress
from dut_connection import duthost_ssh, duthost_console # noqa E402

logger = logging.getLogger(__name__)


ADD_MANAGEMENT_IP = "sudo ip addr add {}/23 brd {} dev eth0"
ADD_DEFAULT_IP_ROUTE = "sudo ip route add default via {}"
# add /etc/network/interfaces -- ip, mask, gw

def dut_lose_management_ip(sonichost, conn_graph_facts, localhost, dutip):
    # Recover DUTs
    logger.info("=====Recover start=====")
    dut_console = duthost_console(sonichost, conn_graph_facts, localhost)
    gw_ip = list(ipaddress.ip_interface("{}/23".format(dutip)).network.hosts())[0]
    brd_ip = ipaddress.ip_interface("{}/23".format(dutip)).network.broadcast_address
    try:
        ret = dut_console.send_command(ADD_MANAGEMENT_IP.format(dutip, brd_ip))  # noqa F841
        dut_console.send_command(ADD_DEFAULT_IP_ROUTE.format(gw_ip))
    except Exception as e:
        logging.info(e)
    finally:
        logger.info("=====Recover finish=====")
        dut_console.disconnect()
