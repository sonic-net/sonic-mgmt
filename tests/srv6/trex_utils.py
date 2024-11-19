import os
import re
import ast
import time
import random
import logging
import pprint
import requests
import json
import ipaddress
import pdb
import string

import socket
import datetime

agent_addr = "172.17.0.3"
agent_port = 54500
logger = logging.getLogger(__name__)

def trex_agent_run(cmd):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((agent_addr, agent_port))
        current_time = datetime.datetime.now()

        logger.info("start req:{}, at:{}".format(cmd, current_time))
        s.send(json.dumps(cmd).encode())

        #wait 60 seconds maximum to receive data
        s.settimeout(60)
        data = s.recv(1024)

        if data:
            result = json.loads(data)
            current_time = datetime.datetime.now()
            logger.info("get res:{}, at:{}".format(result, current_time))
            s.close()
            return result
    except Exception as e:
        err_str = "trex_agent_run Error: %s" % e
        logger.info(err_str)

    if s:
        s.close()
    return None

def trex_run(dip, dscp = 0, uni = "", duration = 10, single_stream = False, ingress_pe="", dscp_random = False):
    """
    Run Trex with stream (uni, dip, dscp) for duration seconds. if uni is specified, It is the outer dst IPv6 address.
    Returns packets result on all ports, for example:
        {'ptf_tot_tx': 15001, 'ptf_tot_rx': 15035, 'P3_tx_to_PE2': 3909, 'P3_tx_to_PE1': 3959, 'P1_tx_to_PE2': 3626, 'P1_tx_to_PE1': 3607}
    @param dip - inner dst ipv4/ipv6 address
    @param dscp - inner dscp in ipv4/ipv6 header
    @param uni - if specified, It is the outer dst IPv6 address
    @single_stream - whether to send data in a single stream
    @ingress_pe - can only be PE1/PE2/PE3, by default is PE3
    @dscp_random - send a stream with random dscp
    """
    cmd = {}
    cmd["cmd"] = "run"
    cmd["dip"] = dip
    cmd["dscp"] = dscp
    cmd["uni"] = uni
    cmd["duration"] = duration
    cmd["tag"] = int(time.time())

    if single_stream:
        cmd["single_stream"] = True
    if ingress_pe != "":
        if ingress_pe != "PE1" and ingress_pe != "PE2" and ingress_pe != "PE3":
            logger.info("trex_run: ingress_pe only support PE1 or PE2 or PE3")
            return None

        cmd["ingress_pe"] = ingress_pe

    if dscp_random:
        cmd["dscp_random"] = True

    result = trex_agent_run(cmd)
    return result

def trex_start(dip, dscp = 0, uni = "", single_stream = False, ingress_pe="", dscp_random = False):
    """
    Start Trex with stream (uni, dip, dscp). if uni is specified, It is the outer dst IPv6 address.
    Stream will keep running until you call trex_stop
    @param dip - inner dst ipv4/ipv6 address
    @param dscp - inner dscp in ipv4/ipv6 header
    @param uni - if specified, It is the outer dst IPv6 address
    @single_stream - whether to send data in a single stream
    @ingress_pe - can only be PE1/PE2/PE3, by default is PE3
    @dscp_random - send a stream with random dscp
    """
    cmd = {}
    cmd["cmd"] = "start"
    cmd["dip"] = dip
    cmd["dscp"] = dscp
    cmd["uni"] = uni
    cmd["tag"] = int(time.time())

    if single_stream:
        cmd["single_stream"] = True

    if ingress_pe != "":
        if ingress_pe != "PE1" and ingress_pe != "PE2" and ingress_pe != "PE3":
            logger.info("trex_start: ingress_pe only support PE1 or PE2 or PE3")
            return None

        cmd["ingress_pe"] = ingress_pe

    if dscp_random:
        cmd["dscp_random"] = True

    result = trex_agent_run(cmd)
    return result

def trex_stop(dip, dscp = 0, uni = ""):
    """
    Stop the stream and return packets result on all ports, for example:
        {'ptf_tot_tx': 15001, 'ptf_tot_rx': 15035, 'P3_tx_to_PE2': 3909, 'P3_tx_to_PE1': 3959, 'P1_tx_to_PE2': 3626, 'P1_tx_to_PE1': 3607}
    """
    cmd = {}
    cmd["cmd"] = "stop"
    cmd["dip"] = dip
    cmd["dscp"] = dscp
    cmd["uni"] = uni
    cmd["tag"] = int(time.time())

    result = trex_agent_run(cmd)
    return result

def thresh_check_item(result, field, expected):
    #we allow 1/10 difference maximum
    #if expected == 0, use default difference LIMIT_LOW
    LIMIT_LOW = 200

    if field not in result:
        return False
    num = result[field]
    if expected == 0:
        if num > LIMIT_LOW:
            logger.info("traffic_loss:{} real:{}, expected:{}".format(field, num, expected))
            return False
    elif num > expected and num > expected + expected/5:
        logger.info("traffic_loss:{} real:{}, expected:{}".format(field, num, expected))
        return False
    elif expected > num and expected > num + num/5:
        logger.info("traffic_loss:{} real:{}, expected:{}".format(field, num, expected))
        return False

    return True

def thresh_check(result, check_list):
    #check stream acts as expected

    if "ptf_tot_tx" in check_list and thresh_check_item(result, "ptf_tot_tx", check_list["ptf_tot_tx"]) == False:
        return False

    if "ptf_tot_rx" in check_list and thresh_check_item(result, "ptf_tot_rx", check_list["ptf_tot_rx"]) == False:
        return False

    if "P1_tx_to_PE1" in check_list and thresh_check_item(result, "P1_tx_to_PE1", check_list["P1_tx_to_PE1"]) == False:
        return False

    if "P1_tx_to_PE2" in check_list and thresh_check_item(result, "P1_tx_to_PE2", check_list["P1_tx_to_PE2"]) == False:
        return False

    if "P3_tx_to_PE1" in check_list and thresh_check_item(result, "P3_tx_to_PE1", check_list["P3_tx_to_PE1"]) == False:
        return False

    if "P3_tx_to_PE2" in check_list and thresh_check_item(result, "P3_tx_to_PE2", check_list["P3_tx_to_PE2"]) == False:
        return False

    if "P2_tx_to_P1" in check_list and thresh_check_item(result, "P2_tx_to_P1", check_list["P2_tx_to_P1"]) == False:
        return False

    if "P2_tx_to_P3" in check_list and thresh_check_item(result, "P2_tx_to_P3", check_list["P2_tx_to_P3"]) == False:
        return False

    if "P4_tx_to_P1" in check_list and thresh_check_item(result, "P4_tx_to_P1", check_list["P4_tx_to_P1"]) == False:
        return False

    if "P4_tx_to_P3" in check_list and thresh_check_item(result, "P4_tx_to_P3", check_list["P4_tx_to_P3"]) == False:
        return False

    if "PE3_tx_to_P2" in check_list and thresh_check_item(result, "PE3_tx_to_P2", check_list["PE3_tx_to_P2"]) == False:
        return False

    if "PE3_tx_to_P4" in check_list and thresh_check_item(result, "PE3_tx_to_P4", check_list["PE3_tx_to_P4"]) == False:
        return False

    return True
def check_pkt_drop(result, span):

    if "ptf_tot_tx" not in result or result["ptf_tot_tx"] == 0:
        return False

    if "ptf_tot_rx" not in result:
        return False

    if span <= 0:
        return False

    tx = result["ptf_tot_tx"]
    rx = result["ptf_tot_rx"]

    if tx >= rx:
        num = tx - rx
    else:
        num = rx - tx

    #report error if drop more than 1/5 packets, the tx pps is fixed to 1000
    if num/span > 200:
        logger.info("traffic_drop num:{} tx:{}, rx:{}, span:{}".format(num, tx, rx, span))
        return False

    return True

def check_pkt_single_path(result, span):

    if "ptf_tot_tx" not in result or result["ptf_tot_tx"] == 0:
        return False

    if "ptf_tot_rx" not in result:
        return False

    if span <= 0:
        return False

    recv_path = 0
    if "P1_tx_to_PE1" in result and result["P1_tx_to_PE1"] > span*100:
        recv_path += 1

    if "P1_tx_to_PE2" in result and result["P1_tx_to_PE2"] > span*100:
        recv_path += 1

    if "P3_tx_to_PE1" in result and result["P3_tx_to_PE1"] > span*100:
        recv_path += 1

    if "P3_tx_to_PE2" in result and result["P3_tx_to_PE2"] > span*100:
        recv_path += 1

    #report error if not recv data on only one path
    if recv_path != 1:
        logger.info("check_pkt_single_path fail expected 1 path, but actual path num:{}".format(recv_path))
        return False

    return True

def trex_install(ptfhost):
    TREX_CFG = "srv6/trex_cfg.yaml"
    TREX_SUPERV_FILE = "srv6/trex_supervisor.conf"
    TREX_AGENT = "srv6/trex_agent.py"
    TREX_AGENT_SUPERV_FILE = "srv6/trex_agent_supervisor.conf"

    # install trex server
    ptfhost.copy(src=TREX_CFG, dest="/etc/")
    ptfhost.copy(src=TREX_SUPERV_FILE, dest="/etc/supervisor/conf.d/")
    ptfhost.copy(src=TREX_AGENT, dest="/root/")
    ptfhost.copy(src=TREX_AGENT_SUPERV_FILE, dest="/etc/supervisor/conf.d/")

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')

    logger.info("Start trex and trex_agent")
    #workaround for trex restart issue
    ptfhost.command('supervisorctl stop trex', module_ignore_errors=True)
    time.sleep(10)
    ptfhost.command('supervisorctl start trex')

    ptfhost.command('supervisorctl restart trex_agent')

# def main():
#     #{'cmd': 'start/stop/run', 'dip': '192.168.0.1', 'dscp': 2, 'uni': 'fd00:202:203a:fff0:22::', 'duration': 10}
#     cmd = {}
#     cmd["cmd"] = "run"
#     cmd["dip"] = "192.168.0.1"
#     cmd["tag"] = int(time.time())
#     result = trex_agent_run(cmd)
#     print(result)

# if __name__ == "__main__":
#     main()