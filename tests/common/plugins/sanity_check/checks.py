import re
import json
import logging
import time

from common.utilities import wait

logger = logging.getLogger(__name__)
SYSTEM_STABILIZE_MAX_TIME = 300
OMEM_THRESHOLD_BYTES=10485760 # 10MB

def check_services(dut):
    logger.info("Checking services status...")

    networking_uptime = dut.get_networking_uptime().seconds
    timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
    interval = 20
    logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" % \
                (networking_uptime, timeout, interval))

    check_result = {"failed": True, "check_item": "services"}
    if timeout == 0:    # Check services status, do not retry.
        services_status = dut.critical_services_status()
        check_result["failed"] = False if all(services_status.values()) else True
        check_result["services_status"] = services_status
    else:               # Retry checking service status
        start = time.time()
        elapsed = 0
        while elapsed < timeout:
            services_status = dut.critical_services_status()
            check_result["failed"] = False if all(services_status.values()) else True
            check_result["services_status"] = services_status

            if check_result["failed"]:
                wait(interval, msg="Not all services are started, wait %d seconds to retry. Remaining time: %d %s" % \
                     (interval, int(timeout - elapsed), str(check_result["services_status"])))
                elapsed = time.time() - start
            else:
                break

    logger.info("Done checking services status.")
    return check_result


def _find_down_ports(dut, interfaces):
    down_ports = []
    intf_facts = dut.interface_facts()['ansible_facts']
    for intf in interfaces:
        try:
            port = intf_facts["ansible_interface_facts"][intf]
            if not port["link"] or not port["active"]:
                down_ports.append(intf)
        except KeyError:
            down_ports.append(intf)
    return down_ports


def check_interfaces(dut):
    logger.info("Checking interfaces status...")

    networking_uptime = dut.get_networking_uptime().seconds
    timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
    interval = 20
    logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" % \
                (networking_uptime, timeout, interval))

    cfg_facts = dut.config_facts(host=dut.hostname, source="persistent")['ansible_facts']
    interfaces = [k for k,v in cfg_facts["PORT"].items() if "admin_status" in v and v["admin_status"] == "up"]
    if "PORTCHANNEL_INTERFACE" in cfg_facts:
        interfaces += cfg_facts["PORTCHANNEL_INTERFACE"].keys()
    if "VLAN_INTERFACE" in cfg_facts:
        interfaces += cfg_facts["VLAN_INTERFACE"].keys()

    logger.info(json.dumps(interfaces, indent=4))

    check_result = {"failed": True, "check_item": "interfaces"}
    if timeout == 0:    # Check interfaces status, do not retry.
        down_ports = _find_down_ports(dut, interfaces)
        check_result["failed"] = True if len(down_ports) > 0 else False
        check_result["down_ports"] = down_ports
    else:               # Retry checking interface status
        start = time.time()
        elapsed = 0
        while elapsed < timeout:
            down_ports = _find_down_ports(dut, interfaces)
            check_result["failed"] = True if len(down_ports) > 0 else False
            check_result["down_ports"] = down_ports

            if check_result["failed"]:
                wait(interval, msg="Found down ports, wait %d seconds to retry. Remaining time: %d, down_ports=%s" % \
                     (interval, int(timeout - elapsed), str(check_result["down_ports"])))
                elapsed = time.time() - start
            else:
                break

    logger.info("Done checking interfaces status.")
    return check_result

def check_dbmemory(dut):
    total_omem = 0
    re_omem = re.compile("omem=(\d+)")
    res = dut.command("/usr/bin/redis-cli client list")
    for l in res['stdout_lines']:
        m = re_omem.search(l)
        if m:
            omem = int(m.group(1))
            total_omem += omem

    logger.info(json.dumps(res['stdout_lines'], indent=4))
    check_result = {"failed": False, "check_item": "dbmemory"}
    if total_omem > OMEM_THRESHOLD_BYTES:
        check_result["failed"] = True
        check_result["total_omem"] = total_omem

    logger.info("Done checking database memory")
    return check_result

def do_checks(dut, check_items):
    results = []
    for item in check_items:
        if item == "services":
            results.append(check_services(dut))
        elif item == "interfaces":
            results.append(check_interfaces(dut))
        elif item == "dbmemory":
            results.append(check_dbmemory(dut))

    return results

def print_logs(dut, print_logs):
    logger.info("Run commands to print logs, logs to be collected:\n%s" % json.dumps(print_logs, indent=4))
    for item in print_logs:
        cmd = print_logs[item]
        res = dut.shell(cmd, module_ignore_errors=True)
        logger.info("cmd='%s', output:\n%s" % (cmd, json.dumps(res["stdout_lines"], indent=4)))
