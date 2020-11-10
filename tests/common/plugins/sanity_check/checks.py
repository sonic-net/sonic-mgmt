import re
import json
import logging
import time

from tests.common.utilities import wait, wait_until

logger = logging.getLogger(__name__)
SYSTEM_STABILIZE_MAX_TIME = 300
OMEM_THRESHOLD_BYTES=10485760 # 10MB

def check_services(dut):
    logger.info("Checking services status on %s..." % dut.hostname)

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
    logger.info("Checking interfaces status on %s..." % dut.hostname)

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


def check_bgp_status(dut):

    def _check_bgp_status_helper():
        asic_check_results = []
        bgp_facts = dut.bgp_facts(asic_index='all')
        for asic_index, a_asic_facts in enumerate(bgp_facts):
            a_asic_result = False
            a_asic_neighbors = a_asic_facts['ansible_facts']['bgp_neighbors']
            if a_asic_neighbors:
                down_neighbors = [k for k, v in a_asic_neighbors.items()
                                  if v['state'] != 'established']
                if down_neighbors:
                    if dut.facts['num_asic'] == 1:
                        check_result['bgp'] = {'down_neighbors' : down_neighbors }
                    else:
                        check_result['bgp' + str(asic_index)] = {'down_neighbors' : down_neighbors }
                    a_asic_result = True
                else:
                    a_asic_result = False
                    if dut.facts['num_asic'] == 1:
                        if 'bgp' in check_result:
                            check_result['bgp'].pop('down_neighbors', None)
                    else:
                        if 'bgp' + str(asic_index) in check_result:
                            check_result['bgp' + str(asic_index)].pop('down_neighbors', None)
            else:
                a_asic_result = True

            asic_check_results.append(a_asic_result)

        if any(asic_check_results):
            check_result['failed'] = True
        return not check_result['failed']

    logger.info("Checking bgp status on host %s ..." % dut.hostname)
    check_result = {"failed": False, "check_item": "bgp"}

    networking_uptime = dut.get_networking_uptime().seconds
    timeout = max(SYSTEM_STABILIZE_MAX_TIME - networking_uptime, 1)
    interval = 20
    wait_until(timeout, interval, _check_bgp_status_helper)
    if (check_result['failed']):
        for a_result in check_result.keys():
            if a_result != 'failed':
                # Dealing with asic result
                if 'down_neighbors' in check_result[a_result]:
                    logger.info('BGP neighbors down: %s on bgp instance %s on dut %s' % (check_result[a_result]['down_neighbors'], a_result, dut.hostname))
    else:
        logger.info('No BGP neighbors are down on %s' % dut.hostname)

    logger.info("Done checking bgp status on %s" % dut.hostname)
    return check_result

def check_dbmemory(dut):
    logger.info("Checking database memory on %s..." % dut.hostname)

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

def check_processes(dut):
    logger.info("Checking process status on %s..." % dut.hostname)

    networking_uptime = dut.get_networking_uptime().seconds
    timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
    interval = 20
    logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" % \
                (networking_uptime, timeout, interval))

    check_result = {"failed": False, "check_item": "processes"}
    if timeout == 0:    # Check processes status, do not retry.
        processes_status = dut.all_critical_process_status()
        check_result["processes_status"] = processes_status
        check_result["services_status"] = {}
        for k, v in processes_status.items():
            if v['status'] == False or len(v['exited_critical_process']) > 0:
                check_result['failed'] = True
            check_result["services_status"].update({k: v['status']})
    else:               # Retry checking processes status
        start = time.time()
        elapsed = 0
        while elapsed < timeout:
            processes_status = dut.all_critical_process_status()
            check_result["processes_status"] = processes_status
            check_result["services_status"] = {}
            for k, v in processes_status.items():
                if v['status'] == False or len(v['exited_critical_process']) > 0:
                    check_result['failed'] = True
                check_result["services_status"].update({k: v['status']})

            if check_result["failed"]:
                wait(interval, msg="Not all processes are started, wait %d seconds to retry. Remaining time: %d %s" % \
                     (interval, int(timeout - elapsed), str(check_result["processes_status"])))
                elapsed = time.time() - start
            else:
                break

    logger.info("Done checking processes status.")
    return check_result

def do_checks(duthosts, check_items):
    results = {}
    for dut in duthosts:
        results[dut.hostname] = []
        for item in check_items:
            if item == "services":
                results[dut.hostname].append(check_services(dut))
            elif item == "interfaces":
                if dut in duthosts.frontend_nodes:
                    results[dut.hostname].append(check_interfaces(dut))
            elif item == "dbmemory":
                results [dut.hostname].append(check_dbmemory(dut))
            elif item == "processes":
                results[dut.hostname].append(check_processes(dut))
            elif item == "bgp":
                if dut in duthosts.frontend_nodes:
                    results[dut.hostname].append(check_bgp_status(dut))

    return results


def print_logs(duthosts, print_logs):
    for per_host in duthosts:
        logger.info("Run commands to print logs, logs to be collected on %s:\n %s" % (per_host.hostname, json.dumps(print_logs, indent=4)))
        for item in print_logs:
            cmd = print_logs[item]
            res = per_host.shell(cmd, module_ignore_errors=True)
            logger.info("cmd='%s', output:\n%s" % (cmd, json.dumps(res["stdout_lines"], indent=4)))
