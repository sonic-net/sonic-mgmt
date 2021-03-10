import re
import json
import logging
import ptf.testutils as testutils
import pytest
import time

from ipaddress import ip_network, IPv4Network
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait, wait_until
from tests.common.dualtor.mux_simulator_control import *
from tests.common.dualtor.dual_tor_utils import *

logger = logging.getLogger(__name__)
SYSTEM_STABILIZE_MAX_TIME = 300
MONIT_STABILIZE_MAX_TIME = 420
OMEM_THRESHOLD_BYTES=10485760 # 10MB

__all__ = [
    'check_services',
    'check_interfaces',
    'check_bgp',
    'check_dbmemory',
    'check_monit',
    'check_processes',
    'check_mux_simulator']


@pytest.fixture(scope="module")
def check_services(duthosts):
    def _check():
        check_results = []
        for dut in duthosts:
            logger.info("Checking services status on %s..." % dut.hostname)

            networking_uptime = dut.get_networking_uptime().seconds
            timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
            interval = 20
            logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" % \
                        (networking_uptime, timeout, interval))

            check_result = {"failed": True, "check_item": "services", "host": dut.hostname}
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

            logger.info("Done checking services status on %s" % dut.hostname)
            check_results.append(check_result)
        return check_results
    return _check


def _find_down_phy_ports(dut, phy_interfaces):
    down_phy_ports = []
    intf_facts = dut.show_interface(command='status', include_internal_intfs=('201811' not in dut.os_version))['ansible_facts']['int_status']
    for intf in phy_interfaces:
        try:
            if intf_facts[intf]['oper_state'] == 'down':
                down_phy_ports.append(intf)
        except KeyError:
            down_phy_ports.append(intf)
    return down_phy_ports


def _find_down_ip_ports(dut, ip_interfaces):
    down_ip_ports = []
    ip_intf_facts = dut.show_ip_interface()['ansible_facts']['ip_interfaces']
    for intf in ip_interfaces:
        try:
            if ip_intf_facts[intf]['oper_state'] == 'down':
                down_ip_ports.append(intf)
        except KeyError:
            down_ip_ports.append(intf)
    return down_ip_ports


def _find_down_ports(dut, phy_interfaces, ip_interfaces):
    """Finds the ports which are operationally down

    Args:
        dut (object): The sonichost/sonicasic object
        phy_interfaces (list): List of all phyiscal operation in 'admin_up'
        ip_interfaces (list): List of the L3 interfaces

    Returns:
        [list]: list of the down ports
    """
    down_ports = []
    down_ports = _find_down_ip_ports(dut, ip_interfaces) + \
        _find_down_phy_ports(dut, phy_interfaces)

    return down_ports


@pytest.fixture(scope="module")
def check_interfaces(duthosts):
    def _check():
        check_results = []
        for dut in duthosts.frontend_nodes:
            logger.info("Checking interfaces status on %s..." % dut.hostname)

            networking_uptime = dut.get_networking_uptime().seconds
            timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
            interval = 20
            logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" % \
                        (networking_uptime, timeout, interval))

            down_ports = []
            check_result = {"failed": True, "check_item": "interfaces", "host": dut.hostname}
            for asic in dut.asics:
                ip_interfaces = []
                cfg_facts = asic.config_facts(host=dut.hostname,
                                            source="persistent", verbose=False)['ansible_facts']
                phy_interfaces = [k for k, v in cfg_facts["PORT"].items() if "admin_status" in v and v["admin_status"] == "up"]
                if "PORTCHANNEL_INTERFACE" in cfg_facts:
                    ip_interfaces = cfg_facts["PORTCHANNEL_INTERFACE"].keys()
                if "VLAN_INTERFACE" in cfg_facts:
                    ip_interfaces += cfg_facts["VLAN_INTERFACE"].keys()

                logger.info(json.dumps(phy_interfaces, indent=4))
                logger.info(json.dumps(ip_interfaces, indent=4))

                if timeout == 0:    # Check interfaces status, do not retry.
                    down_ports += _find_down_ports(asic, phy_interfaces, ip_interfaces)
                    check_result["failed"] = True if len(down_ports) > 0 else False
                    check_result["down_ports"] = down_ports
                else:               # Retry checking interface status
                    start = time.time()
                    elapsed = 0
                    while elapsed < timeout:
                        down_ports = _find_down_ports(asic, phy_interfaces, ip_interfaces)
                        check_result["failed"] = True if len(down_ports) > 0 else False
                        check_result["down_ports"] = down_ports

                        if check_result["failed"]:
                            wait(interval, msg="Found down ports, wait %d seconds to retry. Remaining time: %d, down_ports=%s" % \
                                (interval, int(timeout - elapsed), str(check_result["down_ports"])))
                            elapsed = time.time() - start
                        else:
                            break

            logger.info("Done checking interfaces status on %s" % dut.hostname)
            check_result["failed"] = True if len(down_ports) > 0 else False
            check_result["down_ports"] = down_ports
            check_results.append(check_result)
        return check_results
    return _check


@pytest.fixture(scope="module")
def check_bgp(duthosts):
    def _check():
        check_results = []
        for dut in duthosts.frontend_nodes:
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
            check_result = {"failed": False, "check_item": "bgp", "host": dut.hostname}

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
            check_results.append(check_result)

        return check_results
    return _check


def _is_db_omem_over_threshold(command_output):

    total_omem = 0
    re_omem = re.compile("omem=(\d+)")
    result = False

    for line in command_output:
        m = re_omem.search(line)
        if m:
            omem = int(m.group(1))
            total_omem += omem
    logger.debug(json.dumps(command_output, indent=4))
    if total_omem > OMEM_THRESHOLD_BYTES:
        result = True

    return result, total_omem


@pytest.fixture(scope="module")
def check_dbmemory(duthosts):
    def _check():
        check_results = []
        for dut in duthosts:
            logger.info("Checking database memory on %s..." % dut.hostname)
            redis_cmd = "client list"
            check_result = {"failed": False, "check_item": "dbmemory", "host": dut.hostname}
            # check the db memory on the redis instance running on each instance
            for asic in dut.asics:
                res = asic.run_redis_cli_cmd(redis_cmd)['stdout_lines']
                result, total_omem = _is_db_omem_over_threshold(res)
                if result:
                    check_result["failed"] = True
                    check_result["total_omem"] = total_omem
                    logging.info("{} db memory over the threshold ".format(str(asic.namespace or '')))
                    break
            logger.info("Done checking database memory on %s" % dut.hostname)
            check_results.append(check_result)
        return check_results
    return _check


def _check_monit_services_status(check_result, monit_services_status):
    """
    @summary: Check whether each type of service which was monitored by Monit was in correct status or not.
              If a service was in "Not monitored" status, sanity check will skip it since this service
              was temporarily set to not be monitored by Monit.
    @return: A dictionary contains the testing result (failed or not failed) and the status of each service.
    """
    check_result["services_status"] = {}
    for service_name, service_info in monit_services_status.items():
        check_result["services_status"].update({service_name: service_info["service_status"]})
        if service_info["service_status"] == "Not monitored":
            continue
        if ((service_info["service_type"] == "Filesystem" and service_info["service_status"] != "Accessible")
            or (service_info["service_type"] == "Process" and service_info["service_status"] != "Running")
            or (service_info["service_type"] == "Program" and service_info["service_status"] != "Status ok")):
            check_result["failed"] = True

    return check_result


def get_arp_pkt_info(dut):
    intf_mac = dut.facts['router_mac']
    mgmt_ipv4 = None

    mgmt_intf_facts = dut.get_running_config_facts()['MGMT_INTERFACE']

    for mgmt_intf in mgmt_intf_facts:
        for mgmt_ip in mgmt_intf_facts[mgmt_intf]:
            if type(ip_network(mgmt_ip, strict=False)) is IPv4Network:
                mgmt_ipv4 = mgmt_ip.split('/')[0]
                return intf_mac, mgmt_ipv4

    return intf_mac, mgmt_ipv4


@pytest.fixture(scope='module')
def check_mux_simulator(ptf_server_intf, tor_mux_intf, ptfadapter, upper_tor_host, lower_tor_host, \
                        recover_all_directions, toggle_simulator_port_to_upper_tor, toggle_simulator_port_to_lower_tor, check_simulator_read_side):

    def _check():
        """
        @summary: Checks if the OVS bridge mux simulator is functioning correctly
        @return: A dictionary containing the testing result of the PTF interface tested:
            {
                'failed': <True/False>,
                'failed_reason': <reason string>,
                'intf': '<PTF interface name> mux simulator'
            }
        """
        results = {
                    'failed': False,
                    'failed_reason': '',
                    'check_item': '{} mux simulator'.format(ptf_server_intf)
                }

        logger.info("Checking mux simulator status for PTF interface {}".format(ptf_server_intf))
        ptf_port_index = int(ptf_server_intf.replace('eth', ''))
        recover_all_directions(tor_mux_intf)

        upper_tor_intf_mac, upper_tor_mgmt_ip = get_arp_pkt_info(upper_tor_host)
        lower_tor_intf_mac, lower_tor_mgmt_ip = get_arp_pkt_info(lower_tor_host)

        upper_tor_ping_tgt_ip = '10.10.10.1'
        lower_tor_ping_tgt_ip = '10.10.10.2'
        ptf_arp_tgt_ip = '10.10.10.3'
        ping_cmd = 'ping -I {} {} -c 1 -W 1; true'

        upper_tor_exp_pkt = testutils.simple_arp_packet(eth_dst='ff:ff:ff:ff:ff:ff',
                                                        eth_src=upper_tor_intf_mac,
                                                        ip_snd=upper_tor_mgmt_ip,
                                                        ip_tgt=upper_tor_ping_tgt_ip,
                                                        hw_snd=upper_tor_intf_mac)
        lower_tor_exp_pkt = testutils.simple_arp_packet(eth_dst='ff:ff:ff:ff:ff:ff',
                                                        eth_src=lower_tor_intf_mac,
                                                        ip_snd=lower_tor_mgmt_ip,
                                                        ip_tgt=lower_tor_ping_tgt_ip,
                                                        hw_snd=lower_tor_intf_mac)

        ptf_arp_pkt = testutils.simple_arp_packet(ip_tgt=ptf_arp_tgt_ip,
                                                ip_snd=ptf_arp_tgt_ip,
                                                arp_op=2)

        # Clear ARP tables to start in consistent state
        upper_tor_host.shell("ip neigh flush all")
        lower_tor_host.shell("ip neigh flush all")

        # Run tests with upper ToR active
        toggle_simulator_port_to_upper_tor(tor_mux_intf)

        try:
            pytest_assert(check_simulator_read_side(tor_mux_intf) == 1)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Unable to switch active link to upper ToR'
            return results

        # Ping from both ToRs, expect only message from upper ToR to reach PTF
        upper_tor_host.shell(ping_cmd.format(tor_mux_intf, upper_tor_ping_tgt_ip))
        try:
            testutils.verify_packet(ptfadapter, upper_tor_exp_pkt, ptf_port_index)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from active upper ToR not received'
            return results

        lower_tor_host.shell(ping_cmd.format(tor_mux_intf, lower_tor_ping_tgt_ip))
        try:
            testutils.verify_no_packet(ptfadapter, lower_tor_exp_pkt, ptf_port_index)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from standby lower ToR received'
            return results

        # Send dummy ARP packets from PTF to ToR. Ensure that ARP is learned on both ToRs
        upper_tor_host.shell("ip neigh flush all")
        lower_tor_host.shell("ip neigh flush all")
        testutils.send_packet(ptfadapter, ptf_port_index, ptf_arp_pkt)

        upper_tor_arp_table = upper_tor_host.switch_arptable()['ansible_facts']['arptable']['v4']
        lower_tor_arp_table = lower_tor_host.switch_arptable()['ansible_facts']['arptable']['v4']
        try:
            pytest_assert(ptf_arp_tgt_ip in upper_tor_arp_table)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from PTF not received on active upper ToR'
            return results

        try:
            pytest_assert(ptf_arp_tgt_ip in lower_tor_arp_table)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from PTF not received on standby lower ToR'
            return results

        # Repeat all tests with lower ToR active
        toggle_simulator_port_to_lower_tor(tor_mux_intf)
        try:
            pytest_assert(check_simulator_read_side(tor_mux_intf) == 2)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Unable to switch active link to lower ToR'
            return results

        lower_tor_host.shell(ping_cmd.format(tor_mux_intf, lower_tor_ping_tgt_ip))
        try:
            testutils.verify_packet(ptfadapter, lower_tor_exp_pkt, ptf_port_index)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from active lower ToR not received'
            return results

        upper_tor_host.shell(ping_cmd.format(tor_mux_intf, upper_tor_ping_tgt_ip))
        try:
            testutils.verify_no_packet(ptfadapter, upper_tor_exp_pkt, ptf_port_index)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from standby upper ToR received'
            return results

        upper_tor_host.shell("ip neigh flush all")
        lower_tor_host.shell("ip neigh flush all")
        testutils.send_packet(ptfadapter, ptf_port_index, ptf_arp_pkt)

        upper_tor_arp_table = upper_tor_host.switch_arptable()['ansible_facts']['arptable']['v4']
        lower_tor_arp_table = lower_tor_host.switch_arptable()['ansible_facts']['arptable']['v4']
        try:
            pytest_assert(ptf_arp_tgt_ip in upper_tor_arp_table)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from PTF not received on standby upper ToR'
            return results

        try:
            pytest_assert(ptf_arp_tgt_ip in lower_tor_arp_table)
        except AssertionError:
            results['failed'] = True
            results['failed_reason'] = 'Packet from PTF not received on active lower ToR'
            return results

        logger.info('Finished mux simulator check')
        return results
    return _check


@pytest.fixture(scope="module")
def check_monit(duthosts):
    """
    @summary: Check whether the Monit is running and whether the services which were monitored by Monit are
              in the correct status or not.
    @return: A dictionary contains the testing result (failed or not failed) and the status of each service.
    """
    def _check():
        check_results = []
        for dut in duthosts:
            logger.info("Checking status of each Monit service...")
            networking_uptime = dut.get_networking_uptime().seconds
            timeout = max((MONIT_STABILIZE_MAX_TIME - networking_uptime), 0)
            interval = 20
            logger.info("networking_uptime = {} seconds, timeout = {} seconds, interval = {} seconds" \
                        .format(networking_uptime, timeout, interval))

            check_result = {"failed": False, "check_item": "monit", "host": dut.hostname}

            if timeout == 0:
                monit_services_status = dut.get_monit_services_status()
                if not monit_services_status:
                    logger.info("Monit was not running.")
                    check_result["failed"] = True
                    check_result["failed_reason"] = "Monit was not running"
                    logger.info("Checking status of each Monit service was done!")
                    return check_result

                check_result = _check_monit_services_status(check_result, monit_services_status)
            else:
                start = time.time()
                elapsed = 0
                is_monit_running = False
                while elapsed < timeout:
                    check_result["failed"] = False
                    monit_services_status = dut.get_monit_services_status()
                    if not monit_services_status:
                        wait(interval, msg="Monit was not started and wait {} seconds to retry. Remaining time: {}." \
                            .format(interval, timeout - elapsed))
                        elapsed = time.time() - start
                        continue

                    is_monit_running = True
                    check_result = _check_monit_services_status(check_result, monit_services_status)
                    if check_result["failed"]:
                        wait(interval, msg="Services were not monitored and wait {} seconds to retry. Remaining time: {}. Services status: {}" \
                            .format(interval, timeout - elapsed, str(check_result["services_status"])))
                        elapsed = time.time() - start
                    else:
                        break

                if not is_monit_running:
                    logger.info("Monit was not running.")
                    check_result["failed"] = True
                    check_result["failed_reason"] = "Monit was not running"

            logger.info("Checking status of each Monit service was done on %s" % dut.hostname)
            check_results.append(check_result)

        return check_results
    return _check


@pytest.fixture(scope="module")
def check_processes(duthosts):
    def _check():
        check_results = []
        for dut in duthosts:
            logger.info("Checking process status on %s..." % dut.hostname)

            networking_uptime = dut.get_networking_uptime().seconds
            timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
            interval = 20
            logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" % \
                        (networking_uptime, timeout, interval))

            check_result = {"failed": False, "check_item": "processes", "host": dut.hostname}
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
                    check_result["failed"] = False
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

            logger.info("Done checking processes status on %s" % dut.hostname)
            check_results.append(check_result)

        return check_results
    return _check
