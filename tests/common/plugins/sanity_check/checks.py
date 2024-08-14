import re
import json
import logging
import pytest
import time

from tests.common.utilities import wait, wait_until
from tests.common.dualtor.mux_simulator_control import get_mux_status, reset_simulator_port     # noqa F401
from tests.common.dualtor.nic_simulator_control import restart_nic_simulator                    # noqa F401
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR, NIC
from tests.common.dualtor.dual_tor_common import CableType, active_standby_ports                # noqa F401
from tests.common.cache import FactsCache
from tests.common.plugins.sanity_check.constants import STAGE_PRE_TEST, STAGE_POST_TEST
from tests.common.helpers.parallel import parallel_run, reset_ansible_local_tmp
from tests.common.dualtor.mux_simulator_control import _probe_mux_ports
from tests.common.fixtures.duthost_utils import check_bgp_router_id
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)
SYSTEM_STABILIZE_MAX_TIME = 300
MONIT_STABILIZE_MAX_TIME = 500
OMEM_THRESHOLD_BYTES = 10485760     # 10MB
cache = FactsCache()

CHECK_ITEMS = [
    'check_processes',
    'check_interfaces',
    'check_bgp',
    'check_dbmemory',
    'check_monit',
    'check_secureboot',
    'check_neighbor_macsec_empty',
    'check_ipv6_mgmt',
    'check_mux_simulator']

__all__ = CHECK_ITEMS


def _find_down_phy_ports(dut, phy_interfaces):
    down_phy_ports = []
    include_inband_intfs = True if dut.sonichost.get_facts().get(
        'switch_type', None) == 'voq' else False
    intf_facts = dut.show_interface(command='status',
                                    include_internal_intfs=(
                                        '201811' not in dut.os_version),
                                    include_inband_intfs=include_inband_intfs)[
                                        'ansible_facts']['int_status']
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
    init_result = {"failed": False, "check_item": "interfaces"}

    def _check(*args, **kwargs):
        result = parallel_run(_check_interfaces_on_dut, args, kwargs, duthosts.frontend_nodes,
                              timeout=600, init_result=init_result)
        return list(result.values())

    @reset_ansible_local_tmp
    def _check_interfaces_on_dut(*args, **kwargs):
        dut = kwargs['node']
        results = kwargs['results']
        logger.info("Checking interfaces status on %s..." % dut.hostname)

        networking_uptime = dut.get_networking_uptime().seconds
        timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
        interval = 20
        logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" %
                    (networking_uptime, timeout, interval))

        down_ports = []
        check_result = {"failed": True, "check_item": "interfaces", "host": dut.hostname}
        for asic in dut.asics:
            ip_interfaces = []
            cfg_facts = asic.config_facts(host=dut.hostname,
                                          source="persistent", verbose=False)['ansible_facts']
            phy_interfaces = [k for k, v in list(cfg_facts["PORT"].items()) if
                              "admin_status" in v and v["admin_status"] == "up"]
            if "PORTCHANNEL_INTERFACE" in cfg_facts:
                ip_interfaces = list(cfg_facts["PORTCHANNEL_INTERFACE"].keys())
            if "VLAN_INTERFACE" in cfg_facts:
                ip_interfaces += list(cfg_facts["VLAN_INTERFACE"].keys())

            logger.info(json.dumps(phy_interfaces, indent=4))
            logger.info(json.dumps(ip_interfaces, indent=4))

            if timeout == 0:  # Check interfaces status, do not retry.
                down_ports += _find_down_ports(asic, phy_interfaces, ip_interfaces)
                check_result["failed"] = True if len(down_ports) > 0 else False
                check_result["down_ports"] = down_ports
            else:  # Retry checking interface status
                start = time.time()
                elapsed = 0
                while elapsed < timeout:
                    down_ports = _find_down_ports(asic, phy_interfaces, ip_interfaces)
                    check_result["failed"] = True if len(down_ports) > 0 else False
                    check_result["down_ports"] = down_ports

                    if check_result["failed"]:
                        wait(interval,
                             msg="Found down ports, wait %d seconds to retry. Remaining time: %d, down_ports=%s" %
                                 (interval, int(timeout - elapsed), str(check_result["down_ports"])))
                        elapsed = time.time() - start
                    else:
                        break

        logger.info("Done checking interfaces status on %s" % dut.hostname)
        check_result["failed"] = True if len(down_ports) > 0 else False
        check_result["down_ports"] = down_ports
        results[dut.hostname] = check_result
    return _check


@pytest.fixture(scope="module")
def check_bgp(duthosts, tbinfo):
    init_result = {"failed": False, "check_item": "bgp"}

    def _check(*args, **kwargs):
        result = parallel_run(_check_bgp_on_dut, args, kwargs, duthosts.frontend_nodes,
                              timeout=600, init_result=init_result)
        return list(result.values())

    @reset_ansible_local_tmp
    def _check_bgp_on_dut(*args, **kwargs):
        dut = kwargs['node']
        results = kwargs['results']

        def _check_bgp_status_helper():
            asic_check_results = []
            bgp_facts = dut.bgp_facts(asic_index='all')

            # Conditions to fail BGP check
            #   1. No BGP neighbor.
            #   2. Any BGP neighbor down.
            #   3. Failed to get BGP status (In theory, this should be protected by previous check,
            #      but adding this check here will make BGP check more robust,
            #      and it is necessary since many operations highly depends on the BGP status)

            if len(bgp_facts) == 0:
                logger.info("Failed to get BGP status on host %s ..." % dut.hostname)
                asic_check_results.append(True)

            for asic_index, a_asic_facts in enumerate(bgp_facts):
                a_asic_result = False
                a_asic_neighbors = a_asic_facts['ansible_facts']['bgp_neighbors']
                if a_asic_neighbors is not None and len(a_asic_neighbors) > 0:
                    down_neighbors = [k for k, v in list(a_asic_neighbors.items())
                                      if v['state'] != 'established']
                    if down_neighbors:
                        if dut.facts['num_asic'] == 1:
                            check_result['bgp'] = {'down_neighbors': down_neighbors}
                        else:
                            check_result['bgp' + str(asic_index)] = {'down_neighbors': down_neighbors}
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
            else:
                # Need this to cover case where there were down neighbors in one check and now they are all up
                check_result['failed'] = False
            return not check_result['failed']

        logger.info("Checking bgp status on host %s ..." % dut.hostname)
        check_result = {"failed": False, "check_item": "bgp", "host": dut.hostname}

        # If the topology doesn't have any VMs, it is not using BGP feature at all, hence skip checking
        # the BGP status here.
        if len(tbinfo['topo']['properties']['topology']['VMs']) == 0:
            logger.info("No VMs in topology, skip checking bgp status on host %s ..." % dut.hostname)
            results[dut.hostname] = check_result
            return

        networking_uptime = dut.get_networking_uptime().seconds
        if SYSTEM_STABILIZE_MAX_TIME - networking_uptime + 480 > 500:
            # If max_timeout is higher than 600, it will exceed parallel_run's timeout
            # the check will be killed by parallel_run, we can't get expected results.
            # 500 seconds is about 8 mins, bgp has enough to get up
            max_timeout = 500
        else:
            max_timeout = SYSTEM_STABILIZE_MAX_TIME - networking_uptime + 480
        timeout = max(max_timeout, 1)
        interval = 20
        wait_until(timeout, interval, 0, _check_bgp_status_helper)
        if (check_result['failed']):
            for a_result in list(check_result.keys()):
                if a_result != 'failed':
                    # Dealing with asic result
                    if 'down_neighbors' in check_result[a_result]:
                        logger.info('BGP neighbors down: %s on bgp instance %s on dut %s' % (
                            check_result[a_result]['down_neighbors'], a_result, dut.hostname))
        else:
            logger.info('No BGP neighbors are down on %s' % dut.hostname)

        mgFacts = dut.get_extended_minigraph_facts(tbinfo)
        if dut.num_asics() == 1 and tbinfo['topo']['type'] != 't2' and \
           not wait_until(timeout, interval, 0, check_bgp_router_id, dut, mgFacts):
            check_result['failed'] = True
            logger.info("Failed to verify BGP router identifier is Loopback0 address on %s" % dut.hostname)

        logger.info("Done checking bgp status on %s" % dut.hostname)
        results[dut.hostname] = check_result

    return _check


def _is_db_omem_over_threshold(command_output):

    total_omem = 0
    re_omem = re.compile(r"omem=(\d+)")
    result = False
    non_zero_output = []

    for line in command_output:
        m = re_omem.search(line)
        if m:
            omem = int(m.group(1))
            total_omem += omem
            if omem > 0:
                non_zero_output.append(line)
    logger.debug('total_omen={}, OMEM_THRESHOLD_BYTES={}'.format(total_omem, OMEM_THRESHOLD_BYTES))
    if total_omem > OMEM_THRESHOLD_BYTES:
        result = True

    return result, total_omem, non_zero_output


@pytest.fixture(scope="module")
def check_dbmemory(duthosts):
    def _check(*args, **kwargs):
        init_result = {"failed": False, "check_item": "dbmemory"}
        result = parallel_run(_check_dbmemory_on_dut, args, kwargs, duthosts, timeout=600, init_result=init_result)
        return list(result.values())

    @reset_ansible_local_tmp
    def _check_dbmemory_on_dut(*args, **kwargs):
        dut = kwargs['node']
        results = kwargs['results']

        logger.info("Checking database memory on %s..." % dut.hostname)
        redis_cmd = "client list"
        check_result = {"failed": False, "check_item": "dbmemory", "host": dut.hostname}
        # check the db memory on the redis instance running on each instance
        for asic in dut.asics:
            res = asic.run_redis_cli_cmd(redis_cmd)['stdout_lines']
            result, total_omem, non_zero_output = _is_db_omem_over_threshold(res)
            check_result["total_omem"] = total_omem
            if result:
                check_result["failed"] = True
                logging.info("{} db memory over the threshold ".format(str(asic.namespace or '')))
                logging.info("{} db memory omem non-zero output: \n{}"
                             .format(str(asic.namespace or ''), "\n".join(non_zero_output)))
                break
        logger.info("Done checking database memory on %s" % dut.hostname)
        results[dut.hostname] = check_result
    return _check


def _check_monit_services_status(check_result, monit_services_status):
    """
    @summary: Check whether each type of service which was monitored by Monit was in correct status or not.
              If a service was in "Not monitored" status, sanity check will skip it since this service
              was temporarily set to not be monitored by Monit.
    @return: A dictionary contains the testing result (failed or not failed) and the status of each service.
    """
    check_result["services_status"] = {}
    for service_name, service_info in list(monit_services_status.items()):
        check_result["services_status"].update({service_name: service_info["service_status"]})
        if service_info["service_status"] == "Not monitored":
            continue
        if ((service_info["service_type"] == "Filesystem" and service_info["service_status"] != "Accessible")
                or (service_info["service_type"] == "Process" and service_info["service_status"] != "Running")
                or (service_info["service_type"] == "Program" and service_info["service_status"] != "Status ok")):
            check_result["failed"] = True

    return check_result


def _check_intf_names(intf_status, active_intf, mux_intf, expected_side):
    '''
    Checks that the interface names for the mux are correct

    1. The reported active side (upper or lower ToR) must match expected
    2. The active side interface name must match the ports list returned by the mux
    3. The server/NIC interface name must match the portsr list returned by the mux
    '''
    bridge = intf_status['bridge']
    failed = False
    failed_reason = ''
    # Verify correct active ToR
    if intf_status['active_side'] != expected_side:
        failed = True
        failed_reason = 'Active side mismatch for {}, got {} but expected {}' \
                        .format(bridge, intf_status['active_side'], expected_side)
        return failed, failed_reason

    # Verify correct active ToR interface name
    if active_intf is not None and active_intf != intf_status['ports'][expected_side]:
        failed = True
        failed_reason = 'Active interface name mismatch for {}, got {} but expected {}' \
                        .format(bridge, active_intf, intf_status['ports'][expected_side])
        return failed, failed_reason

    # Verify correct server interface name
    if mux_intf is not None and mux_intf != intf_status['ports'][NIC]:
        failed = True
        failed_reason = 'NIC interface name mismatch for {}, got {} but expected {}' \
                        .format(bridge, mux_intf, intf_status['ports'][NIC])
        return failed, failed_reason

    return failed, failed_reason


def _check_server_flows(intf_status, mux_flows):
    '''
    Checks that the flows originating from the server/NIC port are correct

    1. Checks that there are exactly two flows (one per ToR)
    2. Checks that for each flow, the action is output
    3. Checks that for each flow, the output port is one of the ToR interfaces
        a. Also checks that each ToR interface is used exactly once

    '''
    failed = False
    failed_reason = ''
    bridge = intf_status['bridge']
    # Checking server flows
    if len(mux_flows) != 2:
        failed = True
        failed_reason = 'Incorrect number of mux flows for {}, got {} but expected 2' \
                        .format(bridge, len(mux_flows))
        return failed, failed_reason

    tor_intfs = [intf_status['ports'][UPPER_TOR], intf_status['ports'][LOWER_TOR]]

    # Each flow should be set to output and have the output interface
    # as one of the ToR interfaces
    for flow in mux_flows:
        if flow['action'] != 'output':
            failed = True
            failed_reason = 'Incorrect mux flow action for {}, got {} but expected output' \
                            .format(bridge, flow['action'])
            return failed, failed_reason

        if flow['out_port'] not in tor_intfs:
            failed = True
            failed_reason = 'Incorrect ToR output interface for {}, got {} but expected one of {}' \
                            .format(bridge, flow['out_port'], tor_intfs)
            return failed, failed_reason
        else:
            # Remove already seen ToR intfs from consideration to catch
            # duplicate output ports
            tor_intfs.remove(flow['out_port'])

    return failed, failed_reason


def _check_tor_flows(active_flows, mux_intf, bridge):
    '''
    Checks that the flows originationg from the active ToR are correct

    1. Checks that there is exactly one flow (for the server/NIC)
    2. Checks that the action is output
    3. Checks that the out port is the server/NIC interface
    '''
    failed = False
    failed_reason = ''

    # Checking active ToR flows
    if len(active_flows) != 1:
        failed = True
        failed_reason = 'Incorrect number of active ToR flows for {}, got {} but expected 1' \
                        .format(bridge, len(active_flows))
        return failed, failed_reason

    if active_flows[0]['action'] != 'output':
        failed = True
        failed_reason = 'Incorrect active ToR action for {}, got {} but expected output' \
                        .format(bridge, active_flows[0]['action'])
        return failed, failed_reason

    if active_flows[0]['out_port'] != mux_intf:
        failed = True
        failed_reason = 'Incorrect active ToR flow output interface for {}, got {} but expected {}' \
                        .format(bridge, active_flows[0]['out_port'], mux_intf)
        return failed, failed_reason

    return failed, failed_reason


def _check_single_intf_status(intf_status, expected_side):
    """
    Checks the mux simulator status for a single ToR/server connection
    """
    failed = False
    failed_reason = ''

    bridge = intf_status['bridge']

    # Check the total number of flows is 2, one for
    # server to both ToRs and one for active ToR to server
    if len(intf_status['flows']) != 2:
        failed = True
        failed_reason = 'Incorrect number of flows for {}, got {} but expected 2' \
                        .format(bridge, len(intf_status['flows']))
        return failed, failed_reason

    if not intf_status['healthy']:
        failed = True
        failed_reason = 'Mux simulator reported unhealthy mux for {} with flows {}' \
                        .format(bridge, intf_status['flows'])
        return failed, failed_reason

    # Gather the flow information
    active_intf, mux_intf = None, None
    active_flows, mux_flows = None, None

    for input_intf, actions in list(intf_status['flows'].items()):
        if 'mu' in input_intf:
            mux_intf = input_intf
            mux_flows = actions
        else:
            # Since we have already ensured there are exactly 2 flows
            # The flow which is not originating from the NIC must be
            # the flow for the active ToR
            active_intf = input_intf
            active_flows = actions

    failed, failed_reason = _check_intf_names(intf_status, active_intf, mux_intf, expected_side)

    if not failed:
        failed, failed_reason = _check_server_flows(intf_status, mux_flows)

    if not failed:
        failed, failed_reason = _check_tor_flows(active_flows, mux_intf, bridge)

    return failed, failed_reason


def _check_dut_mux_status(duthosts, duts_minigraph_facts, **kwargs):

    def _verify_show_mux_status(**kwargs):
        dut = kwargs['node']
        results = kwargs['results']
        dut_mux_status = dut.show_and_parse("show mux status")

        dut_parsed_mux_status = {}
        dut_wrong_mux_status_ports = []
        check_result = {"failed": False, "check_item": "check_mux_simulator", "host": dut.hostname, "error_msg": []}
        logger.info('Verify that "show mux status" has output ON {}'.format(dut.hostname))
        if len(dut_mux_status) != len(port_cable_types):
            check_result["error_msg"] = "Some ports doesn't have 'show mux status' output"
            check_result["failed"] = True

        dut_parsed_mux_status = {}
        for row in dut_mux_status:
            if row["status"] not in ("active", "standby"):
                check_result["error_msg"].append('Unexpected mux status "{}", please check output of "show mux status"'
                                                 .format(row['status']))
                dut_wrong_mux_status_ports.append(row['port'])

            port_name = row['port']
            port_idx = str(duts_minigraph_facts[dut.hostname][0][1]['minigraph_port_indices'][port_name])
            mux_status = 0 if row["status"] == "standby" else 1
            dut_parsed_mux_status[port_idx] = {"status": mux_status, "cable_type": port_cable_types[port_idx]}
            if "hwstatus" in row:
                dut_parsed_mux_status[port_idx]["hwstatus"] = row["hwstatus"]

        check_result["parsed_mux_status"] = dut_parsed_mux_status

        if len(dut_wrong_mux_status_ports) != 0:
            check_result["failed"] = True

        results[dut.hostname] = check_result

    def _verify_inconsistent_mux_status(duts_parsed_mux_status, dut_upper_tor, dut_lower_tor):
        logger.info('Verify that the mux status on both ToRs are consistent')
        upper_tor_mux_status = duts_parsed_mux_status[dut_upper_tor.hostname]
        lower_tor_mux_status = duts_parsed_mux_status[dut_lower_tor.hostname]

        logger.info('Verify that mux status is consistent on both ToRs.')
        for port_idx, cable_type in list(port_cable_types.items()):
            if cable_type == CableType.active_standby:
                if (upper_tor_mux_status[port_idx]['status'] ^ lower_tor_mux_status[port_idx]['status']) == 0:
                    err_msg_from_mux_status.append('Inconsistent mux status for active-standby ports on dualtors, \
                                                   please check output of "show mux status"')
                    dut_wrong_mux_status_ports.append(port_idx)
            if cable_type == CableType.active_active:
                logger.debug('Verify that active-active ports:{}'.format(duts_parsed_mux_status))
                if (upper_tor_mux_status[port_idx]['status'] != 1 or lower_tor_mux_status[port_idx]['status'] != 1):
                    err_msg_from_mux_status.append('Inconsistent mux status for active-active ports on dualtors, \
                                                   please check output of "show mux status"')
                    dut_wrong_mux_status_ports.append(port_idx)

        if len(dut_wrong_mux_status_ports) != 0:
            return False

        logger.info('Check passed, return parsed mux status')
        err_msg_from_mux_status.append("")
        return True

    def _check_mux_status_helper():
        run_result.clear()
        duts_parsed_mux_status.clear()
        err_msg_from_mux_status[:] = []
        dut_wrong_mux_status_ports[:] = []
        run_result.update(
            **parallel_run(_verify_show_mux_status, (), kwargs, duthosts, timeout=600, init_result=init_result)
        )
        duts_parsed_mux_status[dut_upper_tor.hostname] = run_result[dut_upper_tor.hostname]["parsed_mux_status"]
        duts_parsed_mux_status[dut_lower_tor.hostname] = run_result[dut_lower_tor.hostname]["parsed_mux_status"]
        return (all(result['failed'] is False for result in run_result.values()) and
                _verify_inconsistent_mux_status(duts_parsed_mux_status, dut_upper_tor, dut_lower_tor))

    dut_upper_tor = duthosts[0]
    dut_lower_tor = duthosts[1]

    if dut_upper_tor.is_multi_asic or dut_lower_tor.is_multi_asic:
        err_msg = 'Multi-asic hwsku not supported for DualTor Topology as of now'
        return False, err_msg, {}

    duts_mux_config = duthosts.show_and_parse("show mux config", start_line_index=3)
    upper_tor_mux_config = duts_mux_config[dut_upper_tor.hostname]
    lower_tor_mux_config = duts_mux_config[dut_lower_tor.hostname]
    if upper_tor_mux_config != lower_tor_mux_config:
        err_msg = "'show mux config' output differs between two ToRs {} v.s. {}"\
            .format(upper_tor_mux_config, lower_tor_mux_config)
        return False, err_msg, {}

    port_cable_types = {}

    for row in upper_tor_mux_config:
        port_name = row["port"]
        port_idx = str(duts_minigraph_facts[dut_upper_tor.hostname][0][1]['minigraph_port_indices'][port_name])
        if "cable_type" in row:
            if row["cable_type"] and row["cable_type"] not in (CableType.active_active, CableType.active_standby):
                err_msg = "Unsupported cable type %s for %s" % (row["cable_type"], port_name)
                return False, err_msg, {}
            elif row["cable_type"]:
                port_cable_types[port_idx] = row["cable_type"]
            else:
                port_cable_types[port_idx] = CableType.default_type
        else:
            port_cable_types[port_idx] = CableType.default_type

    duts_parsed_mux_status = {}
    err_msg_from_mux_status = []
    dut_wrong_mux_status_ports = []

    init_result = {"failed": False, "check_item": "check_mux_simulator"}
    run_result = {}

    check_success = _check_mux_status_helper()

    for result in run_result.values():
        if result['failed'] is True:
            err_msg = result["error_msg"][-1]
            return False, err_msg, {}

    if not check_success:
        if len(dut_wrong_mux_status_ports) != 0:
            # NOTE: Let's probe here to see if those inconsistent mux ports could be
            # restored before using the recovery method.
            port_index_map = duts_minigraph_facts[duthosts[0].hostname][0][1]['minigraph_port_indices']
            dut_wrong_mux_status_ports = list(set(dut_wrong_mux_status_ports))
            inconsistent_mux_ports = [port for port, port_index in port_index_map.items()
                                      if port_index in dut_wrong_mux_status_ports]
            _probe_mux_ports(duthosts, inconsistent_mux_ports)
        if not wait_until(60, 10, 0, _check_mux_status_helper):
            if err_msg_from_mux_status:
                err_msg = err_msg_from_mux_status[-1]
            else:
                err_msg = "Unknown error occured inside the check"
            return False, err_msg, {}

    # FIXME: Enable the check for hwstatus
    # for dut_mux_status in duts_parsed_mux_status.values():
    #     for port_mux_status in dut_mux_status.values():
    #         if "hwstatus" in port_mux_status and port_mux_status["hwstatus"].lower() != "consistent":
    #             err_msg = "'show mux status' shows inconsistent for HWSTATUS"
    #             return False, err_msg, {}

    return True, "", duts_parsed_mux_status


@pytest.fixture(scope='module')
def check_mux_simulator(tbinfo, duthosts, duts_minigraph_facts, get_mux_status,     # noqa F811
                        reset_simulator_port, restart_nic_simulator,                # noqa F811
                        active_standby_ports):                                      # noqa F811
    def _recover():
        duthosts.shell('config muxcable mode auto all; config save -y')
        if active_standby_ports:
            reset_simulator_port()
        restart_nic_simulator()

    def _check(*args, **kwargs):
        """
        @summary: Checks if the OVS bridge mux simulator is functioning correctly
        @return: A dictionary containing the testing result of the PTF interface tested:
            {
                'check_item': 'mux_simulator',
                'failed': <True/False>,
                'failed_reason': <reason string>,
                'action': <recovery function>
            }
        """
        logger.info("Checking mux simulator status")
        results = {
                    'failed': False,
                    'failed_reason': '',
                    'check_item': 'mux_simulator',
                    'action': None
                }

        failed = False
        reason = ''

        check_passed, err_msg, duts_mux_status = _check_dut_mux_status(duthosts, duts_minigraph_facts, **kwargs)
        if not check_passed:
            logger.warning(err_msg)
            results['failed'] = True
            results['failed_reason'] = err_msg
            results['hosts'] = [dut.hostname for dut in duthosts]
            results['action'] = _recover
            return results

        mux_simulator_status = get_mux_status()
        upper_tor_mux_status = duts_mux_status[duthosts[0].hostname]

        for status in list(mux_simulator_status.values()):
            port_index = str(status['port_index'])

            # Some host interfaces in dualtor topo are disabled.
            # We only care about status of mux for the enabled host interfaces
            if port_index in upper_tor_mux_status and upper_tor_mux_status[port_index]["cable_type"] \
                    == CableType.active_standby:
                active_side = UPPER_TOR if upper_tor_mux_status[port_index]["status"] == 1 else LOWER_TOR
                failed, reason = _check_single_intf_status(status, expected_side=active_side)

            if failed:
                logger.warning('Mux sanity check failed for status:\n{}'.format(status))
                results['failed'] = failed
                results['failed_reason'] = reason
                results['action'] = _recover
                return results

        return results

    return _check


@pytest.fixture(scope="module")
def check_monit(duthosts):
    """
    @summary: Check whether the Monit is running and whether the services which were monitored by Monit are
              in the correct status or not.
    @return: A dictionary contains the testing result (failed or not failed) and the status of each service.
    """
    def _check(*args, **kwargs):
        init_result = {"failed": False, "check_item": "monit"}
        result = parallel_run(_check_monit_on_dut, args, kwargs, duthosts, timeout=600, init_result=init_result)
        return list(result.values())

    @reset_ansible_local_tmp
    def _check_monit_on_dut(*args, **kwargs):
        dut = kwargs['node']
        results = kwargs['results']

        logger.info("Checking status of each Monit service...")
        networking_uptime = dut.get_networking_uptime().seconds
        timeout = max((MONIT_STABILIZE_MAX_TIME - networking_uptime), 0)
        interval = 20
        logger.info("networking_uptime = {} seconds, timeout = {} seconds, interval = {} seconds"
                    .format(networking_uptime, timeout, interval))

        check_result = {"failed": False, "check_item": "monit", "host": dut.hostname}

        if timeout == 0:
            monit_services_status = dut.get_monit_services_status()
            if not monit_services_status:
                logger.info("Monit was not running.")
                check_result["failed"] = True
                check_result["failed_reason"] = "Monit was not running"
                logger.info("Checking status of each Monit service was done!")
                results[dut.hostname] = check_result
                return

            check_result = _check_monit_services_status(check_result, monit_services_status)
        else:
            start = time.time()
            elapsed = 0
            is_monit_running = False
            while elapsed < timeout:
                check_result["failed"] = False
                monit_services_status = dut.get_monit_services_status()
                if not monit_services_status:
                    wait(interval, msg="Monit was not started and wait {} seconds to retry. Remaining time: {}."
                         .format(interval, timeout - elapsed))
                    elapsed = time.time() - start
                    continue

                is_monit_running = True
                check_result = _check_monit_services_status(check_result, monit_services_status)
                if check_result["failed"]:
                    wait(interval,
                         msg="Services were not monitored and wait {} seconds to retry. \
                             Remaining time: {}. Services status: {}"
                         .format(interval, timeout - elapsed, str(check_result["services_status"])))
                    elapsed = time.time() - start
                else:
                    break

            if not is_monit_running:
                logger.info("Monit was not running.")
                check_result["failed"] = True
                check_result["failed_reason"] = "Monit was not running"

        logger.info("Checking status of each Monit service was done on %s" % dut.hostname)
        results[dut.hostname] = check_result
    return _check


@pytest.fixture(scope="module")
def check_processes(duthosts):
    def _check(*args, **kwargs):
        init_result = {"failed": False, "check_item": "processes"}
        timeout = 600
        # Increase the timeout for multi-asic virtual switch DUT.
        for node in duthosts.nodes:
            if 'kvm' in node.sonichost.facts['platform'] and node.sonichost.is_multi_asic:
                timeout = 1000
                break
        result = parallel_run(_check_processes_on_dut, args, kwargs, duthosts, timeout=timeout, init_result=init_result)
        return list(result.values())

    @reset_ansible_local_tmp
    def _check_processes_on_dut(*args, **kwargs):
        dut = kwargs['node']
        results = kwargs['results']
        logger.info("Checking process status on %s..." % dut.hostname)

        networking_uptime = dut.get_networking_uptime().seconds
        timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 0)
        interval = 20
        logger.info("networking_uptime=%d seconds, timeout=%d seconds, interval=%d seconds" %
                    (networking_uptime, timeout, interval))

        check_result = {"failed": False, "check_item": "processes", "host": dut.hostname}
        if timeout == 0:  # Check processes status, do not retry.
            processes_status = dut.all_critical_process_status()
            check_result["processes_status"] = processes_status
            check_result["services_status"] = {}
            for container_name, processes in list(processes_status.items()):
                if processes['status'] is False or len(processes['exited_critical_process']) > 0:
                    logger.info("The status of checking process in container '{}' is: {}"
                                .format(container_name, processes["status"]))
                    logger.info("The processes not running in container '{}' are: '{}'"
                                .format(container_name, processes["exited_critical_process"]))
                    check_result['failed'] = True
                check_result["services_status"].update({container_name: processes['status']})
        else:  # Retry checking processes status
            start = time.time()
            elapsed = 0
            while elapsed < timeout:
                check_result["failed"] = False
                processes_status = dut.all_critical_process_status()
                check_result["processes_status"] = processes_status
                check_result["services_status"] = {}
                for container_name, processes in list(processes_status.items()):
                    if processes['status'] is False or len(processes['exited_critical_process']) > 0:
                        logger.info("The status of checking process in container '{}' is: {}"
                                    .format(container_name, processes["status"]))
                        logger.info("The processes not running in container '{}' are: '{}'"
                                    .format(container_name, processes["exited_critical_process"]))
                        check_result['failed'] = True
                    check_result["services_status"].update({container_name: processes['status']})

                if check_result["failed"]:
                    wait(interval,
                         msg="Not all processes are started, wait %d seconds to retry. Remaining time: %d %s" %
                             (interval, int(timeout - elapsed), str(check_result["processes_status"])))
                    elapsed = time.time() - start
                else:
                    break

        logger.info("Done checking processes status on %s" % dut.hostname)
        results[dut.hostname] = check_result
    return _check


@pytest.fixture(scope="module")
def check_secureboot(duthosts, request):
    """
    Check if the file change in rw folder is as expected when secureboot feature enabled
    If the file change is only for test, not for product, please add the change in the default_allowlist below
    """

    default_allowlist = [r".*\.pyc"]
    cache_location = 'secureboot_sanity_check'
    module = request.module.__name__

    def _read_config_by_dut(duthost):
        results = {}

        # Check if secure boot enabled
        check_secureboot_cmd = r"grep -q 'secure_boot_enable=y' /proc/cmdline && echo y"
        shell_result = duthost.shell(check_secureboot_cmd, module_ignore_errors=True)
        if shell_result['stdout'].strip() != 'y':
            logger.info("Skipped to check secure boot for dut %s, since the secure boot is not enabled"
                        % duthost.hostname)
            return results

        # Read the allowlist
        allowlist = []
        results['allowlist'] = allowlist
        read_allowlist_cmd = r"IMAGE=$(sed 's#.* loop=\(.*\)/.*#\1#' /proc/cmdline); \
            unzip -p /host/$IMAGE/sonic.swi allowlist_paths.conf"
        shell_result = duthost.shell(read_allowlist_cmd, module_ignore_errors=True)
        stdout = shell_result['stdout']
        for line in stdout.split('\n'):
            line = line.strip()
            if len(line) > 0:
                allowlist.append(line)
        logger.info("Read %d allowlist settings from dut %s" % (len(allowlist), duthost.hostname))

        # Read the rw files
        rw_files = {}
        results['rw'] = rw_files
        ls_rw_files_cmd = r"IMAGE=$(sed 's#.* loop=\(.*\)/.*#\1#' /proc/cmdline); \
            find /host/$IMAGE/rw -type f -exec md5sum {} \; | sed -E 's#/host/[^/]+/rw/##g'"
        shell_result = duthost.shell(ls_rw_files_cmd, module_ignore_errors=True)
        stdout = shell_result['stdout']
        for line in stdout.split('\n'):
            line = line.strip()
            if len(line) > 33:
                filename = line[33:].strip()
                rw_files[filename] = line[:32]      # md5sum
        logger.info("Read %d rw files from dut %s" % (len(rw_files), duthost.hostname))

        return results

    def _read_configs():
        results = {}
        for duthost in duthosts:
            config = _read_config_by_dut(duthost)
            if config:
                results[duthost.hostname] = config
        return results

    def _do_check(allowlist, filenames, hostname):
        conflicts = []
        allowlist_all = default_allowlist + allowlist
        pattern = '|'.join(allowlist_all)
        pattern = '^%s$' % pattern
        for filename in filenames:
            if not re.match(pattern, filename):
                logger.error('Unexpected change file found: %s' % filename)
                conflicts.append(filename)

        return conflicts

    def _pre_check():
        configs = _read_configs()
        cache.write(cache_location, module, configs)

    def _post_check():
        check_results = []
        old_configs = cache.read(cache_location, module)
        if not old_configs:
            old_configs = {}
        new_configs = _read_configs()
        for hostname in new_configs:
            new_config = new_configs[hostname]
            new_files = new_config['rw']
            allowlist = new_config['allowlist']
            old_config = old_configs.get(hostname, {})
            old_files = old_config.get('rw', {})
            change_files = {}
            for filename in new_files:
                if filename not in old_files or old_files[filename] != new_files[filename]:
                    change_files[filename] = hostname

            # Check if the file change is expected
            check_result = {"failed": False, "check_item": "secureboot", "host": hostname}
            conflicts = _do_check(allowlist, change_files, hostname)
            if conflicts:
                check_result["failed"] = True
                reason = 'Unexpected change files: %s in %s' % (','.join(conflicts), hostname)
                check_result["failed_reason"] = reason
            check_results.append(check_result)

        return check_results

    def _check(*args, **kwargs):
        check_results = []
        stage = kwargs.get('stage', None)

        if stage == STAGE_PRE_TEST:
            _pre_check()
        elif stage == STAGE_POST_TEST:
            check_results = _post_check()
        if not check_results:
            check_result = {"failed": False, "check_item": "secureboot"}
            check_results.append(check_result)

        return check_results
    return _check


@pytest.fixture(scope="module")
def check_neighbor_macsec_empty(ctrl_links):
    nodes = []
    nodes_name = set()
    dut_nbr_mapping = {}
    for _, nbr in list(ctrl_links.items()):
        if nbr["name"] in nodes_name:
            continue
        nodes_name.add(nbr["name"])
        nodes.append({
            "nbr_host": nbr["host"],
            "nbr_name": nbr["name"]})
        dut_nbr_mapping[nbr["name"]] = nbr["dut_name"]

    def _check_macsec_empty(*args, **kwargs):
        node = kwargs['node']
        results = kwargs['results']
        check_result = len(node["nbr_host"].command("ip macsec show")["stdout_lines"]) > 0
        results[node["nbr_name"]] = check_result

    def _check(*args, **kwargs):
        init_check_result = {"failed": False, "check_item": "neighbor_macsec_empty", "unhealthy_nbrs": []}
        check_results = parallel_run(_check_macsec_empty, args, kwargs, nodes, timeout=300)
        unhealthy_dut = set()
        for nbr_name, check_result in list(check_results.items()):
            if check_result:
                init_check_result["failed"] = True
                init_check_result["unhealthy_nbrs"].append(nbr_name)
                unhealthy_dut.add(dut_nbr_mapping[nbr_name])
        if len(unhealthy_dut) > 0:
            init_check_result["hosts"] = list(unhealthy_dut)
        return init_check_result

    return _check


# check ipv6 neighbor reachability
@pytest.fixture(scope="module")
def check_ipv6_mgmt(duthosts, localhost):
    # check ipv6 mgmt interface reachability for debugging purpose only.
    # No failure will be trigger for this sanity check.
    def _check(*args, **kwargs):
        init_result = {"failed": False, "check_item": "ipv6_mgmt"}
        result = parallel_run(_check_ipv6_mgmt_to_dut, args, kwargs, duthosts, timeout=30, init_result=init_result)
        return list(result.values())

    def _check_ipv6_mgmt_to_dut(*args, **kwargs):
        dut = kwargs['node']
        results = kwargs['results']

        logger.info("Checking ipv6 mgmt interface reachability on %s..." % dut.hostname)
        check_result = {"failed": False, "check_item": "ipv6_mgmt", "host": dut.hostname}

        # most of the testbed should reply within 10 ms, Set the timeout to 2 seconds to reduce the impact of delay.
        try:
            shell_result = localhost.shell("ping6 -c 2 -W 2 " + dut.mgmt_ipv6)
            logging.info("ping6 output: %s" % shell_result["stdout"])
        except RunAnsibleModuleFail as e:
            # set to False for now to avoid blocking the test
            check_result["failed"] = False
            logging.info("Failed to ping ipv6 mgmt interface on %s, exception: %s" % (dut.hostname, repr(e)))
        except Exception as e:
            logger.info("Exception while checking ipv6_mgmt reachability for %s: %s" % (dut.hostname, repr(e)))
        finally:
            logger.info("Done checking ipv6 management reachability on %s" % dut.hostname)
            results[dut.hostname] = check_result
    return _check
