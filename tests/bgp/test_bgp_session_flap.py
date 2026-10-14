'''

This script is to test BGP session flapping on SONiC and monitor
the CPU.

'''

import logging
import sys
import threading
import time
import traceback

import pytest
import textfsm

from tests.common.devices.sonic import SonicHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import InterruptableThread, wait_until

from natsort import natsorted

logger = logging.getLogger(__name__)
max_wait = 0
wait_time = 2
proc_textfsm = "./bgp/templates/show_proc_cpu.template"
bgp_sum_textfsm = "./bgp/templates/bgp_summary.template"
skip_hosts = []

cpuSpike = 10
memSpike = 1.3
BGP_SESSION_TIMEOUT = 300
BGP_POLL_INTERVAL = 10
BGP_RECOVERY_DELAY = 30
FLAP_THREAD_STOP_TIMEOUT = 120

pytestmark = [pytest.mark.topology('t1', 't2', 'lrh', 'urh', 'm1', 'lt2', 'ft2', 'c0', 'lma', 'uma')]


def get_bgp_session_states(duthost, asic_index):
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    return bgp_facts['bgp_neighbors']


def filter_external_bgp_sessions(sessions):
    return {
        ip: details
        for ip, details in sessions.items()
        if (
            "INTERNAL" not in details["peer group"]
            and "VOQ_CHASSIS" not in details["peer group"]
        )
    }


def get_bgp_session_groups(duthost, asic_index, skipped_hosts):
    all_sessions = get_bgp_session_states(duthost, asic_index)
    external_sessions = filter_external_bgp_sessions(all_sessions)
    recovery_neighbor_ips = [
        ip for ip, details in all_sessions.items()
        if details['description'].lower() not in skipped_hosts
    ]
    return all_sessions, external_sessions, recovery_neighbor_ips


def get_external_bgp_session_states(duthost, asic_index):
    return filter_external_bgp_sessions(
        get_bgp_session_states(duthost, asic_index)
    )


def all_bgp_sessions_established(duthost, asic_index, neighbor_ips):
    sessions = get_bgp_session_states(duthost, asic_index)
    return all(
        sessions.get(ip, {}).get('state') == 'established'
        for ip in neighbor_ips
    )


def get_unique_neighbor_hosts(neighbors):
    unique_neighbors = {}
    for neigh in neighbors:
        unique_neighbors.setdefault(neigh.hostname, neigh)
    return list(unique_neighbors.values())


def validate_bgp_command_result(neigh, action, result):
    if (
        isinstance(result, dict)
        and (result.get('failed', False) or result.get('rc', 0) != 0)
    ):
        raise RuntimeError(
            "Failed to {} BGP on neighbor {}: {}".format(
                action, neigh, result
            )
        )


def restore_neighbor_bgp(neighbors):
    errors = []
    for neigh in neighbors:
        try:
            result = neigh.start_bgpd()
            validate_bgp_command_result(neigh, "start", result)
        except Exception:
            errors.append(
                "Failed to restore BGP on neighbor {}:\n{}".format(
                    neigh, traceback.format_exc()
                )
            )
    return errors


def stop_flap_workers(workers, stop_event, neighbors):
    stop_event.set()
    deadline = time.time() + FLAP_THREAD_STOP_TIMEOUT
    errors = []

    for thread, _ in workers:
        thread_exception = thread.join(
            timeout=max(0, deadline - time.time()),
            suppress_exception=True
        )
        if thread.is_alive():
            errors.append(
                "Flap worker {} did not stop within {} seconds".format(
                    thread.name, FLAP_THREAD_STOP_TIMEOUT
                )
            )
        elif thread_exception:
            errors.append(
                "Flap worker {} failed:\n{}".format(
                    thread.name,
                    "".join(traceback.format_exception(*thread_exception))
                )
            )

    errors.extend(restore_neighbor_bgp(neighbors))
    return errors


def start_flap_worker(neigh, stop_event):
    flap_completed = threading.Event()
    thread = InterruptableThread(
        target=flap_neighbor_session,
        args=(neigh, stop_event, flap_completed)
    )
    thread.daemon = True
    thread.start()
    return thread, flap_completed


def assert_flap_workers_succeeded(workers, errors, test_exception=None):
    failures = list(errors)
    if test_exception:
        failures.insert(
            0,
            "BGP resource checks failed:\n{}".format(
                "".join(traceback.format_exception(*test_exception))
            )
        )
    incomplete_workers = [
        thread.name for thread, flap_completed in workers
        if not flap_completed.is_set()
    ]
    if incomplete_workers:
        failures.append(
            "BGP flap workers completed no flap cycles: {}".format(
                incomplete_workers
            )
        )
    pytest_assert(
        not failures,
        "BGP flap worker failures:\n{}".format("\n".join(failures))
    )


def get_cpu_stats(dut):
    proc_cpu = dut.shell(
        "show processes cpu | head -n 20", module_ignore_errors=True
    )['stdout']
    proc_mem = dut.shell(
        "show processes memory | head -n 20", module_ignore_errors=True
    )['stdout']
    proc_sum = dut.shell(
        "show processes summary | grep -v '0.0 0.0'",
        module_ignore_errors=True
    )['stdout']
    bgp_cpu = dut.shell(
        "show processes cpu | grep bgp", module_ignore_errors=True
    )['stdout']
    bgp_v4_sum = dut.shell(
        "show ip bgp summary | grep memory", module_ignore_errors=True
    )['stdout']
    bgp_v6_sum = dut.shell(
        "show ipv6 bgp summary | grep memory", module_ignore_errors=True
    )['stdout']
    logger.info(
        "CPU:\n{}\nMemory:\n{}\nSummary:\n{}\nBGP Memory:\n{}\n"
        "BGP IPv4:\n{}\nIPv6:\n{}\n".format(
            proc_cpu, proc_mem, proc_sum, bgp_cpu, bgp_v4_sum, bgp_v6_sum
        )
    )
    with open(proc_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        parsed_cpu = fsm.ParseText(proc_cpu)[0]

    with open(bgp_sum_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        parsed_ipv4 = fsm.ParseText(bgp_v4_sum)[0]
        parsed_ipv6 = fsm.ParseText(bgp_v6_sum)[0]
    data = [
        float(parsed_cpu[0]), float(parsed_cpu[1]), float(parsed_cpu[2]),
        float(parsed_ipv4[0]), float(parsed_ipv4[1]), float(parsed_ipv4[2]),
        float(parsed_ipv6[0]), float(parsed_ipv6[1]), float(parsed_ipv6[2])
    ]
    return data


@pytest.fixture(scope='module')
def setup(
    tbinfo,
    nbrhosts,
    duthosts,
    enum_frontend_dut_hostname,
    enum_rand_one_frontend_asic_index
):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index
    namespace = duthost.get_namespace_from_asic_id(asic_index)

    all_bgp_sessions, bgp_sessions, recovery_neighbor_ips = (
        get_bgp_session_groups(duthost, asic_index, skip_hosts)
    )
    neigh_keys = []
    tor_neighbors = dict()
    neigh_asn = dict()
    for details in bgp_sessions.values():
        neigh_keys.append(details['description'])
        neigh_asn[details['description']] = details['remote AS']
        tor_neighbors[details['description']] = (
            nbrhosts[details['description']]["host"]
        )
    neighbor_hosts = get_unique_neighbor_hosts(tor_neighbors.values())
    logger.info(
        "Selected %d unique neighbor hosts for %d external BGP peers",
        len(neighbor_hosts),
        len(tor_neighbors)
    )

    if not neigh_keys:
        pytest.skip(
            "No BGP neighbors found on ASIC {} of DUT {}".format(
                asic_index, duthost.hostname
            )
        )

    neighbor_ips = list(bgp_sessions)
    sessions_established = wait_until(
        BGP_SESSION_TIMEOUT, BGP_POLL_INTERVAL, 0,
        all_bgp_sessions_established, duthost, asic_index, neighbor_ips
    )
    if not sessions_established:
        logger.error(
            "BGP sessions did not establish on ASIC %s: %s",
            asic_index,
            get_external_bgp_session_states(duthost, asic_index)
        )
    pytest_assert(
        sessions_established,
        "Not all BGP sessions are established on DUT ASIC {}".format(
            asic_index
        )
    )

    tor1 = natsorted(neigh_keys)[0]

    # verify sessions are established
    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))

    setup_info = {
        'duthost': duthost,
        'neighhost': tor_neighbors[tor1],
        'neigh_asn': neigh_asn[tor1],
        'asn_dict':  neigh_asn,
        'neighbors': neighbor_hosts,
        'namespace': namespace
    }

    logger.info(
        "DUT BGP Config: {}".format(
            duthost.shell(
                'vtysh -n {} -c "show run bgp"'.format(namespace),
                module_ignore_errors=True
            )
        )
    )
    # If host it sonic use 'show runningconfig bgp'
    if isinstance(nbrhosts[tor1]["host"], SonicHost):
        logger.info("Neighbor BGP Config: {}".format(
           nbrhosts[tor1]["host"].command("show runningconfig bgp")))
    else:
        # Else use industry standard 'show run | sec bgp'
        logger.info("Neighbor BGP Config: {}".format(
            nbrhosts[tor1]["host"].eos_command(
                commands=["show run | section bgp"]
            )
        ))

    logger.info('Setup_info: {}'.format(setup_info))

    #  get baseline BGP CPU and Memory Utilization
    get_cpu_stats(duthost)

    yield setup_info

    restore_errors = restore_neighbor_bgp(neighbor_hosts)

    sessions_established = wait_until(
        BGP_SESSION_TIMEOUT, BGP_POLL_INTERVAL, BGP_RECOVERY_DELAY,
        all_bgp_sessions_established,
        duthost,
        asic_index,
        recovery_neighbor_ips
    )
    if not sessions_established:
        logger.error(
            "BGP sessions did not recover on ASIC %s: %s",
            asic_index,
            get_bgp_session_states(duthost, asic_index)
        )
    pytest_assert(
        not restore_errors,
        "Failed to restore neighbor BGP processes:\n{}".format(
            "\n".join(restore_errors)
        )
    )
    pytest_assert(
        sessions_established,
        "Not all BGP sessions recovered on DUT ASIC {}".format(asic_index)
    )


def flap_neighbor_session(neigh, stop_event, flap_completed):
    while not stop_event.is_set():
        result = neigh.kill_bgpd()
        validate_bgp_command_result(neigh, "stop", result)
        result = neigh.start_bgpd()
        validate_bgp_command_result(neigh, "start", result)
        flap_completed.set()


def test_bgp_single_session_flaps(setup):
    # get baseline stat information
    stats = []
    stats.append(get_cpu_stats(setup['duthost']))

    # start threads to flap neighbor sessions
    stop_event = threading.Event()
    workers = []
    test_exception = None
    try:
        workers.append(start_flap_worker(setup['neighhost'], stop_event))
        for i in range(10):
            stats.append(get_cpu_stats(setup['duthost']))
            index = len(stats) - 1
            assert stats[index][0] < (stats[0][0] + cpuSpike)
            assert stats[index][1] < (stats[0][1] + cpuSpike)
            assert stats[index][2] < (stats[0][2] + cpuSpike)
            # Memory can be zero when an address family has no neighbors.
            assert stats[index][3] <= (stats[0][3] * memSpike)
            assert stats[index][4] <= (stats[0][4] * memSpike)
            assert stats[index][5] <= (stats[0][5] * memSpike)
            assert stats[index][6] <= (stats[0][6] * memSpike)
            assert stats[index][7] <= (stats[0][7] * memSpike)
            assert stats[index][8] <= (stats[0][8] * memSpike)

            time.sleep(wait_time)
    except (Exception, pytest.fail.Exception):
        test_exception = sys.exc_info()
    finally:
        worker_errors = stop_flap_workers(
            workers, stop_event, [setup['neighhost']]
        )

    assert_flap_workers_succeeded(workers, worker_errors, test_exception)


def test_bgp_multiple_session_flaps(setup):
    # get baseline stat information
    stats = []
    stats.append(get_cpu_stats(setup['duthost']))

    # start threads to flap neighbor sessions
    neighbors = setup['neighbors']
    stop_event = threading.Event()
    workers = []
    test_exception = None
    try:
        for neigh in neighbors:
            workers.append(start_flap_worker(neigh, stop_event))
        for i in range(10):
            stats.append(get_cpu_stats(setup['duthost']))
            index = len(stats) - 1
            assert stats[index][0] < (stats[0][0] + cpuSpike)
            assert stats[index][1] < (stats[0][1] + cpuSpike)
            assert stats[index][2] < (stats[0][2] + cpuSpike)
            # Memory can be zero when an address family has no neighbors.
            assert stats[index][3] <= (stats[0][3] * memSpike)
            assert stats[index][4] <= (stats[0][4] * memSpike)
            assert stats[index][5] <= (stats[0][5] * memSpike)
            assert stats[index][6] <= (stats[0][6] * memSpike)
            assert stats[index][7] <= (stats[0][7] * memSpike)
            assert stats[index][8] <= (stats[0][8] * memSpike)

            time.sleep(wait_time)
    except (Exception, pytest.fail.Exception):
        test_exception = sys.exc_info()
    finally:
        worker_errors = stop_flap_workers(workers, stop_event, neighbors)

    assert_flap_workers_succeeded(workers, worker_errors, test_exception)
