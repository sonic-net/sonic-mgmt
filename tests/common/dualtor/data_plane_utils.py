import pytest
import json
import os.path
import re
import time
import random
import shutil

from tests.common.dualtor.dual_tor_common import active_active_ports        # noqa F401
from tests.common.dualtor.dual_tor_common import active_standby_ports       # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type     # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_io import DualTorIO
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import InterruptableThread
from tests.common.utilities import wait_until
from tests.common.plugins.sanity_check import print_logs
import threading
import logging
from natsort import natsorted

logger = logging.getLogger(__name__)


def get_peerhost(duthosts, activehost):
    if duthosts[0] == activehost:
        return duthosts[1]
    else:
        return duthosts[0]


def arp_setup(ptfhost):
    logger.info('Copy ARP responder to the PTF container  {}'.format(ptfhost.hostname))
    ptfhost.copy(src='scripts/arp_responder.py', dest='/opt')
    ptfhost.host.options["variable_manager"].extra_vars.update(
        {"arp_responder_args": ""})
    ptfhost.template(src="templates/arp_responder.conf.j2",
                     dest="/etc/supervisor/conf.d/arp_responder.conf")
    logging.info("Refreshing supervisorctl")
    ptfhost.shell("supervisorctl reread && supervisorctl update")


def validate_traffic_results(tor_IO, allowed_disruption, delay,
                             allow_disruption_before_traffic=False):
    """
    Generates a report (dictionary) of I/O metrics that were calculated as part
    of the dataplane test. This report is to be used by testcases to verify the
    results as expected by test-specific scenarios
    Returns:
        data_plane_test_report (dict): sent/received/lost/disrupted packet counters
    """
    results = tor_IO.get_test_results()

    pytest_assert(results is not None, "No traffic test results found")
    server_summaries = dict()

    failures = list()
    # Calculate and log test summaries
    for server_ip, result in natsorted(list(results.items())):
        total_received_packets = result['received_packets']
        received_packet_diff = result['received_packets'] - result['sent_packets']
        total_disruptions = len(result['disruptions'])

        longest_disruption = 0
        for disruption in result['disruptions']:
            disruption_length = disruption['end_time'] - disruption['start_time']
            if disruption_length > longest_disruption:
                longest_disruption = disruption_length

        total_duplications = len(result['duplications'])
        longest_duplication = 0
        for duplication in result['duplications']:
            duplication_length = duplication['end_time'] - duplication['start_time']
            if duplication_length > longest_duplication:
                longest_duplication = duplication_length

        disruption_before_traffic = result['disruption_before_traffic']
        disruption_after_traffic = result['disruption_after_traffic']

        server_summary = {
            'received_packets': total_received_packets,
            'received_packet_diff': received_packet_diff,
            'total_disruptions': total_disruptions,
            'longest_disruption': longest_disruption,
            'total_duplications': total_duplications,
            'longest_duplication': longest_duplication,
            'disruption_before_traffic': disruption_before_traffic,
            'disruption_after_traffic': disruption_after_traffic
        }

        logger.info('Server {} summary:\n{}'.format(server_ip, json.dumps(server_summary, indent=4, sort_keys=True)))
        server_summaries[server_ip] = server_summary

        # Assert test results separately so all server results are logged
        if total_received_packets <= 0:
            failures.append("Test failed to capture any meaningful received "
                            "packets for server {}".format(server_ip))

        if total_disruptions > allowed_disruption:
            failures.append("Traffic to server {} was "
                            "disrupted {} times. Allowed number of disruptions: {}"
                            .format(server_ip, total_disruptions, allowed_disruption))

        if longest_disruption > delay and _validate_long_disruption(result['disruptions'],
                                                                    allowed_disruption, delay):
            failures.append("Traffic on server {} was disrupted for {}s. "
                            "Maximum allowed disruption: {}s"
                            .format(server_ip, longest_disruption, delay))

        if total_duplications > allowed_disruption:
            failures.append("Traffic to server {} was duplicated {} times. "
                            "Allowed number of duplications: {}"
                            .format(server_ip, total_duplications, allowed_disruption))

        if longest_duplication > delay and _validate_long_disruption(result['duplications'],
                                                                     allowed_disruption, delay):
            failures.append("Traffic on server {} was duplicated for {}s. "
                            "Maximum allowed duplication: {}s"
                            .format(server_ip, longest_duplication, delay))

        if not allow_disruption_before_traffic and bool(disruption_before_traffic):
            failures.append("Traffic on server {} was disrupted prior to test start, "
                            "missing {} packets from the start of the packet flow"
                            .format(server_ip, disruption_before_traffic))

        if bool(disruption_after_traffic):
            failures.append("Traffic on server {} was disrupted after test end, "
                            "missing {} packets from the end of the packet flow"
                            .format(server_ip, result['sent_packets'] - disruption_after_traffic))

    pytest_assert(len(failures) == 0, '\n' + '\n'.join(failures))


def _validate_long_disruption(disruptions, allowed_disruption, delay):
    """
    Helper function to validate when two continuous disruption combine as one.
    """

    total_disruption_length = 0

    for disruption in disruptions:
        total_disruption_length += disruption['end_time'] - disruption['start_time']

    logger.debug("total_disruption_length: {}, total_allowed_disruption_length=allowed_disruption*delay: {}".format(
        total_disruption_length, allowed_disruption*delay))

    if total_disruption_length > allowed_disruption * delay:
        return True
    return False


def verify_and_report(tor_IO, verify, delay, allowed_disruption,
                      allow_disruption_before_traffic=False):
    # Wait for the IO to complete before doing checks
    if verify:
        validate_traffic_results(tor_IO, allowed_disruption=allowed_disruption, delay=delay,
                                 allow_disruption_before_traffic=allow_disruption_before_traffic)
    return tor_IO.get_test_results()


def run_test(
    duthosts, activehost, ptfhost, ptfadapter, vmhost, action,
    tbinfo, tor_vlan_port, send_interval, traffic_direction,
    stop_after, cable_type=CableType.active_standby     # noqa F811
):
    io_ready = threading.Event()

    peerhost = get_peerhost(duthosts, activehost)
    tor_IO = DualTorIO(
        activehost, peerhost, ptfhost, ptfadapter, vmhost, tbinfo,
        io_ready, tor_vlan_port=tor_vlan_port, send_interval=send_interval, cable_type=cable_type
    )
    tor_IO.generate_traffic(traffic_direction)

    send_and_sniff = InterruptableThread(target=tor_IO.start_io_test)
    send_and_sniff.set_error_handler(lambda *args, **kargs: io_ready.set())

    send_and_sniff.start()
    io_ready.wait()
    if action:
        # do not perform the provided action until
        # IO threads (sender and sniffer) are ready
        logger.info("Sender and sniffer threads started, ready to execute the callback action")
        time.sleep(15)

        try:
            action()
        except Exception as error:
            logging.error("Caught exception %s during action.", repr(error))
            tor_IO.stop_early = True
            send_and_sniff.join()
            raise

    # do not time-wait the test, if early stop is not requested (when stop_after=None)
    if stop_after is not None:
        wait_until(timeout=stop_after, interval=0.5, delay=0, condition=lambda: not send_and_sniff.is_alive)
        if send_and_sniff.is_alive():
            logger.info("Sender/Sniffer threads are still running. Sending signal "
                        "to stop the IO test after {}s of the action".format(stop_after))
            tor_IO.stop_early = True
    # Wait for the IO to complete before doing checks
    send_and_sniff.join()
    tor_IO.examine_flow()
    return tor_IO


def cleanup(ptfadapter, duthosts_list):
    print_logs(duthosts_list, print_dual_tor_logs=True)
    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts_list:
        logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear arp')


@pytest.fixture
def save_pcap(request, pytestconfig):
    """Save pcap file to the log directory."""

    yield

    pcap_file = "/tmp/capture.pcap"
    local_pcap_file_template = "%s_dump.pcap"
    if os.path.isfile(pcap_file):
        test_log_file = pytestconfig.getoption("log_file", None)
        if test_log_file:
            log_dir = os.path.dirname(os.path.abspath(test_log_file))
            # Remove any illegal characters from the test name
            local_pcap_filename = local_pcap_file_template % re.sub(r"[^\w\s-]", "_", request.node.name)
            local_pcap_filename = re.sub(r'[_\s]+', '_', local_pcap_filename)
            pcap_file_dst = os.path.join(log_dir, local_pcap_filename)
            logging.debug("Save dualtor-io pcap file to %s", pcap_file_dst)
            shutil.copyfile(src=pcap_file, dst=pcap_file_dst)
        else:
            logging.info("Skip saving pcap file to log directory as log directory not set.")
    else:
        logging.warn("No pcap file found at {}".format(pcap_file))


@pytest.fixture
def send_t1_to_server_with_action(duthosts, ptfhost, ptfadapter, tbinfo,
                                  cable_type, vmhost, save_pcap, skip_traffic_test=False):       # noqa F811
    """
    Starts IO test from T1 router to server.
    As part of IO test the background thread sends and sniffs packets.
    As soon as sender and sniffer threads are in running state, a callback
    action is performed. When action is finished, the sender and sniffer threads
    are given time to complete. Finally, the collected packets are sniffed,
    and the disruptions are measured.

    As part of teardown, the ARP table is cleared and ptf dataplane is flushed.
    Args:
        ptfhost (fixture): Fixture for PTF instance to be used during the test
        ptfadapter (fixture): Fixture to use ptf ptf testutils
        tbinfo (fixture): Fixture for testebd inventory information

    Yields:
        function: A helper function to run and monitor the IO test
    """
    arp_setup(ptfhost)

    def t1_to_server_io_test(activehost, tor_vlan_port=None,
                             delay=0, allowed_disruption=0, action=None, verify=False, send_interval=0.1,
                             stop_after=None, allow_disruption_before_traffic=False,
                             skip_traffic_test=False):
        """
        Helper method for `send_t1_to_server_with_action`.
        Starts sender and sniffer before performing the action on the tor host.

        Args:
            tor_vlan_port (str): Port name (as in minigraph_portchannels) which
                corresponds to VLAN member port of the activehost. This is used to
                select the downstream server IP to send the packets to.
                default - None. If set to None, the test sends traffic to randomly
                selected downstream server addresses.
            delay (int): Maximum acceptable delay for traffic to continue flowing again.
            action (function): A Lambda function (with optional args) which performs
                the desired action while the traffic is flowing from server to T1.
                default - `None`: No action will be performed and traffic will run
                between server to T1 router.
            verify (boolean): If set to True, test will automatically verify packet
                drops/duplication based on given qualification criteria
            send_interval (int): Sleep duration between two sent packets
            stop_after (int): Wait time after which sender/sniffer threads are terminated
                default - None: Early termination will not be performed
        Returns:
            data_plane_test_report (dict): traffic test statistics (sent/rcvd/dropped)
        """

        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter, vmhost,
                          action, tbinfo, tor_vlan_port, send_interval,
                          traffic_direction="t1_to_server", stop_after=stop_after,
                          cable_type=cable_type)

        # If a delay is allowed but no numebr of allowed disruptions
        # is specified, default to 1 allowed disruption
        if delay and not allowed_disruption:
            allowed_disruption = 1

        if skip_traffic_test is True:
            logging.info("Skipping traffic test")
            return
        return verify_and_report(tor_IO, verify, delay, allowed_disruption, allow_disruption_before_traffic)

    yield t1_to_server_io_test

    cleanup(ptfadapter, duthosts)


@pytest.fixture
def send_server_to_t1_with_action(duthosts, ptfhost, ptfadapter, tbinfo,
                                  cable_type, vmhost, save_pcap, skip_traffic_test=False):   # noqa F811
    """
    Starts IO test from server to T1 router.
    As part of IO test the background thread sends and sniffs packets.
    As soon as sender and sniffer threads are in running state, a callback
    action is performed.
    When action is finished, the sender and sniffer threads are given time to
    complete. Finally, the collected packets are sniffed, and the disruptions
    are measured.

    As part of teardown, the ARP, FDB tables are cleared and ptf dataplane is flushed.
    Args:
        ptfhost (fixture): Fixture for PTF instance to be used during the test
        ptfadapter (fixture): Fixture to use ptf testutils
        tbinfo (fixture): Fixture for testebd inventory information

    Yields:
        function: A helper function to run and monitor the IO test
    """
    arp_setup(ptfhost)

    def server_to_t1_io_test(activehost, tor_vlan_port=None,
                             delay=0, allowed_disruption=0, action=None, verify=False, send_interval=0.01,
                             stop_after=None, skip_traffic_test=False):
        """
        Helper method for `send_server_to_t1_with_action`.
        Starts sender and sniffer before performing the action on the tor host.

        Args:
            tor_vlan_port (str): Port name (as in minigraph_portchannels) which
                corresponds to VLAN member port of the activehost.
                default - None. If set to None, the test chooses random VLAN
                member port for this test.
            delay (int): Maximum acceptable delay for traffic to continue flowing again.
            action (function): A Lambda function (with optional args) which
                performs the desired action while the traffic flows from server to T1.
                default - `None`: No action will be performed and traffic will run
                between server to T1 router.
            verify (boolean): If set to True, test will automatically verify packet
                drops/duplication based on given qualification critera
            send_interval (int): Sleep duration between two sent packets
            stop_after (int): Wait time after which sender/sniffer threads are terminated
                default - None: Early termination will not be performed
        Returns:
            data_plane_test_report (dict): traffic test statistics (sent/rcvd/dropped)
        """

        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter, vmhost,
                          action, tbinfo, tor_vlan_port, send_interval,
                          traffic_direction="server_to_t1", stop_after=stop_after,
                          cable_type=cable_type)

        # If a delay is allowed but no numebr of allowed disruptions
        # is specified, default to 1 allowed disruption
        if delay and not allowed_disruption:
            allowed_disruption = 1

        if skip_traffic_test is True:
            logging.info("Skipping traffic test")
            return
        return verify_and_report(tor_IO, verify, delay, allowed_disruption)

    yield server_to_t1_io_test

    cleanup(ptfadapter, duthosts)


@pytest.fixture
def send_soc_to_t1_with_action(duthosts, ptfhost, ptfadapter, tbinfo,
                               cable_type, vmhost, save_pcap, skip_traffic_test=False):      # noqa F811

    arp_setup(ptfhost)

    def soc_to_t1_io_test(activehost, tor_vlan_port=None,
                          delay=0, allowed_disruption=0, action=None, verify=False, send_interval=0.01,
                          stop_after=None, skip_traffic_test=False):

        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter, vmhost,
                          action, tbinfo, tor_vlan_port, send_interval,
                          traffic_direction="soc_to_t1", stop_after=stop_after,
                          cable_type=cable_type)

        if delay and not allowed_disruption:
            allowed_disruption = 1

        if skip_traffic_test is True:
            logging.info("Skipping traffic test")
            return
        return verify_and_report(tor_IO, verify, delay, allowed_disruption)

    yield soc_to_t1_io_test

    cleanup(ptfadapter, duthosts)


@pytest.fixture
def send_t1_to_soc_with_action(duthosts, ptfhost, ptfadapter, tbinfo,
                               cable_type, vmhost, save_pcap, skip_traffic_test=False):      # noqa F811

    arp_setup(ptfhost)

    def t1_to_soc_io_test(activehost, tor_vlan_port=None,
                          delay=0, allowed_disruption=0, action=None, verify=False, send_interval=0.01,
                          stop_after=None, skip_traffic_test=False):

        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter, vmhost,
                          action, tbinfo, tor_vlan_port, send_interval,
                          traffic_direction="t1_to_soc", stop_after=stop_after,
                          cable_type=cable_type)

        # If a delay is allowed but no numebr of allowed disruptions
        # is specified, default to 1 allowed disruption
        if delay and not allowed_disruption:
            allowed_disruption = 1

        if skip_traffic_test is True:
            logging.info("Skipping traffic test")
            return
        return verify_and_report(tor_IO, verify, delay, allowed_disruption)

    yield t1_to_soc_io_test

    cleanup(ptfadapter, duthosts)


@pytest.fixture
def select_test_mux_ports(active_active_ports, active_standby_ports):                               # noqa F811
    """Return helper function to select test mux ports based on cable_type"""

    def _select_test_mux_ports(cable_type, count):                                                  # noqa F811
        if cable_type == CableType.active_active:
            test_mux_ports = random.sample(active_active_ports, count)
        elif cable_type == CableType.active_standby:
            test_mux_ports = random.sample(active_standby_ports, count)
        else:
            raise ValueError("Unsupported cable type %s" % cable_type)
        return test_mux_ports

    return _select_test_mux_ports


@pytest.fixture
def send_server_to_server_with_action(duthosts, ptfhost, ptfadapter, tbinfo,
                                      cable_type, vmhost, save_pcap, skip_traffic_test=False):   # noqa F811

    arp_setup(ptfhost)

    def server_to_server_io_test(activehost, test_mux_ports, delay=0,
                                 allowed_disruption=0, action=None,
                                 verify=False, send_interval=0.01, stop_after=None, skip_traffic_test=False):
        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter, vmhost,
                          action, tbinfo, test_mux_ports, send_interval,
                          traffic_direction="server_to_server", stop_after=stop_after,
                          cable_type=cable_type)

        # If a delay is allowed but no numebr of allowed disruptions
        # is specified, default to 1 allowed disruption
        if delay and not allowed_disruption:
            allowed_disruption = 1

        if skip_traffic_test is True:
            logging.info("Skipping traffic test")
            return
        return verify_and_report(tor_IO, verify, delay, allowed_disruption)

    yield server_to_server_io_test

    cleanup(ptfadapter, duthosts)
