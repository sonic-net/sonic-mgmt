import pytest
import json
from tests.common.dualtor.dual_tor_io import DualTorIO
from tests.common.helpers.assertions import pytest_assert
import threading
import logging

logger = logging.getLogger(__name__)


def get_standbyhost(duthosts, activehost):
    if duthosts[0] == activehost:
        return duthosts[1]
    else:
        return duthosts[0]


def arp_setup(ptfhost):
    logger.info('Copy ARP responder to the PTF container  {}'\
        .format(ptfhost.hostname))
    ptfhost.copy(src='scripts/arp_responder.py', dest='/opt')
    ptfhost.host.options["variable_manager"].extra_vars.update(
        {"arp_responder_args": ""})
    ptfhost.template(src="templates/arp_responder.conf.j2",
                     dest="/etc/supervisor/conf.d/arp_responder.conf")
    logging.info("Refreshing supervisorctl")
    ptfhost.shell("supervisorctl reread && supervisorctl update")


def validate_no_traffic_loss(tor_IO, allowed_disruption, delay):
    """
    Validates traffic loss is as expected:

    """
    received_counter = tor_IO.get_total_received_packets()
    total_disruptions = tor_IO.get_total_disruptions()
    longest_disruption = tor_IO.get_longest_disruption()
    total_lost_packets = tor_IO.get_total_lost_packets()
    duplicated_packets = tor_IO.get_duplicated_packets_count()

    if received_counter:
        pytest_assert(total_disruptions <= allowed_disruption, "Traffic was "\
            "disrupted {} times. Allowed number of disruption: {}"\
            .format(total_disruptions, allowed_disruption))
        pytest_assert(longest_disruption <= delay, "Traffic was disrupted for {}s. "\
            "Maximum allowed disruption: {}s".format(longest_disruption, delay))
    else:
        pytest_assert(received_counter > 0, "Test failed to capture any meaningful "\
            "received packet")

    if total_lost_packets:
        logging.warn("Packets were lost during the test. Total lost count: {}"\
            .format(total_lost_packets))
    pytest_assert(duplicated_packets == 0, "Duplicated packets received. "\
        "Count: {}.".format(duplicated_packets))


def generate_test_report(tor_IO):
    """
    Generates a report (dictionary) of I/O metrics that were calculated as part
    of the dataplane test. This report is to be used by testcases to verify the
    results as expected by test-specific scenarios
    Returns:
        data_plane_test_report (dict): sent/received/lost/disrupted packet counters
    """
    data_plane_test_report = {
            "total_received_packets": tor_IO.get_total_received_packets(),
            "total_sent_packets": tor_IO.get_total_sent_packets(),
            "duplicated_packets_count": tor_IO.get_duplicated_packets_count(),
            "disruptions": {
                "total_disruptions": tor_IO.get_total_disruptions(),
                "total_disrupted_packets": tor_IO.get_total_disrupted_packets(),
                "total_disruption_time": tor_IO.get_total_disrupt_time(),
                "longest_disruption": tor_IO.get_longest_disruption(),
                "total_lost_packets": tor_IO.get_total_lost_packets()
            }
    }
    logger.info("Data plane traffic test results: \n{}".format(json.dumps(data_plane_test_report, indent=4)))
    return data_plane_test_report


@pytest.fixture
def send_t1_to_server_with_action(duthosts, ptfhost, ptfadapter, tbinfo):
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
    
    duthosts_list = []
    def t1_to_server_io_test(activehost, tor_vlan_port=None,
                            delay=0, action=None, verify=False):
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
                drops/duplication based on given qualification critera
        """
        duthosts_list.append(activehost)
        io_ready = threading.Event()
        standbyhost = get_standbyhost(duthosts, activehost)
        tor_IO = DualTorIO(activehost, standbyhost, ptfhost, ptfadapter, tbinfo,
            io_ready, tor_vlan_port=tor_vlan_port)
        send_and_sniff = threading.Thread(target=tor_IO.start_io_test,
            kwargs={'traffic_generator': tor_IO.generate_from_t1_to_server})
        send_and_sniff.start()
        if action:
            # do not perform the provided action until IO threads (sender and sniffer) are ready
            io_ready.wait()
            logger.info("Sender and sniffer threads started, ready to execute "\
                "the callback action")
            action()

        # Wait for the IO to complete before doing checks
        logger.info("Waiting for sender and sniffer threads to finish..")
        send_and_sniff.join()
        generate_test_report(tor_IO)
        if verify:
            allowed_disruption = 0 if delay == 0 else 1
            validate_no_traffic_loss(tor_IO, allowed_disruption=allowed_disruption,
                delay=delay)

    yield t1_to_server_io_test

    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts_list:
        logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear arp')


@pytest.fixture
def send_server_to_t1_with_action(duthosts, ptfhost, ptfadapter, tbinfo):
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

    duthosts_list = []
    def server_to_t1_io_test(activehost, tor_vlan_port=None,
                            delay=0, action=None, verify=False):
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
        """
        duthosts_list.append(activehost)
        io_ready = threading.Event()
        standbyhost = get_standbyhost(duthosts, activehost)
        tor_IO = DualTorIO(activehost, standbyhost, ptfhost, ptfadapter, tbinfo,
            io_ready, tor_vlan_port=tor_vlan_port)
        send_and_sniff = threading.Thread(target=tor_IO.start_io_test,
            kwargs={'traffic_generator': tor_IO.generate_from_server_to_t1})
        send_and_sniff.start()

        if action:
            # do not perform the provided action until
            # IO threads (sender and sniffer) are ready
            io_ready.wait()
            logger.info("Sender and sniffer threads started, ready to execute the "\
                "callback action")
            action()

        # Wait for the IO to complete before doing checks
        send_and_sniff.join()
        generate_test_report(tor_IO)
        if verify:
            allowed_disruption = 0 if delay == 0 else 1
            validate_no_traffic_loss(tor_IO, allowed_disruption=allowed_disruption,
                delay=delay)

    yield server_to_t1_io_test

    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts_list:
       logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
       duthost.shell('sonic-clear arp')
