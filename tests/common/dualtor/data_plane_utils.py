import pytest
from tests.common.dualtor.dual_tor_io import DualTorIO
from tests.common.helpers.assertions import pytest_assert
import threading
import logging

logger = logging.getLogger(__name__)


def arp_setup(ptfhost):
    logger.info('Copy ARP responder to the PTF container  {}'.format(ptfhost.hostname))
    ptfhost.copy(src='scripts/arp_responder.py', dest='/opt')
    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": "-e"})
    ptfhost.template(src="templates/arp_responder.conf.j2",
                     dest="/etc/supervisor/conf.d/arp_responder.conf")
    logging.info("Refreshing supervisorctl")
    ptfhost.shell("supervisorctl reread && supervisorctl update")


def validate_IO_results(tor_IO, allowed_disruption, delay):
    received_counter = tor_IO.get_total_received_packets()
    total_disruptions = tor_IO.get_total_disruptions()
    longest_disruption = tor_IO.get_longest_disruption()
    total_lost_packets = tor_IO.get_total_dropped_packets()

    if received_counter:
        pytest_assert(total_disruptions <= 1, "Traffic was disrupted {} times. Allowed number of disruption: {}"\
            .format(total_disruptions, allowed_disruption))

        pytest_assert(longest_disruption <= delay, "Traffic was disrupted for {}s. Maximum allowed disruption: {}s".\
            format(longest_disruption, delay))
    else:
        pytest_assert(received_counter > 0, "Test failed to capture any meaningful received packet")

    if total_lost_packets:
        logging.warn("Packets were lost during the test. Total lost count: {}".format(total_lost_packets))


@pytest.fixture
def send_t1_to_server_after_action(ptfhost, ptfadapter, tbinfo):
    """
    Starts IO test from T1 router to server.
    As part of IO test the background thread sends and sniffs packets.
    As soon as sender and sniffer threads are in running state, a callback action is performed.
    When action is finished, the sender and sniffer threads are given time to complete.
    Finally, the collected packets are sniffed, and the disruptions are measured.

    As part of teardown, the ARP table is cleared and ptf dataplane is flushed.
    Args:
        ptfhost (fixture): Fixture for PTF instance to be used during the test
        ptfadapter (fixture): Fixture which provides helper utility to use ptf ptf testutils
        tbinfo (fixture): Fixture for testebd inventory information

    Yields:
        function: A helper function to run and monitor the IO test
    """
    arp_setup(ptfhost)
    
    duthosts = []
    def t1_to_server_io_test(duthost, server_port=None, tor_port=None, delay=1, timeout=5, action=None):
        """
        Helper method for `send_t1_to_server_after_action`.
        Starts sender and sniffer before performing the action on the tor host.

        Args:
            server_port: The port intended to receive the packet
            tor_port: The T1 port through which to send the packet. Connected to either the upper or lower ToR.
                default - None. If set to None, the test chooses random portchannel member port for this test.
            delay: Maximum acceptable delay for traffic to continue flowing again
            timeout: Time to wait for packet to be transmitted
            action: Some function (with args) which performs the desired action, or `None` if no action/delay is desired
        """
        duthosts.append(duthost)
        io_ready = threading.Event()
        tor_IO = DualTorIO(duthost, ptfhost, ptfadapter, tbinfo, server_port, tor_port, delay, timeout, io_ready)
        send_and_sniff = threading.Thread(target=tor_IO.start_io_test, kwargs={'traffic_generator': tor_IO.generate_from_t1_to_server})
        send_and_sniff.start()
        if action:
            # do not perform the provided action until IO threads (sender and sniffer) are ready
            io_ready.wait()
            logger.info("Sender and sniffer threads started, ready to execute the callback action")
            action()

        # Wait for the IO to complete before doing checks
        logger.info("Waiting for sender and sniffer threads to finish..")
        send_and_sniff.join()
        validate_IO_results(tor_IO, allowed_disruption=1, delay=delay)

    yield t1_to_server_io_test

    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts:
        logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear arp')


@pytest.fixture
def send_server_to_t1_after_action(ptfhost, ptfadapter, tbinfo):
    """
    Starts IO test from server to T1 router.
    As part of IO test the background thread sends and sniffs packets.
    As soon as sender and sniffer threads are in running state, a callback action is performed.
    When action is finished, the sender and sniffer threads are given time to complete.
    Finally, the collected packets are sniffed, and the disruptions are measured.

    As part of teardown, the ARP, FDB tables are cleared and ptf dataplane is flushed.
    Args:
        ptfhost (fixture): Fixture for PTF instance to be used during the test
        ptfadapter (fixture): Fixture which provides helper utility to use ptf testutils
        tbinfo (fixture): Fixture for testebd inventory information

    Yields:
        function: A helper function to run and monitor the IO test
    """
    arp_setup(ptfhost)

    duthosts = []
    def server_to_t1_io_test(duthost, server_port=None, tor_port=None, delay=1, timeout=5, action=None):
        """
        Helper method for `send_server_to_t1_after_action`.
        Starts sender and sniffer before performing the action on the tor host.

        Args:
            server_port: The port intended to receive the packet
            tor_port: The port through which to send the packet. Connected to either the upper or lower ToR.
                default - None. If set to None, the test chooses random portchannel member port for this test.
            delay: Maximum acceptable delay for traffic to continue flowing again
            timeout: Time to wait for packet to be transmitted
            action: Some function (with args) which performs the desired action, or `None` if no action/delay is desired
        """
        duthosts.append(duthost)
        io_ready = threading.Event()
        tor_IO = DualTorIO(duthost, ptfhost, ptfadapter, tbinfo, server_port, tor_port, delay, timeout, io_ready)
        send_and_sniff = threading.Thread(target=tor_IO.start_io_test, kwargs={'traffic_generator': tor_IO.generate_from_server_to_t1})
        send_and_sniff.start()

        if action:
            # do not perform the provided action until IO threads (sender and sniffer) are ready
            io_ready.wait()
            logger.info("Sender and sniffer threads started, ready to execute the callback action")
            action()

        # Wait for the IO to complete before doing checks
        send_and_sniff.join()
        validate_IO_results(tor_IO, allowed_disruption=1, delay=delay)

    yield server_to_t1_io_test

    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts:
       logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
       duthost.shell('sonic-clear arp')
