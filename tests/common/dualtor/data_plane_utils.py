import pytest
from tests.common.dualtor.dual_tor_io import DualTorIO
from tests.common.helpers.assertions import pytest_assert
import threading
import logging

logger = logging.getLogger(__name__)


@pytest.fixture
def send_t1_to_server_after_action(ptfhost, ptfadapter, tbinfo):
    """
    Starts IO test from T1 router to server.
    As part of IO test the banckground thread sends and sniffs packets.
    As soon as sender and sniffer threads are in running state, a callback action is performed.
    When action is finished, the sender and sniffer threads are given time to complete.
    Finally, the collected packets are sniffed, and the disruptions are measured.

    Should return `send_t1_to_server` for the external user to control the timing of test.
    As part of teardown, the ARP, FDB tables are cleared and ptf dataplane is flushed.
    Args:
        ptfhost (fixture): Fixture for PTF instance to be used during the test
        ptfadapter (fixture): Ficture which provides helper utility to use ptf ptf testutils
        tbinfo (fixture): Fixture for testebd inventory  information

    Yields:
        function: A helper function to run and monitor the IO test
    """
    logger.info('Copy ARP responder to the PTF container  {}'.format(ptfhost.hostname))
    ptfhost.copy(src='scripts/arp_responder.py', dest='/opt')
    logging.info("Enabling arp_responder")
    ptfhost.shell("supervisorctl reread && supervisorctl update")
    ptfhost.shell("supervisorctl restart arp_responder")
    logging.info("arp_responder enabled")

    duthosts = []
    def t1_to_server_io_test(duthost, server_port=None, tor_port=None, expect_tunnel_packet=False, delay=1, timeout=5, action=None):
        """
        Helper method for `send_t1_to_server_after_action`.
        Starts sender and sniffer before performing the action on the tor host.

        Args:
            server_port: The port intended to receive the packet
            tor_port: The port through which to send the packet. Connected to either the upper or lower ToR.
                default - None. If set to None, the test chooses random portchannel member port for this test.
            delay: Maximum acceptable delay for traffic to continue flowing again
            timeout: Time to wait for packet to be transmitted
            action: Some function (with args) which performs the desired action, or `None` if no action/delay is desired
            expect_tunnel_packet: `True` or `False` whether to expect an IP-in-IP tunnel packet (TODO)
        """
        duthosts.append(duthost)
        io_ready = threading.Event()
        tor_IO = DualTorIO(duthost, ptfhost, ptfadapter, tbinfo, server_port, tor_port, expect_tunnel_packet, delay, timeout, io_ready)
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
        allowed_disruption = 1
        total_disruptions = tor_IO.get_total_disruptions()
        longest_disruption = tor_IO.get_longest_disruption()

        pytest_assert(total_disruptions <= 1, "Traffic was disrupted {} times. Allowed number of disruption: {}"\
            .format(total_disruptions, allowed_disruption))

        pytest_assert(longest_disruption <= delay, "Traffic was disrupted for {}s. Maximum allowed disruption: {}s".\
            format(longest_disruption, delay))

    yield t1_to_server_io_test

    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts:
        logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear arp')
        logger.info('Clearing all fdb entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear fdb all')


@pytest.fixture
def send_server_to_t1_after_action(ptfhost, ptfadapter, tbinfo):
    """
    Starts IO test from T1 router to server.
    As part of IO test the banckground thread sends and sniffs packets.
    As soon as sender and sniffer threads are in running state, a callback action is performed.
    When action is finished, the sender and sniffer threads are given time to complete.
    Finally, the collected packets are sniffed, and the disruptions are measured.

    Should return `send_t1_to_server` for the external user to control the timing of test.
    As part of teardown, the ARP, FDB tables are cleared and ptf dataplane is flushed.
    Args:
        ptfhost (fixture): Fixture for PTF instance to be used during the test
        ptfadapter (fixture): Ficture which provides helper utility to use ptf ptf testutils
        tbinfo (fixture): Fixture for testebd inventory  information

    Yields:
        function: A helper function to run and monitor the IO test
    """
    logger.info('Copy ARP responder to the PTF container  {}'.format(ptfhost.hostname))
    ptfhost.copy(src='scripts/arp_responder.py', dest='/opt')
    logging.info("Enabling arp_responder")
    ptfhost.shell("supervisorctl restart arp_responder")
    logging.info("arp_responder enabled")
    duthosts = []

    def server_to_t1_io_test(duthost, server_port=None, tor_port=None, expect_tunnel_packet=False, delay=1, timeout=5, action=None):
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
            expect_tunnel_packet: `True` or `False` whether to expect an IP-in-IP tunnel packet (TODO)
        """
        duthosts.append(duthost)
        io_ready = threading.Event()
        tor_IO = DualTorIO(duthost, ptfhost, ptfadapter, tbinfo, server_port, tor_port, expect_tunnel_packet, delay, timeout, io_ready)
        send_and_sniff = threading.Thread(target=tor_IO.start_io_test, kwargs={'traffic_generator': tor_IO.generate_from_server_to_t1})
        send_and_sniff.start()

        if action:
            # do not perform the provided action until IO threads (sender and sniffer) are ready
            io_ready.wait()
            logger.info("Sender and sniffer threads started, ready to execute the callback action")
            action()

        # Wait for the IO to complete before doing checks
        send_and_sniff.join()
        allowed_disruption = 1
        total_disruptions = tor_IO.get_total_disruptions()
        longest_disruption = tor_IO.get_longest_disruption()

        pytest_assert(total_disruptions <= 1, "Traffic was disrupted {} times. Allowed number of disruption: {}"\
            .format(total_disruptions, allowed_disruption))

        pytest_assert(longest_disruption <= delay, "Traffic was disrupted for {}s. Maximum allowed disruption: {}s".\
            format(longest_disruption, delay))

    yield server_to_t1_io_test

    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts:
        logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear arp')
        logger.info('Clearing all fdb entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear fdb all')
