import pytest
import json
from tests.common.dualtor.dual_tor_io import DualTorIO
from tests.common.helpers.assertions import pytest_assert
import threading
import logging
from natsort import natsorted

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


def generate_test_report(tor_IO, verify, delay):
    """
    Generates a report (dictionary) of I/O metrics that were calculated as part
    of the dataplane test. This report is to be used by testcases to verify the
    results as expected by test-specific scenarios
    Returns:
        data_plane_test_report (dict): sent/received/lost/disrupted packet counters
    """
    received_counter = tor_IO.get_total_received_packets()
    pytest_assert(received_counter > 0, "Test failed to capture any meaningful "\
                "received packet")
    total_lost_packets = tor_IO.get_total_lost_packets()
    if total_lost_packets:
        logging.warn("Packets were lost during the test. Total lost count: {}"\
            .format(total_lost_packets))

    allowed_disruption = 0 if delay == 0 else 1
    servers_with_disruptions = tor_IO.get_servers_with_disruptions()
    servers_with_transmissions = tor_IO.get_servers_with_transmissions()
    per_server_report = dict()
    logger.info("Traffic summary:")
    failures = list()
    for server_addr, stats  in natsorted(servers_with_disruptions.items()):
        losstime = packets_lost = disruption_lost = 0
        for stat in stats:
            if "end" in stat:
                losstime += stat["end"] - stat["start"]
                packets_lost += (stat["end_id"] -
                    stat["start_id"])/len(servers_with_transmissions)
            else:
                disruption_lost += sum( 1 for stat in stats if "end" not in stat)
        disruptions = len(stats)
        per_server_report.update({server_addr:{
            "packets_lost": packets_lost,
            "disruptions": disruptions,
            "disruptions_time": losstime,
            "disruption_lost": disruption_lost}})
        logger.info("Server {}, stats: {}, disruptions count: {}".format(
            server_addr, servers_with_transmissions[server_addr], disruptions))
        if verify and disruptions > allowed_disruption:
            failures.append("Server: {}: Traffic disruption count: {}. "\
                "Allowed number of disruption: {}"\
                    .format(server_addr, disruptions, allowed_disruption))
        if verify and losstime > delay:
            failures.append("Traffic was disrupted for {}s for {}. "\
                "Maximum allowed disruption: {}s".format(losstime, server_addr, delay))

    data_plane_test_report = {
            "total_received_packets": tor_IO.get_total_received_packets(),
            "total_sent_packets": tor_IO.get_total_sent_packets(),
            "total_lost_packets": tor_IO.get_total_lost_packets(),
            "per_server_report": per_server_report
    }
    logger.debug("Detailed disruption summary: {}".format(
        json.dumps(servers_with_disruptions, indent=4)))
    logger.debug("Data plane traffic test results: \n{}".format(
        json.dumps(data_plane_test_report, indent=4)))

    if verify:
        pytest_assert(len(failures) == 0, "\n".join(failures))

    return data_plane_test_report


def run_test(duthosts, activehost, ptfhost, ptfadapter, action,
            tbinfo, tor_vlan_port, send_interval, traffic_direction):
    io_ready = threading.Event()
    standbyhost = get_standbyhost(duthosts, activehost)
    tor_IO = DualTorIO(activehost, standbyhost, ptfhost, ptfadapter, tbinfo,
        io_ready, tor_vlan_port=tor_vlan_port, send_interval=send_interval)
    if traffic_direction == "server_to_t1":
        traffic_generator = tor_IO.generate_from_server_to_t1
    elif traffic_direction == "t1_to_server":
        traffic_generator = tor_IO.generate_from_t1_to_server

    send_and_sniff = threading.Thread(target=tor_IO.start_io_test,
        kwargs={'traffic_generator': traffic_generator})

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
    return tor_IO


def cleanup(ptfadapter, duthosts_list):
    # cleanup torIO
    ptfadapter.dataplane.flush()
    for duthost in duthosts_list:
        logger.info('Clearing arp entries on DUT  {}'.format(duthost.hostname))
        duthost.shell('sonic-clear arp')


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
                            delay=0, action=None, verify=False, send_interval=None):
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
        Returns:
            data_plane_test_report (dict): traffic test statistics (sent/rcvd/dropped)
        """
        duthosts_list.append(activehost)

        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter,
                        action, tbinfo, tor_vlan_port, send_interval,
                        traffic_direction="t1_to_server")

        return generate_test_report(tor_IO, verify, delay)

    yield t1_to_server_io_test

    cleanup(ptfadapter, duthosts_list)


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
                            delay=0, action=None, verify=False, send_interval=None):
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
        Returns:
            data_plane_test_report (dict): traffic test statistics (sent/rcvd/dropped)
        """
        duthosts_list.append(activehost)

        tor_IO = run_test(duthosts, activehost, ptfhost, ptfadapter,
                        action, tbinfo, tor_vlan_port, send_interval,
                        traffic_direction="server_to_t1")

        return generate_test_report(tor_IO, verify, delay)

    yield server_to_t1_io_test

    cleanup(ptfadapter, duthosts_list)
