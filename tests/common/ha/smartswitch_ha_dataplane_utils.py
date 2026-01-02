import logging

import json
import threading
import time
import pytest

from tests.common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import InterruptableThread
from tests.common.utilities import wait_until
from itertools import groupby
from natsort import natsorted

DEFAULT_SEND_INTERVAL = 0.01


def get_peerhost(duthosts, targethost):
    for duthost in duthosts:
        if duthost != targethost:
            return duthost
    return None


def select_ports_in_sender_namespace(duthost, ptfhost, tbinfo):
    """
    TODO:
    To test tcp connection, two namespaces are created on PTF host.
    This mentioned function selects the ports in the sender namespace.
    """

    return []


def run_test(duthosts, targethost, ptfhost, ptfadapter, tbinfo, action=None, stop_after=None):
    io_ready = threading.Event()

    test_IO = SmartSwitchHaTrafficTest(
        targethost, ptfhost, tbinfo,
        io_ready, send_interval=DEFAULT_SEND_INTERVAL
    )

    send_and_sniff = InterruptableThread(target=test_IO.start_io_test)
    send_and_sniff.set_error_handler(lambda *args, **kargs: io_ready.set())

    send_and_sniff.start()
    io_ready.wait()
    if action:
        # do not perform the provided action until IO threads (sender and sniffer) are ready
        logging.info("Sender and sniffer threads started, ready to execute the callback action")
        time.sleep(15)

        try:
            action()
        except Exception as error:
            logging.error("Caught exception %s during action.", repr(error))
            test_IO.stop_early = True
            send_and_sniff.join()
            raise

    if stop_after is not None:
        wait_until(timeout=stop_after, interval=0.5, delay=0, condition=lambda: not send_and_sniff.is_alive)
        if send_and_sniff.is_alive():
            logging.info("Sender/Sniffer threads are still running. Sending signal to "
                         "stop the IO test after {}s of the action".format(stop_after))
            test_IO.stop_early = True

    send_and_sniff.join()

    if targethost.facts["asic_type"] != "vs":
        test_IO.examine_flow()

    return test_IO


def validate_traffic_results(test_IO, allowed_disruption_duration=0, allowed_disruption_count=0):

    results = test_IO.get_test_results()

    pytest_assert(results is not None, "No traffic test results found")

    per_dst_summaries = dict()

    failures = list()

    for dst_ip, result in natsorted(list(results.items())):
        total_received_packets = result['received_packets']
        received_packet_diff = result['received_packets'] - result['sent_packets']

        total_disruptions = len(result['disruptions'])
        longest_disruption = 0
        for disruption in result['disruptions']:
            disruption_length = disruption['end_time'] - disruption['start_time']
            if disruption_length > longest_disruption:
                longest_disruption = disruption_length

        total_duplications = len([_ for _ in groupby(enumerate(result['duplications']),
                                                     lambda t: t[0] - t[1]['start_id'])])

        summary = {
            'received_packets': total_received_packets,
            'received_packet_diff': received_packet_diff,
            'total_disruptions': total_disruptions,
            'longest_disruption': longest_disruption,
            'total_duplications': total_duplications,
        }

        logging.info('dst ip: {} summary:\n{}'.format(dst_ip, json.dumps(summary, indent=4, sort_keys=True)))
        per_dst_summaries[dst_ip] = summary

        if total_received_packets <= 0:
            failures.append("Test failed to capture any meaningful received "
                            "packets for dst {}".format(dst_ip))

        if total_disruptions > allowed_disruption_count:
            failures.append("Traffic to dst {} was "
                            "disrupted {} times. Allowed number of disruptions: {}"
                            .format(dst_ip, total_disruptions, allowed_disruption_count))

        if longest_disruption > allowed_disruption_duration:
            failures.append("Traffic on dst {} was disrupted for {}s. "
                            "Maximum allowed disruption: {}s"
                            .format(dst_ip, longest_disruption, allowed_disruption_duration))

        # No duplications are allowed in the test
        if total_duplications > 0:
            failures.append("Traffic to dst {} was duplicated {} times. "
                            "Allowed number of duplications: {}"
                            .format(dst_ip, total_duplications, 0))

    pytest_assert(len(failures) == 0, '\n' + '\n'.join(failures))


def verify_and_report(test_IO, verify, allowed_disruption_duration=0, allowed_disruption_count=0):

    if verify:
        validate_traffic_results(
            test_IO, allowed_disruption_duration, allowed_disruption_count
        )

    return test_IO.get_test_results()


@pytest.fixture
def send_traffic_with_action(duthosts, ptfhost, ptfadapter, tbinfo):

    def _send_traffic(target_npu, verify=True, allowed_disruption_duration=0, allowed_disruption_count=0, action=None,
                      send_interval=DEFAULT_SEND_INTERVAL, stop_after=None):

        test_IO = run_test(
            duthosts, target_npu, ptfhost, ptfadapter, tbinfo,
            action=action, stop_after=stop_after
        )

        return verify_and_report(test_IO, verify, allowed_disruption_duration, allowed_disruption_count)

    yield _send_traffic
