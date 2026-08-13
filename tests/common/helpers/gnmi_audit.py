import json
import shlex

from scapy.all import Raw, UDP, rdpcap

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


RPC_COMPLETION_PREFIX = "RPC_COMPLETION "


def parse_audit_records(log_text, method, principal):
    records = []
    decoder = json.JSONDecoder()
    for line in log_text.splitlines():
        _, separator, payload = line.partition(RPC_COMPLETION_PREFIX)
        if not separator:
            continue
        try:
            record, _ = decoder.raw_decode(payload)
        except json.JSONDecodeError:
            continue
        if (record.get("method") == method
                and record.get("principal") == principal):
            records.append(record)
    return records


def _audit_record_written(duthost, offset, method, principal):
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1),
        module_ignore_errors=True,
    )["stdout"]
    return len(parse_audit_records(new_log, method, principal)) == 1


def wait_for_audit_record(duthost, offset, method, principal):
    pytest_assert(
        wait_until(30, 1, 0, _audit_record_written,
                   duthost, offset, method, principal),
        "Missing {} completion record in /var/log/gnmi.log".format(method),
    )
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1)
    )["stdout"]
    records = parse_audit_records(new_log, method, principal)
    pytest_assert(
        len(records) == 1,
        "Expected exactly one {} completion record".format(method),
    )
    return records


def read_forwarded_payloads(duthost, capture_result, capture_file):
    pytest_assert(
        wait_until(35, 1, 0, capture_result.ready),
        "UDP/514 packet capture did not finish",
    )
    capture_status = capture_result.get()
    pcap_status = duthost.shell(
        "sudo test -s {}".format(shlex.quote(capture_file)),
        module_ignore_errors=True,
    )
    pytest_assert(
        pcap_status["rc"] == 0,
        "UDP/514 capture file is empty or missing: {}".format(
            capture_status
        ),
    )
    duthost.fetch(src=capture_file, dest="/tmp/", flat=True)
    return [
        bytes(packet[Raw].load).decode("utf-8", errors="replace")
        for packet in rdpcap(capture_file)
        if UDP in packet and Raw in packet
    ]
