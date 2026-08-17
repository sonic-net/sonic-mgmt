import json
import shlex

from scapy.all import Raw, UDP, rdpcap

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


RPC_COMPLETION_PREFIX = "RPC_COMPLETION "


def get_audit_log_offset(duthost):
    return int(
        duthost.shell(
            "sudo stat -c %s /var/log/gnmi.log"
        )["stdout"].strip()
    )


def parse_audit_records(log_text, method, principal, code=None, path=None):
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
        if (record.get("method") != method
                or record.get("principal") != principal):
            continue
        if code is not None and record.get("code") != code:
            continue
        if path is not None and path not in (record.get("path") or []):
            continue
        records.append(record)
    return records


def _audit_records_written(duthost, offset, method, principal,
                           expected_count, code, path):
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1),
        module_ignore_errors=True,
    )["stdout"]
    records = parse_audit_records(
        new_log, method, principal, code=code, path=path
    )
    return len(records) >= expected_count


def wait_for_audit_records(duthost, offset, method, principal,
                           expected_count, code=None, path=None, timeout=30):
    pytest_assert(
        wait_until(timeout, 1, 0, _audit_records_written,
                   duthost, offset, method, principal,
                   expected_count, code, path),
        "Expected {} {} completion records in /var/log/gnmi.log".format(
            expected_count, method
        ),
    )
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1)
    )["stdout"]
    records = parse_audit_records(
        new_log, method, principal, code=code, path=path
    )
    pytest_assert(
        len(records) == expected_count,
        "Expected exactly {} {} completion records, got {}".format(
            expected_count, method, len(records)
        ),
    )
    return records


def wait_for_audit_record(duthost, offset, method, principal):
    return wait_for_audit_records(
        duthost, offset, method, principal, expected_count=1
    )


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
