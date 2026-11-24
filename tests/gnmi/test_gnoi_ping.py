"""
Integration tests for the gNOI System.Ping RPC.

Ping streams one response per reply, then a summary with the packet counts and
round-trip times.
"""

import ipaddress
import logging

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert, pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

MS = 1000 * 1000  # gNOI durations are in nanoseconds

# Documentation addresses (RFC 5737, RFC 3849), which never answer
UNREACHABLE = {4: "192.0.2.1", 6: "2001:db8::1"}


def system_ping(gnmi_tls, **kwargs):  # noqa: F811
    try:
        return gnmi_tls.gnoi.system_ping(**kwargs)
    except Exception as e:
        if "Unimplemented" in str(e):
            pytest.skip(f"System.Ping is not implemented by this image: {e}")
        raise


def same_address(value, address):
    """Compare two IP addresses, ignoring how an IPv6 address is written."""
    try:
        return ipaddress.ip_address(value) == ipaddress.ip_address(address)
    except ValueError:
        return False


def test_gnoi_ping_ptf(duthosts, rand_one_dut_hostname, ptfhost, gnmi_tls):  # noqa: F811
    """Ping the PTF management address: three replies, then a summary counting them."""
    duthost = duthosts[rand_one_dut_hostname]
    target = ptfhost.mgmt_ip
    pytest_require(
        duthost.shell(f"ping -c 1 -W 2 {target}", module_ignore_errors=True)["rc"] == 0,
        f"PTF host {target} does not answer ping from the DUT",
    )

    responses = system_ping(gnmi_tls, destination=target, count=3, interval=200 * MS)
    logger.info("Ping %s responses: %s", target, responses)

    *replies, summary = responses
    pytest_assert(len(replies) == 3, f"Expected 3 replies, got {replies}")
    for reply in replies:
        pytest_assert(same_address(reply.get("source"), target), f"Unexpected reply source: {reply}")
        pytest_assert(reply.get("time", 0) > 0, f"Reply has no round-trip time: {reply}")
        pytest_assert(reply.get("ttl", 0) > 0, f"Reply has no TTL: {reply}")

    pytest_assert(summary.get("sent") == 3, f"Summary does not count 3 sent: {summary}")
    pytest_assert(summary.get("received") == 3, f"Summary does not count 3 received: {summary}")
    pytest_assert(
        0 < summary.get("minTime", 0) <= summary.get("avgTime", 0) <= summary.get("maxTime", 0),
        f"Summary round-trip times are inconsistent: {summary}",
    )


def test_gnoi_ping_unreachable(ptfhost, gnmi_tls):  # noqa: F811
    """A destination that never answers still gets a summary, with nothing received."""
    target = UNREACHABLE[ipaddress.ip_address(ptfhost.mgmt_ip).version]

    responses = system_ping(gnmi_tls, destination=target, count=2, interval=200 * MS, wait=1000 * MS)
    logger.info("Ping %s responses: %s", target, responses)

    pytest_assert(len(responses) == 1, f"Expected only the summary, got {responses}")
    pytest_assert(responses[0].get("sent") == 2, f"Summary does not count 2 sent: {responses[0]}")
    pytest_assert(responses[0].get("received", 0) == 0, f"Summary counts replies: {responses[0]}")


def test_gnoi_ping_vrf(gnmi_tls, gnoi_test_vrf):  # noqa: F811
    """Ping an address that exists only in a VRF, from that VRF."""
    vrf, address = gnoi_test_vrf

    responses = system_ping(gnmi_tls, destination=address, count=2, interval=200 * MS, network_instance=vrf)
    logger.info("Ping %s in %s responses: %s", address, vrf, responses)

    summary = responses[-1]
    pytest_assert(summary.get("received") == 2, f"Summary does not count 2 received: {summary}")


@pytest.mark.parametrize(
    "request_fields",
    [
        pytest.param({"destination": ""}, id="no_destination"),
        pytest.param({"destination": "-f"}, id="option_as_destination"),
        pytest.param({"destination": "no-such-host.invalid"}, id="unresolvable_destination"),
        pytest.param({"destination": "127.0.0.1", "interval": 5 * MS}, id="interval_too_short"),
        pytest.param({"destination": "127.0.0.1", "count": -2}, id="negative_count"),
        pytest.param({"destination": "127.0.0.1", "size": 70000}, id="size_too_large"),
        pytest.param({"destination": "127.0.0.1", "network_instance": "a;reboot"}, id="bad_network_instance"),
    ],
)
def test_gnoi_ping_invalid_request(gnmi_tls, request_fields):  # noqa: F811
    """Requests that ping cannot run are rejected with InvalidArgument."""
    with pytest.raises(Exception, match="InvalidArgument"):
        system_ping(gnmi_tls, **request_fields)
