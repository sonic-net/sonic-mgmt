"""
Integration tests for the gNOI System.Traceroute RPC.

Traceroute streams a summary with the destination address and hop limit, then
one response per probe.
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

MAX_TTL = 5


def system_traceroute(gnmi_tls, **kwargs):  # noqa: F811
    try:
        return gnmi_tls.gnoi.system_traceroute(**kwargs)
    except Exception as e:
        if "Unimplemented" in str(e):
            pytest.skip(f"System.Traceroute is not implemented by this image: {e}")
        raise


def same_address(value, address):
    """Compare two IP addresses, ignoring how an IPv6 address is written."""
    try:
        return ipaddress.ip_address(value) == ipaddress.ip_address(address)
    except ValueError:
        return False


def check_reached(responses, target, max_ttl):
    """Check the summary, and that the probes of the last hop were answered by the target."""
    summary, probes = responses[0], responses[1:]
    pytest_assert(same_address(summary.get("destinationAddress"), target), f"Unexpected summary: {summary}")
    pytest_assert(summary.get("hops") == max_ttl, f"Summary does not report {max_ttl} hops: {summary}")
    pytest_assert(probes, f"No probe responses: {responses}")

    last_hop = max(probe.get("hop", 0) for probe in probes)
    pytest_assert(1 <= last_hop <= max_ttl, f"Last hop {last_hop} is out of range: {probes}")
    answered = [p for p in probes if p.get("hop") == last_hop and same_address(p.get("address"), target)]
    pytest_assert(answered, f"{target} did not answer at hop {last_hop}: {probes}")
    for probe in answered:
        pytest_assert(probe.get("rtt", 0) > 0, f"Probe has no round-trip time: {probe}")


@pytest.mark.parametrize("l4protocol", ["ICMP", "UDP"])
def test_gnoi_traceroute_ptf(duthosts, rand_one_dut_hostname, ptfhost, gnmi_tls, l4protocol):  # noqa: F811
    """Trace the route to the PTF management address, which ends at the PTF host."""
    duthost = duthosts[rand_one_dut_hostname]
    target = ptfhost.mgmt_ip
    pytest_require(
        duthost.shell(f"ping -c 1 -W 2 {target}", module_ignore_errors=True)["rc"] == 0,
        f"PTF host {target} does not answer ping from the DUT",
    )

    responses = system_traceroute(
        gnmi_tls,
        destination=target,
        max_ttl=MAX_TTL,
        wait=1000 * MS,
        do_not_resolve=True,
        l4protocol=l4protocol,
    )
    logger.info("Traceroute %s responses: %s", target, responses)
    check_reached(responses, target, MAX_TTL)


def test_gnoi_traceroute_vrf(gnmi_tls, gnoi_test_vrf):  # noqa: F811
    """Trace the route to an address that exists only in a VRF, from that VRF."""
    vrf, address = gnoi_test_vrf

    responses = system_traceroute(
        gnmi_tls,
        destination=address,
        max_ttl=MAX_TTL,
        wait=1000 * MS,
        do_not_resolve=True,
        network_instance=vrf,
    )
    logger.info("Traceroute %s in %s responses: %s", address, vrf, responses)
    check_reached(responses, address, MAX_TTL)


@pytest.mark.parametrize(
    "request_fields",
    [
        pytest.param({"destination": ""}, id="no_destination"),
        pytest.param({"destination": "-f"}, id="option_as_destination"),
        pytest.param({"destination": "127.0.0.1", "max_ttl": 256}, id="max_ttl_too_large"),
        pytest.param({"destination": "127.0.0.1", "initial_ttl": 10, "max_ttl": 5}, id="initial_ttl_above_max_ttl"),
        pytest.param({"destination": "127.0.0.1", "wait": -1}, id="negative_wait"),
        pytest.param({"destination": "127.0.0.1", "network_instance": "a;reboot"}, id="bad_network_instance"),
    ],
)
def test_gnoi_traceroute_invalid_request(gnmi_tls, request_fields):  # noqa: F811
    """Requests that traceroute cannot run are rejected with InvalidArgument."""
    with pytest.raises(Exception, match="InvalidArgument"):
        system_traceroute(gnmi_tls, **request_fields)
