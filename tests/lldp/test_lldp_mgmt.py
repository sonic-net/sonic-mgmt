"""
Tests for LLDP on management interface (eth0).

Lab management infrastructure typically does not forward LLDP frames,
so we inject crafted LLDP packets using a veth pair with tc mirred
ingress redirect to deliver frames directly into eth0's receive path.

This bypasses the Linux kernel's IEEE 802.1D reserved multicast
filtering (which blocks LLDP's 01:80:c2:00:00:0e in bridge/macvlan
code) because tc mirred injects via netif_receive_skb() and eth0
is not enslaved to any bridge.
"""

import logging
import struct
import time

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

MOCK_NEIGHBOR_NAME = "mock-neighbor"
MOCK_NEIGHBOR_DESC = "Mock LLDP neighbor for BMC testing"
MOCK_NEIGHBOR_PORT = "Ethernet0"
MOCK_NEIGHBOR_MAC = "aa:bb:cc:00:11:22"
LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
LLDP_TTL = 120
VETH_INJECT = "veth_lldp_inj"
VETH_SINK = "veth_lldp_sink"


# ---------------------------------------------------------------------------
# LLDP frame builder helpers
# ---------------------------------------------------------------------------

def _build_lldp_tlv(tlv_type, value_bytes):
    """Build a single LLDP TLV (type/length/value)."""
    length = len(value_bytes)
    header = struct.pack("!H", (tlv_type << 9) | length)
    return header + value_bytes


def _mac_to_bytes(mac_str):
    """Convert 'aa:bb:cc:00:11:22' to bytes."""
    return bytes(int(b, 16) for b in mac_str.split(":"))


def build_lldp_frame(src_mac=MOCK_NEIGHBOR_MAC,
                     chassis_name=None,
                     port_name=MOCK_NEIGHBOR_PORT,
                     ttl=LLDP_TTL,
                     system_name=MOCK_NEIGHBOR_NAME,
                     system_desc=MOCK_NEIGHBOR_DESC):
    """
    Build a complete LLDP Ethernet frame as a hex string.

    Returns:
        str: Hex-encoded Ethernet frame ready for raw socket send.
    """
    # Ethernet header: dst(6) + src(6) + ethertype(2)
    dst_mac = _mac_to_bytes(LLDP_MULTICAST_MAC)
    src_mac_bytes = _mac_to_bytes(src_mac)
    eth_header = dst_mac + src_mac_bytes + struct.pack("!H", 0x88CC)

    # Chassis ID TLV (type=1): subtype 4 (MAC address)
    chassis_id_value = struct.pack("B", 4) + _mac_to_bytes(
        chassis_name if chassis_name else src_mac
    )
    tlv_chassis = _build_lldp_tlv(1, chassis_id_value)

    # Port ID TLV (type=2): subtype 5 (interface name)
    port_id_value = struct.pack("B", 5) + port_name.encode()
    tlv_port = _build_lldp_tlv(2, port_id_value)

    # TTL TLV (type=3)
    tlv_ttl = _build_lldp_tlv(3, struct.pack("!H", ttl))

    # System Name TLV (type=5)
    tlv_sys_name = _build_lldp_tlv(5, system_name.encode())

    # System Description TLV (type=6)
    tlv_sys_desc = _build_lldp_tlv(6, system_desc.encode())

    # End of LLDPDU TLV (type=0, length=0)
    tlv_end = _build_lldp_tlv(0, b"")

    frame = (eth_header + tlv_chassis + tlv_port + tlv_ttl
             + tlv_sys_name + tlv_sys_desc + tlv_end)
    return frame.hex()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def lldp_inject(duthost):
    """
    Create a veth pair with tc mirred ingress redirect to inject LLDP
    frames into eth0's receive path, bypassing IEEE 802.1D multicast
    filtering.

    Topology:
        Send on veth_lldp_inj -> arrives on veth_lldp_sink (veth peer)
        -> tc mirred ingress redirect -> eth0 RX -> lldpd
    """
    # Clean up stale interfaces from a previous failed run
    duthost.shell("ip link del {} 2>/dev/null || true".format(VETH_INJECT))

    # Create veth pair
    duthost.shell(
        "ip link add {} type veth peer name {}".format(VETH_INJECT, VETH_SINK)
    )
    duthost.shell("ip link set {} up".format(VETH_INJECT))
    duthost.shell("ip link set {} up".format(VETH_SINK))

    # Set up tc on veth_sink: redirect ingress traffic to eth0's ingress
    duthost.shell("/sbin/tc qdisc add dev {} ingress".format(VETH_SINK))
    duthost.shell(
        "/sbin/tc filter add dev {} ingress protocol 0x88cc u32 match u32 0 0 "
        "action mirred ingress redirect dev eth0".format(VETH_SINK)
    )
    logger.info(
        "Created veth pair %s <-> %s with tc mirred redirect to eth0",
        VETH_INJECT, VETH_SINK
    )

    yield VETH_INJECT

    # Removing the veth pair also removes the tc config
    duthost.shell("ip link del {} 2>/dev/null || true".format(VETH_INJECT))
    logger.info("Removed veth pair %s <-> %s", VETH_INJECT, VETH_SINK)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _lldpcli_cmd(duthost, cmd):
    """Run an lldpcli command inside the lldp container."""
    return duthost.shell(
        "docker exec lldp lldpcli {}".format(cmd)
    )["stdout"]


def _send_lldp_frame(duthost, iface, frame_hex):
    """
    Send a raw Ethernet frame on the given interface using Python's
    socket module.  No scapy dependency required on the DUT.
    """
    # Use a small inline Python script to send raw frame
    py_script = (
        "import socket,binascii;"
        "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88cc));"
        "s.bind(('{}',0));"
        "s.send(binascii.unhexlify('{}'));"
        "s.close();"
        "print('sent')"
    ).format(iface, frame_hex)
    result = duthost.shell("python3 -c \"{}\"".format(py_script))
    pytest_assert("sent" in result["stdout"],
                  "Failed to send LLDP frame on {}".format(iface))


def _get_lldp_neighbors_json(duthost):
    """Get LLDP neighbors in JSON format from lldpctl."""
    output = duthost.shell(
        "docker exec lldp lldpctl -f json"
    )["stdout"]
    import json
    return json.loads(output)


def _wait_for_neighbor(duthost, expected_name, timeout=30, interval=5):
    """
    Poll lldpctl until a neighbor with the expected system name appears
    or timeout is reached.

    Returns:
        dict or None: The matching neighbor entry, or None if not found.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = _get_lldp_neighbors_json(duthost)
            lldp = data.get("lldp", {})
            interfaces = lldp.get("interface", {})

            # lldpctl JSON can return interface as a dict or a list
            if isinstance(interfaces, dict):
                interfaces = [interfaces]
            elif not isinstance(interfaces, list):
                interfaces = []

            for iface_entry in interfaces:
                if isinstance(iface_entry, dict):
                    for iface_name, iface_data in iface_entry.items():
                        chassis = iface_data.get("chassis", {})
                        # chassis can be a dict with the neighbor name as key
                        for chassis_name, chassis_info in chassis.items():
                            if chassis_name == expected_name:
                                return {
                                    "interface": iface_name,
                                    "chassis": chassis_info,
                                    "chassis_name": chassis_name,
                                    "port": iface_data.get("port", {}),
                                }
        except Exception as e:
            logger.debug("Error polling neighbors: %s", e)
        time.sleep(interval)
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLldpMgmt:
    """LLDP tests for management interface (eth0)."""

    def test_lldp_mgmt_interface_enabled(self, duthost):
        """Verify eth0 is registered with lldpd and has active TX."""
        output = _lldpcli_cmd(duthost, "show interfaces")
        pytest_assert("eth0" in output,
                      "eth0 not found in lldpcli interfaces output")

        stats = _lldpcli_cmd(duthost, "show statistics")
        logger.info("LLDP statistics:\n%s", stats)
        # Verify eth0 appears in statistics
        pytest_assert("eth0" in stats,
                      "eth0 not found in lldpcli statistics")

    def test_lldp_tx_frame_on_mgmt(self, duthost):
        """Verify the BMC transmits LLDP frames on eth0."""
        # Capture up to 1 LLDP frame within 35s (default TX interval ~30s)
        result = duthost.shell(
            "timeout 35 tcpdump -i eth0 -c 1 "
            "'ether proto 0x88cc' -q 2>&1 || true",
            module_ignore_errors=True
        )
        output = result["stdout"] + result.get("stderr", "")
        logger.info("tcpdump output:\n%s", output)
        pytest_assert(
            "1 packet captured" in output or "1 packets captured" in output,
            "No LLDP frame captured on eth0 within 35 seconds"
        )

    def test_lldp_neighbor_on_mgmt(self, duthost, lldp_inject):
        """
        Inject a crafted LLDP frame via veth + tc mirred and verify
        the mock neighbor appears in the LLDP neighbor table.
        """
        frame_hex = build_lldp_frame()

        # Send the frame multiple times to ensure lldpd picks it up
        for i in range(3):
            _send_lldp_frame(duthost, lldp_inject, frame_hex)
            logger.info("Sent LLDP frame %d/3 on %s", i + 1, lldp_inject)
            time.sleep(2)

        # Wait for lldpd to register the neighbor
        neighbor = _wait_for_neighbor(
            duthost, MOCK_NEIGHBOR_NAME, timeout=30, interval=5
        )
        pytest_assert(
            neighbor is not None,
            "Mock neighbor '{}' not found in LLDP table after injection".format(
                MOCK_NEIGHBOR_NAME)
        )

        logger.info("Found mock neighbor: %s", neighbor)

        # Verify neighbor details
        pytest_assert(
            neighbor["chassis_name"] == MOCK_NEIGHBOR_NAME,
            "Chassis name mismatch: expected '{}', got '{}'".format(
                MOCK_NEIGHBOR_NAME, neighbor["chassis_name"])
        )

    def test_lldp_neighbor_timeout(self, duthost, lldp_inject):
        """
        Inject a crafted LLDP frame with a short TTL and verify the
        neighbor entry is removed after the TTL expires.
        """
        short_ttl = 10
        frame_hex = build_lldp_frame(ttl=short_ttl)

        # Send the frame
        for _ in range(3):
            _send_lldp_frame(duthost, lldp_inject, frame_hex)
            time.sleep(2)

        # Verify neighbor appears
        neighbor = _wait_for_neighbor(
            duthost, MOCK_NEIGHBOR_NAME, timeout=30, interval=5
        )
        pytest_assert(neighbor is not None,
                      "Mock neighbor did not appear after injection")
        logger.info("Neighbor appeared, waiting for TTL (%ds) to expire", short_ttl)

        # Wait for TTL to expire + margin
        time.sleep(short_ttl + 5)

        # Verify neighbor is gone
        neighbor_after = _wait_for_neighbor(
            duthost, MOCK_NEIGHBOR_NAME, timeout=5, interval=2
        )
        pytest_assert(
            neighbor_after is None,
            "Mock neighbor '{}' still present after TTL expiry".format(
                MOCK_NEIGHBOR_NAME)
        )
        logger.info("Neighbor correctly expired after TTL")
