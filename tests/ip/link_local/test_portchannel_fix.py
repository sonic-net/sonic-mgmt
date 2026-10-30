"""
Standalone unit test for the fix applied in test_link_local_ip.py for issue #26581.

Bug:
    common_params fixture called:
        rx_pc, tx_pc = random.sample(list(pc_ports_map.keys()), 2)
    Without checking if pc_ports_map has at least 2 entries.
    On topologies like t1-d96u4 with 0 or 1 PortChannels, this crashes with:
        ValueError: Sample larger than population or is negative

Fix:
    Added a guard before random.sample():
        if len(pc_ports_map) < 2:
            pytest.skip(...)

This test file proves the fix works without needing real SONiC hardware.
"""

import random
import pytest

pytestmark = [
    pytest.mark.topology('any')
]


# -----------------------------------------------------------------------
# The EXACT logic extracted from the common_params fixture
# (same code, no hardware dependencies)
# -----------------------------------------------------------------------

def simulate_common_params(pc_ports_map, downlinks):
    """
    Simulates the critical part of the common_params fixture.
    Returns ('rx_pc', 'tx_pc') on success, or raises pytest.skip.
    """
    if not downlinks:
        pytest.skip("Test case not supported: no downlinks in this topology")

    # THE FIX: guard before random.sample
    if len(pc_ports_map) < 2:
        pytest.skip(
            "SKIP: Not enough PortChannels for this test, "
            "need at least 2. Found {}".format(len(pc_ports_map))
        )

    rx_pc, tx_pc = random.sample(list(pc_ports_map.keys()), 2)
    return rx_pc, tx_pc


# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------

class TestPortChannelGuardFix:

    def test_zero_portchannels_skips_not_crashes(self):
        """
        Topology with NO PortChannels at all.
        OLD code: ValueError: Sample larger than population or is negative
        NEW code: pytest.skip is raised gracefully
        """
        pc_ports_map = {}
        downlinks = {"Ethernet0", "Ethernet4"}   # downlinks exist

        with pytest.raises(pytest.skip.Exception) as exc_info:
            simulate_common_params(pc_ports_map, downlinks)

        assert "Not enough PortChannels" in str(exc_info.value)
        assert "Found 0" in str(exc_info.value)
        print("\n[OK] 0 PortChannels -> graceful skip, not ValueError")

    def test_one_portchannel_skips_not_crashes(self):
        """
        Topology with exactly 1 PortChannel (like t1-d96u4).
        OLD code: ValueError: Sample larger than population or is negative
        NEW code: pytest.skip is raised gracefully
        """
        pc_ports_map = {"PortChannel0001": ["Ethernet64"]}
        downlinks = {"Ethernet0", "Ethernet4"}

        with pytest.raises(pytest.skip.Exception) as exc_info:
            simulate_common_params(pc_ports_map, downlinks)

        assert "Not enough PortChannels" in str(exc_info.value)
        assert "Found 1" in str(exc_info.value)
        print("\n[OK] 1 PortChannel -> graceful skip, not ValueError")

    def test_old_code_crashes_with_zero_portchannels(self):
        """
        PROVES THE BUG: reproduces what the old code did without the guard.
        random.sample on an empty list raises ValueError.
        """
        pc_ports_map = {}

        with pytest.raises(ValueError, match="Sample larger than population or is negative"):
            random.sample(list(pc_ports_map.keys()), 2)

        print("\n[BUG CONFIRMED] random.sample on empty list raises ValueError")

    def test_old_code_crashes_with_one_portchannel(self):
        """
        PROVES THE BUG: reproduces what the old code did with only 1 PortChannel.
        """
        pc_ports_map = {"PortChannel0001": ["Ethernet64"]}

        with pytest.raises(ValueError, match="Sample larger than population or is negative"):
            random.sample(list(pc_ports_map.keys()), 2)

        print("\n[BUG CONFIRMED] random.sample on 1-item list raises ValueError")

    def test_two_portchannels_proceeds_normally(self):
        """
        Topology with exactly 2 PortChannels: test should proceed (not skip).
        """
        pc_ports_map = {
            "PortChannel0001": ["Ethernet64"],
            "PortChannel0002": ["Ethernet68"],
        }
        downlinks = {"Ethernet0", "Ethernet4"}

        rx_pc, tx_pc = simulate_common_params(pc_ports_map, downlinks)

        assert rx_pc in pc_ports_map
        assert tx_pc in pc_ports_map
        assert rx_pc != tx_pc
        print("\n[OK] 2 PortChannels -> test proceeds normally: rx={}, tx={}".format(rx_pc, tx_pc))

    def test_many_portchannels_proceeds_normally(self):
        """
        Topology with many PortChannels (normal t1-64 etc): test proceeds normally.
        """
        pc_ports_map = {
            "PortChannel{}".format(i): ["Ethernet{}".format(i * 4)]
            for i in range(10)
        }
        downlinks = {"Ethernet100", "Ethernet104"}

        rx_pc, tx_pc = simulate_common_params(pc_ports_map, downlinks)

        assert rx_pc in pc_ports_map
        assert tx_pc in pc_ports_map
        assert rx_pc != tx_pc
        print("\n[OK] 10 PortChannels -> test proceeds normally: rx={}, tx={}".format(rx_pc, tx_pc))

    def test_no_downlinks_skips_regardless_of_portchannels(self):
        """
        The existing skip for no-downlinks topology still works correctly.
        """
        pc_ports_map = {
            "PortChannel0001": ["Ethernet64"],
            "PortChannel0002": ["Ethernet68"],
        }
        downlinks = set()   # empty - no downlinks

        with pytest.raises(pytest.skip.Exception) as exc_info:
            simulate_common_params(pc_ports_map, downlinks)

        assert "no downlinks" in str(exc_info.value)
        print("\n[OK] No downlinks -> graceful skip")


if __name__ == "__main__":
    print("=" * 65)
    print(" Testing PortChannel guard fix for issue #26581")
    print("=" * 65)
    pytest.main([__file__, "-v", "-s"])
