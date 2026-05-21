import sys
import os

# Add parent qos/ directory to path so qos_helpers can be found
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def pytest_configure(config):
    """Register custom markers used by this test module."""
    config.addinivalue_line(
        "markers",
        "config_only: pure CONFIG_DB test — no traffic or Ixia required; "
        "run with --skip-tgen to skip Ixia init",
    )
    config.addinivalue_line(
        "markers",
        "traffic: test requires Ixia traffic generator (D1T1:2 topology); "
        "skip with --skip-tgen",
    )
    config.addinivalue_line(
        "markers",
        "traffic_nxos: test requires a 2-DUT topology (D1D2:1) with scapy on D2; "
        "run with fx3_qos_testbed_peer_link.yaml",
    )
    config.addinivalue_line(
        "markers",
        "vxlan_transit: test requires a 2-DUT topology (peer_link/breakout) "
        "with VxLAN L3VNI + BGP EVPN configured on both DUTs (Section I); "
        "automatically skipped in single-DUT ixia mode",
    )
