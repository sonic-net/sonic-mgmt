from collections import OrderedDict
from spytest import SpyTestDict

ESI1 = "03:00:44:33:22:11:00:00:00:02"
EXPECTED_L3VNI = "5030"
EXPECTED_L2VNI = "5010"
## config: eBGP + ES
##  Topology : 1x Spine + 3 Leafs
##  SD1 -- Spine0  - D1
##  SD2 -- Leaf0   - D2
##  SD3 -- Leaf1   - D3
##  SD4 -- Leaf2   - D4

LEAF0_VXLAN_IP = "fd27::233:d0c6:fefb"
LEAF1_VXLAN_IP = "fd27::2dc:c1c9:e17c"
LEAF2_VXLAN_IP = "fd27::2d9:76fd:4c43"

SEQ_IDS = OrderedDict(
    [
        ("LEAF0", {"local": 0, "remote": 0}),
        ("LEAF1", {"local": 0, "remote": 0}),
        ("LEAF2", {"local": 0, "remote": 0}),
    ]
)

leaf0_vrf_prefix = "10.212.10.0"
leaf1_vrf_prefix = "10.212.10.0"
leaf2_vrf_prefix = "10.212.20.0"

# some fileds of spytest_data will be updated as part of traffic fixture
# values set remain constant throughout the test
spytest_data = SpyTestDict()
spytest_data.config_vrfs = []

spytest_data.d2t1_ip_addr = "10.212.10.10"  # Host1 GW
spytest_data.t1d2p1_ip_addr = "10.212.10.1"  # Host1 IP
spytest_data.t1d2p1_mac_addr = "00:00:00:00:00:01"  # Host1 Mac
spytest_data.lag_ip = "10.212.10.2"  # Lag IP
spytest_data.lag_gateway_ip = "10.212.10.10"  # Lag GW
spytest_data.lag_mac = "00:00:00:00:00:02"  # Lag Mac
spytest_data.t1d3p2_ip_addr = "10.212.10.5"  # Host5 IP
spytest_data.t1d3p2_mac_addr = "00:00:00:00:01:05"  # Host5 Mac
spytest_data.t1d4p1_ip_addr = "10.212.10.3"  # Host3 IP
spytest_data.t1d4p1_mac_addr = "00:00:00:00:02:03"  # Host3 Mac
spytest_data.d4t1_ip_addr = "10.212.20.10"  # Host3 GW
spytest_data.t1d4p2_ip_addr = "10.212.20.1"  # Host4 IP
spytest_data.t1d4p2_mac_addr = "00:00:00:00:02:04"  # Host4 Mac
lag_ports = ["T1D2P2", "T1D3P1"]
lag_name = "LAG1"
phy_int_map = {
    "T1D2P1": {
        "host_ip": spytest_data.t1d2p1_ip_addr,
        "gateway": spytest_data.d2t1_ip_addr,
        "mac": spytest_data.t1d2p1_mac_addr,
    },
    "T1D3P2": {
        "host_ip": spytest_data.t1d3p2_ip_addr,
        "gateway": spytest_data.d2t1_ip_addr,
        "mac": spytest_data.t1d3p2_mac_addr,
    },
    "T1D4P1": {
        "host_ip": spytest_data.t1d4p1_ip_addr,
        "gateway": spytest_data.d2t1_ip_addr,
        "mac": spytest_data.t1d4p1_mac_addr,
    },
    "T1D4P2": {
        "host_ip": spytest_data.t1d4p2_ip_addr,
        "gateway": spytest_data.d4t1_ip_addr,
        "mac": spytest_data.t1d4p2_mac_addr,
    },
}
lag_int_map = {
        lag_name: {
            "host_ip": spytest_data.lag_ip,
            "gateway": spytest_data.lag_gateway_ip,
            "mac": spytest_data.lag_mac,
        }
    }

interface_map = {}
interface_map.update(phy_int_map)
interface_map.update(lag_int_map)

port_name_map = {
    "H1": "T1D2P1",
    "H2": lag_name,
    "H3": "T1D4P1",
    "H4": "T1D4P2",
    "H5": "T1D3P2",
}
