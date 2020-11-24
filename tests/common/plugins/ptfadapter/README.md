# How to write traffic tests using PTF adapter

## Overview

```PtfTestAdapter``` provides an interface to send and receive traffic in the same way as ```ptf.base_tests.BaseTest``` object in PTF framework.
It makes use of ```ptf_nn_agent.py``` script running on PTF host, connects to it over TCP and initialize PTF data plane thread.

**NOTE** a good network connection between sonic-mgmt node and PTF host is required for traffic tests to be stable.

## Usage in pytest

You can use ```ptfadapter``` fixture which runs ```ptf_nn_agent.py``` on PTF and yields ```PtfTestAdapter``` object.

Example test case code using PTF adapter:

```python
import ptf.testutils as testutils
import ptf.mask as mask

def test_some_traffic(duthost, ptfadapter):
    pkt = testutils.simple_tcp_packet(
        eth_dst=duthost.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, 0),
        ip_src='1.1.1.1',
        ip_dst='192.168.0.1',
        ip_ttl=64,
        tcp_sport=1234,
        tcp_dport=4321)

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

    testutils.send(ptfadapter, 5, pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[28, 29, 30, 31])
```

If you have changed interface configuration on PTF host (like MAC address change) or you want to run PTF providing custom parameters you can use ```reinit``` method, e.g.:

```python
def test_some_traffic(ptfadapter):
    ptfadapter.reinit({'qlen': 1000})
    # rest of the test ...
```