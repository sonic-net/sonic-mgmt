



### After enabling

| Test                                                        | Error                                                        | Elastictest Link                                             |
| ----------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash       | RuntimeError: Didnot get any reply for this destination:150.0.3.1 Its active endpoints:['100.0.1.10'] | https://elastictest.org/scheduler/testplan/69fbca2e39aa410dfe77faed |
| vxlan/test_vxlan_ecmp.py::Test_VxLAN_entropy                | Test terminated before this test due to the error in vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash | https://elastictest.org/scheduler/testplan/69fbca2e39aa410dfe77faed |
| vxlan/test_vxlan_underlay_ecmp.py::Test_VxLAN_underlay_ecmp | RuntimeError: Underlay ECMP distribution among egress interfaces failed for endpoint 100.0.1.10. Interface PortChannel105 received 0 packet(s), expected between 1068.9642857142858 and 1781.6071428571427. | https://elastictest.org/scheduler/testplan/69fae4d990b147b195e54672 |
| vxlan/test_vxlan_multiple_tunnels.py                        | AssertionError: Did not receive expected packet on any of ports | https://elastictest.org/scheduler/testplan/69fbca2e39aa410dfe77faed |
| vxlan/test_vnet_decap.py                                    | AssertionError: Did not receive expected packet on any of ports | https://elastictest.org/scheduler/testplan/69fae4d990b147b195e54672 |
| vxlan/test_vxlan_bfd_tsa.py                                 | RuntimeError: Pls update this script for your platform.      | https://elastictest.org/scheduler/testplan/69fae4d990b147b195e54672 |                                                            |

