# IPv4 Port Based DHCP Server Test Plan
<!-- TOC -->

- [IPv4 Port Based DHCP Server Test Plan](#ipv4-port-based-dhcp-server-test-plan)
    - [Related Documents](#related-documents)
    - [Overview](#overview)
    - [Scope](#scope)
        - [Test Scenario](#test-scenario)
        - [Supported Topology](#supported-topology)
    - [Test Case](#test-case)
        - [Test Module #1 test_dhcp_server.py](#test-module-1-test_dhcp_serverpy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_default](#test_dhcp_server_default)
            - [test_dhcp_server_config_change](#test_dhcp_server_config_change)
            - [test_dhcp_server_config_vlan_change](#test_dhcp_server_config_vlan_change)
            - [test_dhcp_server_critical_process](#test_dhcp_server_critical_process)
        - [Test Module #2 test_dhcp_server_multi_vlan.py](#test-module-2-test_dhcp_server_multi_vlanpy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_multi_vlan](#test_dhcp_server_multi_vlan)
        - [Test Module #3 test_dhcp_server_stress.py](#test-module-3-test_dhcp_server_stresspy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_stress](#test_dhcp_server_stress)
        - [Test Module #4 test_dhcp_server_smart_switch.py](#test-module-4-test_dhcp_server_smart_switchpy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_smart_switch](#test_dhcp_server_smart_switch)

<!-- /TOC -->

## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| IPv4 Port Based DHCP_SERVER in SONiC | [port_based_dhcp_server_high_level_design.md](https://github.com/sonic-net/SONiC/blob/master/doc/dhcp_server/port_based_dhcp_server_high_level_design.md)|
|Smart Switch IP address assignment| [smart-switch-ip-address-assignment.md](https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/ip-address-assigment/smart-switch-ip-address-assignment.md)|

## 1. Overview

A DHCP Server is a server on network that can automatically provide and assign IP addresses, default gateways and other network parameters to client devices. Port based DHCP server is to assign IPs based on interface index.

## 2. Scope

### 2.1. Test Scenario

The tests will include:

1. Configuration test
   1. Add related configuration into CONFIG_DB and then verify configuration and process running status.
   2. Update related tables in CONFIG_DB to see whether configuration for DHCP Server change too.
2. Functionality test
   1. Check whether dhcrelay in dhcp_relay can foward DHCP packets between client and dhcp_server container.
   2. Check whether dhcp_server container can reply DHCP reply packets as expected.
   3. Verify in multi-vlan scenario.

### 2.2. Supported Topology

Base dhcp_server functionality tests (test module [#1](#test-module-1-test_dhcp_serverpy) [#2](#test-module-2-test_dhcp_server_multi_vlanpy) [#3](#test-module-3-test_dhcp_server_stresspy)) are supported on mx topology, smart switch related test (test module [#4](#test-module-4-test_dhcp_server_smart_switchpy)) is supported on t1 topology.

## 3. Test Case

### Test Module #1 test_dhcp_server.py

#### Common setup

* Check whether dhcrelay process running as expected (Original dhcp_relay functionality).
* Enable dhcp_server feature, and then use CLI to add DHCP Server configuration.

#### Common teardown

* Diable dhcp_server fature, and then check whether dhcrelay process running as expected (Original dhcp_relay functionality).
* Config reload, remove dhcp_server container.

#### test_dhcp_server_default

* **Test objective**

   To test base ip assign.

* **Test detail**

  * Check whether dhcrelay/dhcpmon processes running as expected (status, parameters) in dhcp_relay container.
  * Check whether configuration file generated in dhcp_server container as expected, path: `dhcp_server:/etc/kea/kea-dhcp4.conf`
  * Send DHCP discover packets from ptf, check whether configured port receive DHCP offer packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr / customized_options.
  * Send DHCP request packets from ptf, check whether configured port receive DHCP offer packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr / customized_options. Besides, check lease file (path: `dhcp_server:/tmp/kea-lease.csv`) inside dhcp_server container to make sure lease record is correct.
  * Send DHCP release packets from ptf, check whether lease release via lease file inside dhcp_server container.

#### test_dhcp_server_config_change

* **Test objective**

   To test dhcp_server configuration change scenario.

* **Test detail**

  * Use CLI to modify lease_time / netmask / gateway / customized_options in `DHCP_SEVER_IPV4` table to see whether `dhcp_server:/etc/kea/kea-dhcp4.conf` change as expected.
  * Use CLI to disable / enable DHCP interface to see whether dhcrelay/dhcpmon process in dhcp_relay container change, whether `dhcp_server:/etc/kea/kea-dhcp4.conf` change as expected.
  * Use CLI to modify `DHCP_SERVER_IPV4_PORT` / `DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS` table to see whether `dhcp_server:/etc/kea/kea-dhcp4.conf` change as expected.

#### test_dhcp_server_config_vlan_change

* **Test objective**

   To test vlan configuration change scenario.

* **Test detail**

  * Modify vlan ip in `VLAN_INTERFACE` table, change to another subnet. Check `dhcp_server:/etc/kea/kea-dhcp4.conf`, expect no interface configured.
  * Modify vlan ip back and remove vlan member in `VLAN_MEMBER` table that was configured in `DHCP_SERVER_IPV4_PORT` table, expect that configuration doesn't contain removed port.

#### test_dhcp_server_critical_process

* **Test objective**

   To test critical processes crush scenario.

* **Test detail**
  
   * Kill processes in `dhcp_relay:/etc/supervisor/critical_processes` and `dhcp_server:/etc/supervisor/critical_processes` to see whether dhcp_server and dhcp_relay container restart.
   * Can refer to `tests/process_monitoring/test_critical_process_monitoring.py`

### Test Module #2 test_dhcp_server_multi_vlan.py

#### Common setup

* Enable dhcp_server feature.
* Apply DHCP Server related configuration for multiple vlans (Suggest use GCU).
* Install isc-dhcp-client in ptf.

#### Common teardown

* Config reload, remove dhcp_server container.
* Uninstall isc-dhcp-client in ptf.

#### test_dhcp_server_multi_vlan

* **Test objective**

   To test ip assign in multiple vlan scenario.

* **Test detail**

  * Use GCU to apply different VLAN configuration (VLAN / VLAN_MEMBER / VLAN_INTERFACE).
  * Check whether dhcpmon / dhcrelay processes running status is consistent with configuration.
  * Check whether `dhcp_server:/etc/kea/kea-dhcp4.conf` is consistent with configuration.
  * Use dhclient in ptf to check whether configured port can get ip and non-configured port cannot get ip.

### Test Module #3 test_dhcp_server_stress.py

#### Common setup

* Enable dhcp_server feature, and then add DHCP Server configuration.

#### Common teardown

* Config reload, remove dhcp_server container.

#### test_dhcp_server_stress

* **Test objective**

   To test ip assign with flooding packets.

* **Test detail**

   * Send flooding (100/s) DHCP discover packets in ptf and verify offer packets receive (whether receive and receive time) in ptf side.
   * Send flooding (100/s) DHCP request packets in ptf and verify ack packets receive (whether receive and receive time) in ptf side.
   * During test, increasement of CPU and memory utilization don't exceed threshold.

### Test Module #4 test_dhcp_server_smart_switch.py

#### Common setup

* Enable dhcp_server feature.
* Set `DEVICE_METADATA|localhost|subtype` to "SmartSwitch".
* Create a bridge in DUT and add 4 interface into it.
* Config ip address in bridge.
* Add DHCP Server configuration.
* Add smart switch related configuration.
* Install isc-dhcp-client in ptf.

#### Common teardown

* Config reload, remove dhcp_server container.
* Remove bridge.
* Uninstall isc-dhcp-client in ptf.

#### test_dhcp_server_smart_switch

* **Test objective**

   To test ip assign with in smart switch.

* **Test detail**
  
  * Use dhclient to get ip in ptf
