# Wake-on-LAN Test Plan

## 1 Overview

The purpose is to test the functionality of **WoL** (**Wake-on-LAN**) feature on SONiC switch.

For details of WoL feature design, please refer to HLD: [Wake-on-LAN in SONiC](https://github.com/sonic-net/SONiC/blob/master/doc/wol/Wake-on-LAN-HLD.md).

### 1.1 Scope

The test is targeting a running SONiC system will fully functioning configuration. The purpose of this test is to verify the function of WoL CLI utility.

### 1.2 Testbed

The test can run on both physical and virtual testbeds with any topology.

### 1.3 Limitation

The functional test of WoL depends on NIC capability of target device. In real scenarios, the device waiting for wake up is in low-power mode. In this situation, the network interface is UP but wol packet is not delivered to CPU of device. Instead, the wol packet is handled by NIC and NIC will turn on the device.

In this testplan, the interfaces in PTF are not in low-power mode. **We only verify the SONiC switch can send out wol packet as expected. Will not verify the target device can be woken up.**

## 2 Setup Configuration

No setup pre-configuration is required, test will setup and clean-up all the configuration.

## 3 Test

### Test for WoL CLI Utility

The test will issue `wol` commands with various parameter combinations on DUT, then check if target devices (PTF) can capture the expected packet(s).

#### Test case #1 - Verrify send a wol packet to a specific interface
1. Start `tcpdump` process in PTF to capture WoL packet on spacific interface. Save the captured packets to `.pcap` file.
1. Issue command on DUT host:
   1. Send magic pattern in ethernet payload: `wol <sonic_interface_name> <target_mac>` (e.g., `wol Ethernet10 00:11:22:33:44:55`)
   1. Send magic pattern in udp payload with ipv4 address:  `wol <sonic_interface_name> <target_mac> <udp> <ip-address>` (e.g., `wol Ethernet10 00:11:22:33:44:55 -u --ip-address 255.255.255.255`)
   1. Send magic pattern in udp payload with ipv6 address and a specific udp_port:  `wol <sonic_interface_name> <target_mac> <udp> <ip-address> <udp-port>`  (e.g., `wol Ethernet10 00:11:22:33:44:55 -u --ip-address 2404:f801:10::ffff::ffff:ffff --udp-port 1234`)
1. Stop `tcpdump` process in PTF.
1. Check if only one wol packet exists in `.pcap` file and the content is expected.

#### Test case #2 - Verify send a wol packekt to each member of a vlan
1. Start multiple `tcpdump` processes in PTF to capture WoL packet on each interfaces. Save the captured packets to different `.pcap` files.
1. Issue command on DUT host:
   1. Send magic pattern in ethernet payload: `wol <vlan_name> <target_mac>`. (e.g., `wol Vlan1000 00:11:22:33:44:55`)
   1. Send magic pattern in udp payload with ipv4 address:  `wol <vlan_name> <target_mac> <udp> <ip-address>` (e.g., `wol Vlan1000 00:11:22:33:44:55 -u --ip-address 255.255.255.255`)
   1. Send magic pattern in udp payload with ipv6 address and a specific udp_port:  `wol <vlan_name> <target_mac> <udp> <ip-address> <udp-port>`  (e.g., `wol Vlan1000 00:11:22:33:44:55 -u --ip-address 2404:f801:10::ffff::ffff:ffff --udp-port 1234`)
1. Stop all `tcpdump` processes in PTF.
1. *For each interface in vlan*, check if one wol packet exists in corresponding `.pcap` file and the content is expected.
1. *For each interface not in vlan*, check no wol packet exists in corresponding `.pcap` file.

#### Test case #3 - Verify send a broadcast wol packet
1. Start `tcpdump` process in PTF to capture WoL packet on spacific interface. Save the captured packets to `.pcap` file.
1. Issue command on DUT host: `wol <sonic_interface_name> <target_mac> -b` (e.g., `wol Ethernet10 00:11:22:33:44:55 -b`)
1. Stop `tcpdump` process in PTF.
1. Check if only one wol packet exists in `.pcap` file and the content is expected. Especially, verify the destination MAC in Ethernet frame header is broadcast MAC address (`FF:FF:FF:FF:FF:FF`).

#### Test case #4 - Verify send a wol packet with password
1. Start `tcpdump` process in PTF to capture WoL packet on spacific interface. Save the captured packets to `.pcap` file.
1. Issue command on DUT host:
   1. Send magic pattern in ethernet payload: `wol <sonic_interface_name> <target_mac> -p <password>` (e.g., `wol Ethernet10 00:11:22:33:44:55 -p 192.168.1.1`)
   1. Send magic pattern in udp payload with ipv4 address:  `wol <sonic_interface_name> <target_mac> <udp> <ip-address>` (e.g., `wol Ethernet10 00:11:22:33:44:55 -u --ip-address 255.255.255.255` -p 11:22:33:44:55:66`)
   1. Send magic pattern in udp payload with ipv6 address and a specific udp_port:  `wol <sonic_interface_name> <target_mac> <udp> <ip-address> <udp-port>`  (e.g., `wol Ethernet10 00:11:22:33:44:55 -u --ip-address 2404:f801:10::ffff::ffff:ffff --udp-port 1234 -p 192.168.123.123`)
1. Stop `tcpdump` process in PTF.
1. Check if only one wol packet exists in `.pcap` file and the content is expected. Especially, verify the password in wol packet is same as command.

#### Test case #5 - Verify send multiple wol packets with specific interval to a specific interface
1. Start `tcpdump` process in PTF to capture WoL packet on spacific interface. Save the captured packets to `.pcap` file.
1. Issue command on DUT host:
   1. Send magic pattern in ethernet payload: `wol <sonic_interface_name> <target_mac> -c <count> -i <interval>` (e.g., `wol Ethernet10 00:11:22:33:44:55 -c 3 -i 2000`)
   1. Send magic pattern in udp payload with ipv4 address:  `wol <sonic_interface_name> <target_mac> <udp> <ip-address>` (e.g., `wol Ethernet10 00:11:22:33:44:55 -u --ip-address 255.255.255.255 -c 4 -i 1000`)
   1. Send magic pattern in udp payload with ipv6 address and a specific udp_port:  `wol <sonic_interface_name> <target_mac> <udp> <ip-address> <udp-port>`  (e.g., `wol Ethernet10 00:11:22:33:44:55 -u --ip-address 2404:f801:10::ffff::ffff:ffff --udp-port1234 -c 5 -i 1500`)
1. Stop `tcpdump` process in PTF.
1. Check if exact `<count>` wol packets exist in `.pcap` file and the content is expected. Moreover, check the time interval between each wol packet in `.pcap` file is ALMOST SAME[^1] as input `<interval>`.

#### Test case #6 - Verify send multiple wol packets with specific interval to each membor of a vlan
1. Start multiple `tcpdump` processes in PTF to capture WoL packet on each interfaces. Save the captured packets to different `.pcap` files.
1. Issue command on DUT host:
   1. `wol <vlan_name> <target_mac> -c <count> -i <interval>` (e.g., `wol Vlan1000 00:11:22:33:44:55 -c 3 -i 2000`)
   1. Send magic pattern in udp payload with ipv4 address:  `wol <vlan_name> <target_mac> <udp> <ip-address>` (e.g., `wol Vlan1000 00:11:22:33:44:55 -u --ip-address 255.255.255.255 -c 4 -i 1000`)
   1. Send magic pattern in udp payload with ipv6 address and a specific udp_port:  `wol <vlan_name> <target_mac> <udp> <ip-address> <udp-port>`  (e.g., `wol Vlan1000 00:11:22:33:44:55 -u --ip-address 2404:f801:10::ffff::ffff:ffff --udp-port 1234 -c 5 -i 1500`)
1. Stop `tcpdump` process in PTF.
1. *For each interface in vlan*, check if exact `<count>` wol packets exist in `.pcap` file and the content is expected. Moreover, check the time interval between each wol packet in `.pcap` file is ALMOST SAME[^1] as input `<interval>`.
1. *For each interface not in vlan*, check no wol packet exists in corresponding `.pcap` file.

#### Test case #7 - Verify constrain of parameters
1. Make sure count and interval both exist or not.
1. Make sure udp flag is required when using ip address or udp port.
1. Make sure udp flag is conflict with mac broadcast flag.

#### Test case #8 - Verify parameters can be set correctly by CLI
1. Make sure interface that receving packet and command line parameter interface are same.
1. Make sure target_mac in payload and command line parameter target_mac are same.
1. Make sure ip address (both ipv4 and ipv6 should be tested) in header and command line parameter ip_address are same.
1. Make sure when command line parameter ip_address is empty, ip address in header is default value: 255.255.255.255.
1. Make sure udp port in header and command line parameter udp port are same.
1. Make sure when command line parameter udp_port is empty, udp port in header is default value: 9.

[^1]: ALMOST SAME means we should tolerate small errors caused by electrical characteristics.
