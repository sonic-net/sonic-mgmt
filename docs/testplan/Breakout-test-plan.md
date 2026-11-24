- [Overview](#overview)
  * [Scope](#scope)
  * [Testbed](#testbed)
  * [Breakout Modes](#breakout-modes)

- [Setup Configuration](#setup-configuration)
  * [Setup of DUT Switch](#setup-of-dut-switch
  * [Breakout Configuration](#breakout-configuration)


- [Test Cases][#test-cases]


## Overview
The Overview section provides a high-level understanding of what the document is about. It sets the context for breakout testing, configuration, and validation on the DUT (Device Under Test).

## Scope
The test targets a running SONiC system with basic network connectivity and supported breakout-capable interfaces.

The purpose of this test is to verify the port breakout (channelization) functionality on the SONiC device. This includes validating that high-speed physical ports can be split into multiple lower-speed logical interfaces and operate correctly under different configurations.

## Testbed
T1 TOPO

## Setup Configuration
This section defines the required devices and their roles in the test environment for validating breakout functionality in a T1 topology.

#### Setup of DUT switch
During testrun, Ansible will copy Breakout commands to DUT.

Breakout CLI COMMAND

- 'sudo config interface breakout Ethernet0 2x400G[200G] -f'
- 'sudo config interface breakout Ethernet0 4x200G[100G] -f'
- 'sudo config interface breakout Ethernet0 8x100G[50G] -f'

Ping Validation for IPv4 and IPv6 on DUT.
### Ping Validation for IPv4 and IPv6 on DUT

- IPv4: `ping <IPv4-peer>`
- IPv6: `ping6 <IPv6-peer>`

### Note:
- 'Verify the optics support for channelization speeds (800G, 400G, 100G) and execute the breakout configuration accordingly'
- 'Breakout should be done for both Fanout and DUT'

## Test cases
### Test case # 1 - Verify 2x400G, L3 Interface Creation After Breakout on Random Interface (IPv4 and IPv6)
**Topology:** T0 and T1

**Selection:** Randomly select an operational, supported DUT interface that has a valid DUT-to-fanout connection and is not a management or reserved interface. Derive the fanout interface from the topology connection graph.

1. Record the pre-breakout mode and identify the old child interfaces that will be removed.
2. Apply breakout configuration on the DUT:

   ```text
   sudo config interface breakout <InterfaceName> 2x400G[200G] -f
   ```

   Apply the corresponding breakout configuration on the SONiC fanout interface and bring up the DUT and fanout child interfaces:

   ```text
   sudo config interface breakout <FanoutInterface> 2x400G[200G] -f
   sudo config interface startup <child1>
   sudo config interface startup <child2>
   sudo config interface startup <FanoutChild1>
   sudo config interface startup <FanoutChild2>
   ```

3. Verify the breakout related show outputs and CONFIG_DB entries. `<InterfaceName>` is the parent port, for example `Ethernet0`; `<child1>` and `<child2>` are `Ethernet0` and `Ethernet4`; `<removed1>` and `<removed2>` are child names from the previous mode that no longer exist, for example `Ethernet2` and `Ethernet6`:

   ```text
   show interfaces breakout current-mode <InterfaceName>
   show interfaces breakout | grep -A 12 '"<InterfaceName>"'
   show interfaces status | grep -E "^ +(<child1>|<child2>|<removed1>|<removed2>) "
   redis-cli -n 4 HGETALL "BREAKOUT_CFG|<InterfaceName>"
   redis-cli -n 4 KEYS "PORT|Ethernet*"
   redis-cli -n 4 HMGET "PORT|<child1>" alias lanes speed index
   redis-cli -n 4 HMGET "PORT|<child2>" alias lanes speed index
   ```

   Expected: the current mode is `2x400G[200G]`; `show interfaces breakout` lists `"brkout_mode": "2x400G[200G]"`, the parent lanes, and the breakout_modes list; `<child1>` and `<child2>` are listed in `show interfaces status` with 400G speed, and `<removed1>` and `<removed2>` are absent. `BREAKOUT_CFG|<InterfaceName>` contains `brkout_mode=2x400G[200G]`; both child `PORT` entries exist and the removed child entries do not. Each child has `speed=400000`, the parent lanes are split evenly between the children, and `admin_status` is `up` after startup.

   Repeat the relevant breakout verification on the fanout. On a multi-ASIC DUT use `show interfaces breakout -n <asic>` and `sonic-db-cli -n <asic> CONFIG_DB HGETALL "BREAKOUT_CFG|<InterfaceName>"`.

4. Configure IPv4 and IPv6 addresses and create the required L3 binding on the DUT and peer:

   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3):

     ```text
     sudo config vlan add 100
     sudo config vlan member add -u 100 <child1>
     sudo config interface ip add Vlan100 192.168.100.1/24
     sudo config interface ip add Vlan100 2001:db8:100::1/64
     ping -I <child1> 192.168.100.2 -c 10
     ping6 -I <child1> 2001:db8:100::2 -c 10
     show vlan brief
     show ip interface Vlan100
     show ipv6 interface Vlan100
     redis-cli -n 4 HGETALL "VLAN_MEMBER|Vlan100|<child1>"
     ```

     Peer: On the ARISTA VM, configure the peer/fanout port corresponding to `<child1>` as untagged VLAN 100. Configure peer `Vlan100` with `192.168.100.2/24` and `2001:db8:100::2/64`. Verify ping and BGP on `<child1>`.

     After the first-child checks pass, remove `<child1>` from the VLAN and move the same VLAN/SVI IP pair to `<child2>`:

     ```text
     sudo config vlan member del 100 <child1>
     sudo config vlan member add -u 100 <child2>
     ping -I <child2> 192.168.100.2 -c 10
     ping6 -I <child2> 2001:db8:100::2 -c 10
     show vlan brief
     redis-cli -n 4 KEYS "VLAN_MEMBER|Vlan100|*"
     redis-cli -n 4 HGETALL "VLAN_MEMBER|Vlan100|<child2>"
     ```

     Move the ARISTA peer port to VLAN 100 for `<child2>`. Keep the DUT and peer SVI addresses unchanged. The same IP pair is active on only one breakout child at a time.

   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3):

     ```text
     sudo config portchannel add PortChannel10
     sudo config portchannel member add PortChannel10 <child1>
     sudo config interface startup PortChannel10
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show interfaces portchannel
     show ip interface PortChannel10
     show ipv6 interface PortChannel10
     redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|PortChannel10|*"
     ```

     Peer: On the ARISTA VM, create `Port-Channel10`, add the peer port corresponding to `<child1>`, and configure `192.0.2.0/31` and `2001:db8:1::/127` on the peer PortChannel.

     After the first-child checks pass, remove `<child1>` and the PortChannel IP, attach `<child2>`, and reuse the same IP pair:

     ```text
     sudo config portchannel member del PortChannel10 <child1>
     sudo config interface ip remove PortChannel10 192.0.2.1/31
     sudo config interface ip remove PortChannel10 2001:db8:1::1/127
     sudo config portchannel member add PortChannel10 <child2>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show interfaces portchannel
     redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|PortChannel10|*"
     ```

     Move the ARISTA peer link to `Port-Channel10` for `<child2>`. Keep `192.0.2.0/31` and `2001:db8:1::/127` unchanged. Do not configure a direct IP on the physical breakout child.

   - T1 routed (apply `SETUP-T1`, 6.3):

     ```text
     sudo config interface startup <child1>
     sudo config interface ip add <child1> 192.0.2.1/31
     sudo config interface ip add <child1> 2001:db8:1::1/127
     ping -I <child1> 192.0.2.0 -c 10
     ping6 -I <child1> 2001:db8:1:: -c 10
     show interfaces status | grep -E "^ +<child1> "
     show ip interface <child1>
     show ipv6 interface <child1>
     redis-cli -n 4 KEYS "INTERFACE|<child1>*"
     ```

     Peer: On the ARISTA VM, configure the peer port corresponding to `<child1>` as routed with `192.0.2.0/31` and `2001:db8:1::/127`. Verify IPv4 and IPv6 ping and BGP through `<child1>`.

     After the first-child checks pass, remove the IP from `<child1>` and attach the same IP pair to `<child2>`:

     ```text
     sudo config interface ip remove <child1> 192.0.2.1/31
     sudo config interface ip remove <child1> 2001:db8:1::1/127
     sudo config interface startup <child2>
     sudo config interface ip add <child2> 192.0.2.1/31
     sudo config interface ip add <child2> 2001:db8:1::1/127
     ping -I <child2> 192.0.2.0 -c 10
     ping6 -I <child2> 2001:db8:1:: -c 10
     show interfaces status | grep -E "^ +(<child1>|<child2>) "
     show ip interface <child2>
     show ipv6 interface <child2>
     redis-cli -n 4 KEYS "INTERFACE|<child1>*"
     redis-cli -n 4 KEYS "INTERFACE|<child2>*"
     ```

     Move the ARISTA peer routed configuration to the peer port corresponding to `<child2>`. Keep `192.0.2.0/31` and `2001:db8:1::/127` unchanged. The same DUT/peer IP pair is not active on both breakout children simultaneously.

   Remove or release any existing VLAN, PortChannel, or IP binding from the selected breakout child before applying the variant when required by the breakout dependency rules.

5. Verify IPv4 and IPv6 BGP and L3 connectivity sequentially. Configure and test `<child1>` first, then detach its IP/member binding and attach the same IP pair to `<child2>`:

   - T0 VLAN:

     ```text
     sudo config vlan member add -u 100 <child1>
     ping -I <child1> 192.168.100.2 -c 10
     ping6 -I <child1> 2001:db8:100::2 -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config vlan member del 100 <child1>
     sudo config vlan member add -u 100 <child2>
     ping -I <child2> 192.168.100.2 -c 10
     ping6 -I <child2> 2001:db8:100::2 -c 10
     show ip bgp summary
     show bgp ipv6 summary
     ```

     Configure the ARISTA peer port corresponding to `<child1>`, verify the peer SVI, move the peer port/member to `<child2>`, and verify again. The SVI IP addresses remain on `Vlan100`; only the breakout VLAN member is moved.

   - T0 PortChannel:

     ```text
     sudo config portchannel member add PortChannel10 <child1>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config portchannel member del PortChannel10 <child1>
     sudo config interface ip remove PortChannel10 192.0.2.1/31
     sudo config interface ip remove PortChannel10 2001:db8:1::1/127
     sudo config portchannel member add PortChannel10 <child2>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     ```

     Move the corresponding ARISTA peer link between `<child1>` and `<child2>` while preserving `192.0.2.0/31` and `2001:db8:1::/127`.

   - T1 routed:

     ```text
     sudo config interface ip add <child1> 192.0.2.1/31
     sudo config interface ip add <child1> 2001:db8:1::1/127
     ping -I <child1> 192.0.2.0 -c 10
     ping6 -I <child1> 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config interface ip remove <child1> 192.0.2.1/31
     sudo config interface ip remove <child1> 2001:db8:1::1/127
     sudo config interface ip add <child2> 192.0.2.1/31
     sudo config interface ip add <child2> 2001:db8:1::1/127
     ping -I <child2> 192.0.2.0 -c 10
     ping6 -I <child2> 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     ```

     Move the routed ARISTA peer port from `<child1>` to `<child2>` and keep `192.0.2.0/31` and `2001:db8:1::/127` unchanged.

   Expected: for `<child1>` and then `<child2>`, each configured IPv4 and IPv6 BGP session is `Established`, and ping success is at least 50 percent. The same DUT/peer IP pair is not active on both children simultaneously.

6. Verify interface and routing state after the final `<child2>` configuration:

   ```text
   show ip interface
   show ipv6 interface
   show ip route
   show ipv6 route
   show interfaces status | grep -E "^ +(<child1>|<child2>) "
   show interfaces portchannel
   show vlan brief
   ```

   Expected: `<child2>` is operational and the final VLAN, PortChannel, or routed IP binding is active. The peer network is installed in the IPv4 and IPv6 routing tables through `<child2>`. `<child1>` has no stale IP or VLAN/PortChannel member unless the topology requires both links to remain active.

7. Repeat the breakout show and CONFIG_DB commands from step 3 after the L3 configuration and traffic. Verify that the breakout mode, child/removed port names, lane split, alias, index, and speed remain unchanged.

### Test case # 2 - Breakout 4x200G, L3 Interface Creation After Breakout on Random Interface (IPv4 and IPv6)
**Topology:** T0 and T1

**Selection:** Randomly select an operational, supported DUT interface that has a valid DUT-to-fanout connection and is not a management or reserved interface. Derive the fanout interface and all four fanout child ports from the topology connection graph.

1. Record the pre-breakout mode and the old child interfaces that will be removed.
2. Apply breakout configuration on the DUT and the corresponding fanout:

   ```text
   sudo config interface breakout <InterfaceName> 4x200G[100G] -f
   sudo config interface breakout <FanoutInterface> 4x200G[100G] -f
   ```

3. Verify the breakout mode and the properties of the broken down ports. `<InterfaceName>` is the parent, for example `Ethernet0`; `<child1>` to `<child4>` are `Ethernet0`, `Ethernet2`, `Ethernet4`, and `Ethernet6`:

   ```text
   show interfaces breakout current-mode <InterfaceName>
   show interfaces breakout | grep -A 12 '"<InterfaceName>"'
   redis-cli -n 4 HGETALL "BREAKOUT_CFG|<InterfaceName>"
   redis-cli -n 4 HMGET "PORT|<child1>" alias lanes index speed admin_status
   redis-cli -n 4 HMGET "PORT|<child2>" alias lanes index speed admin_status
   redis-cli -n 4 HMGET "PORT|<child3>" alias lanes index speed admin_status
   redis-cli -n 4 HMGET "PORT|<child4>" alias lanes index speed admin_status
   show interfaces status | grep -E "^ +(<child1>|<child2>|<child3>|<child4>) "
   redis-cli -n 4 KEYS "PORT|Ethernet*"
   ```

   Expected: the current mode is `4x200G[100G]` and `BREAKOUT_CFG|<InterfaceName>` contains `brkout_mode=4x200G[100G]`. For each child: `alias` matches the platform breakout entry, `lanes` is one equal lane group from the parent with no overlap, `index` is the parent front-panel index, `speed` is `200000`, and `admin_status` is `down` until startup. The four sets together equal the parent lanes, for example `0,1` / `2,3` / `4,5` / `6,7`. `show interfaces status` lists four 200G children.

   Bring up all DUT and fanout children, then verify them:

   ```text
   sudo config interface startup <child1>
   sudo config interface startup <child2>
   sudo config interface startup <child3>
   sudo config interface startup <child4>
   sudo config interface startup <FanoutChild1>
   sudo config interface startup <FanoutChild2>
   sudo config interface startup <FanoutChild3>
   sudo config interface startup <FanoutChild4>
   redis-cli -n 4 HGET "PORT|<child1>" admin_status
   redis-cli -n 4 HGET "PORT|<child2>" admin_status
   redis-cli -n 4 HGET "PORT|<child3>" admin_status
   redis-cli -n 4 HGET "PORT|<child4>" admin_status
   show interfaces status | grep -E "^ +(<child1>|<child2>|<child3>|<child4>) "
   ```

   Expected: `admin_status` is `up` and the four DUT children are `up/up` after startup. Repeat the relevant breakout and startup verification on the fanout.

   On a multi-ASIC DUT use `show interfaces breakout -n <asic>` and `sonic-db-cli -n <asic> CONFIG_DB HGETALL "BREAKOUT_CFG|<InterfaceName>"`.

4. Configure IPv4 and IPv6 addresses on the DUT and corresponding peer for the selected topology:

   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3):

     ```text
     sudo config vlan add 100
     sudo config interface ip add Vlan100 192.168.100.1/24
     sudo config interface ip add Vlan100 2001:db8:100::1/64
     show vlan brief
     show ip interface Vlan100
     show ipv6 interface Vlan100
     ```

     On the ARISTA VM, configure peer `Vlan100` with `192.168.100.2/24` and `2001:db8:100::2/64`. Test all four DUT breakout children sequentially; attach only one child as an untagged VLAN 100 member at a time:

     ```text
     for p in <child1> <child2> <child3> <child4>; do
       sudo config vlan member add -u 100 $p
       ping -I $p 192.168.100.2 -c 10
       ping6 -I $p 2001:db8:100::2 -c 10
       show ip bgp summary
       show bgp ipv6 summary
       sudo config vlan member del 100 $p
     done
     show vlan brief
     redis-cli -n 4 KEYS "VLAN_MEMBER|Vlan100|*"
     ```

     Before each ping, move the corresponding ARISTA peer/fanout port to VLAN 100. Keep the DUT and peer SVI addresses unchanged. The same IP pair is active on only one child at a time.

   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3):

     ```text
     sudo config portchannel add PortChannel10
     sudo config interface startup PortChannel10
     show interfaces portchannel
     ```

     On the ARISTA VM, create `Port-Channel10` and configure `192.0.2.0/31` and `2001:db8:1::/127`. Test all four breakout children sequentially, removing the previous member and PortChannel IP before attaching the next child:

     ```text
     for p in <child1> <child2> <child3> <child4>; do
       sudo config portchannel member add PortChannel10 $p
       sudo config interface ip add PortChannel10 192.0.2.1/31
       sudo config interface ip add PortChannel10 2001:db8:1::1/127
       ping -I PortChannel10 192.0.2.0 -c 10
       ping6 -I PortChannel10 2001:db8:1:: -c 10
       show ip bgp summary
       show bgp ipv6 summary
       show interfaces portchannel
       sudo config portchannel member del PortChannel10 $p
       sudo config interface ip remove PortChannel10 192.0.2.1/31
       sudo config interface ip remove PortChannel10 2001:db8:1::1/127
     done
     redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|PortChannel10|*"
     ```

     Move the corresponding ARISTA peer link into `Port-Channel10` for each child in the same sequence. Keep the peer PortChannel addresses unchanged. No physical breakout child retains a direct IP address.

   - T1 routed (apply `SETUP-T1`, 6.3):

     Test one child at a time with the same DUT and peer IP pair. Remove the IP from the current child before configuring the next child:

     ```text
     for p in <child1> <child2> <child3> <child4>; do
       sudo config interface ip add $p 192.0.2.1/31
       sudo config interface ip add $p 2001:db8:1::1/127
       ping -I $p 192.0.2.0 -c 10
       ping6 -I $p 2001:db8:1:: -c 10
       show ip bgp summary
       show bgp ipv6 summary
       sudo config interface ip remove $p 192.0.2.1/31
       sudo config interface ip remove $p 2001:db8:1::1/127
     done
     show interfaces status | grep -E "^ +(<child1>|<child2>|<child3>|<child4>) "
     redis-cli -n 4 KEYS "INTERFACE|<child1>*"
     redis-cli -n 4 KEYS "INTERFACE|<child2>*"
     redis-cli -n 4 KEYS "INTERFACE|<child3>*"
     redis-cli -n 4 KEYS "INTERFACE|<child4>*"
     ```

     On the ARISTA VM, move the routed peer port to the corresponding breakout child in the same sequence and keep `192.0.2.0/31` and `2001:db8:1::/127` unchanged. The same DUT/peer IP pair is not active on two breakout children simultaneously.

   Remove or release any existing VLAN, PortChannel, or IP binding from the selected breakout children before applying the variant where required by breakout dependency rules.

5. Verify IPv4 and IPv6 BGP and direct L3 connectivity sequentially. Test `<child1>`, `<child2>`, `<child3>`, and `<child4>` one at a time, using the same DUT/peer IP pair:

   - T0 VLAN:

     ```text
     sudo config vlan member add -u 100 <child1>
     ping -I <child1> 192.168.100.2 -c 10
     ping6 -I <child1> 2001:db8:100::2 -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config vlan member del 100 <child1>

     sudo config vlan member add -u 100 <child2>
     ping -I <child2> 192.168.100.2 -c 10
     ping6 -I <child2> 2001:db8:100::2 -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config vlan member del 100 <child2>

     sudo config vlan member add -u 100 <child3>
     ping -I <child3> 192.168.100.2 -c 10
     ping6 -I <child3> 2001:db8:100::2 -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config vlan member del 100 <child3>

     sudo config vlan member add -u 100 <child4>
     ping -I <child4> 192.168.100.2 -c 10
     ping6 -I <child4> 2001:db8:100::2 -c 10
     show ip bgp summary
     show bgp ipv6 summary
     ```

     Move the ARISTA peer port for each child in the same sequence. Keep peer `Vlan100` at `192.168.100.2/24` and `2001:db8:100::2/64`. `<child4>` is the final active VLAN member.

   - T0 PortChannel:

     ```text
     sudo config portchannel member add PortChannel10 <child1>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config portchannel member del PortChannel10 <child1>
     sudo config interface ip remove PortChannel10 192.0.2.1/31
     sudo config interface ip remove PortChannel10 2001:db8:1::1/127

     sudo config portchannel member add PortChannel10 <child2>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config portchannel member del PortChannel10 <child2>
     sudo config interface ip remove PortChannel10 192.0.2.1/31
     sudo config interface ip remove PortChannel10 2001:db8:1::1/127

     sudo config portchannel member add PortChannel10 <child3>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     sudo config portchannel member del PortChannel10 <child3>
     sudo config interface ip remove PortChannel10 192.0.2.1/31
     sudo config interface ip remove PortChannel10 2001:db8:1::1/127

     sudo config portchannel member add PortChannel10 <child4>
     sudo config interface ip add PortChannel10 192.0.2.1/31
     sudo config interface ip add PortChannel10 2001:db8:1::1/127
     ping -I PortChannel10 192.0.2.0 -c 10
     ping6 -I PortChannel10 2001:db8:1:: -c 10
     show ip bgp summary
     show bgp ipv6 summary
     show interfaces portchannel
     redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|PortChannel10|*"
     ```

     Move the ARISTA peer link into `Port-Channel10` for each child in sequence. Keep peer addresses `192.0.2.0/31` and `2001:db8:1::/127` unchanged. `<child4>` is final.

   - T1 routed:

     ```text
     for p in <child1> <child2> <child3> <child4>; do
       sudo config interface ip add $p 192.0.2.1/31
       sudo config interface ip add $p 2001:db8:1::1/127
       ping -I $p 192.0.2.0 -c 10
       ping6 -I $p 2001:db8:1:: -c 10
       show ip bgp summary
       show bgp ipv6 summary
       sudo config interface ip remove $p 192.0.2.1/31
       sudo config interface ip remove $p 2001:db8:1::1/127
     done

     sudo config interface ip add <child4> 192.0.2.1/31
     sudo config interface ip add <child4> 2001:db8:1::1/127
     ping -I <child4> 192.0.2.0 -c 10
     ping6 -I <child4> 2001:db8:1:: -c 10
     ```

     Move the routed ARISTA peer port to each DUT child in sequence and keep `192.0.2.0/31` and `2001:db8:1::/127` unchanged. `<child4>` retains the final IP pair.

   Expected: each child passes IPv4/IPv6 ping and BGP verification before its binding is released. The same DUT/peer IP pair is not active on multiple children simultaneously. `<child4>` is the final active child.

6. Verify interface and routing state after the final `<child4>` configuration:

   ```text
   show ip interface
   show ipv6 interface
   show ip route
   show ipv6 route
   show interfaces status | grep -E "^ +(<child1>|<child2>|<child3>|<child4>) "
   show interfaces portchannel
   show vlan brief
   ```

   Expected: `<child4>` is operational and the final VLAN, PortChannel, or routed IP binding is active. `<child1>`, `<child2>`, and `<child3>` have no stale IP or VLAN/PortChannel member. Peer routes are installed through `<child4>` in the IPv4 and IPv6 routing tables.

7. Repeat the breakout show and CONFIG_DB checks from step 3 after L3 configuration and traffic:

   ```text
   redis-cli -n 4 HMGET "PORT|<child1>" alias lanes index speed
   redis-cli -n 4 HMGET "PORT|<child2>" alias lanes index speed
   redis-cli -n 4 HMGET "PORT|<child3>" alias lanes index speed
   redis-cli -n 4 HMGET "PORT|<child4>" alias lanes index speed
   ```

   Verify that the `4x200G[100G]` mode, child names, aliases, lane split, index, and `speed=200000` remain unchanged.

### Test case # 3 - Breakout 8x100G, L3 Interface Creation After Breakout on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT using sudo config interface breakout <InterfaceName> 8x100G[50G] -f
2. Configure IPv4 and IPv6 addresses on all breakout interfaces.
3. Verify bgp session, L3 Traffic and L3 connectivity by performing ping from DUT on breakout interfaces.
4. Check that all interfaces are operational and routing entries are correctly installed using show ip interface and show ip route

### Test case # 4 - Breakout 1x800G, L3 Interface Creation After Breakout on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT using sudo config interface breakout Ethernet0 1x800G[400G] -f
2. Configure IPv4 and IPv6 addresses on all breakout interfaces.
3. Verify bgp session and L3 connectivity by performing ping from DUT to all peer IPs
4. Check that all interfaces are operational and routing entries are correctly installed using show ip interface and show ip route

### Test case # 5 - Mixed Channelization on Single Port
1. Start with default configuration on the port.
2. Apply first breakout configuration:
        sudo config interface breakout Ethernet0 2x400G[200G] -f
3. Configure IPv4 addresses on resulting interfaces and verify:
        Interfaces come UP
        L3 connectivity (ping + BGP if applicable)
4. Without reboot, reconfigure the same port to a different breakout mode:
        sudo config interface breakout Ethernet0 4x200G[100G] -f
5. Verify:
        New interfaces are created correctly
        Interfaces are operational (UP)
        L3 connectivity is restored after reconfiguration
6. Again reconfigure to another mode:
        sudo config interface breakout Ethernet0 8x100G[50G] -f
7. Verify the interafce is up and L3 connectivity.
8. Revert back to original mode:
        sudo config interface breakout Ethernet0 1x800G[400G] -f

### Test case # 6 - Breakout interface flap with L3 configuration (2x400G) for IPv4 and IPv6
1. Apply breakout configuration on DUT using sudo config interface breakout Ethernet0 2x400G[200G] -f
2. Configure IPv4 addresses on breakout interfaces and establish L3 connectivity with peers
3. Shutdown and bring up one breakout interface using config interface shutdown/startup
4. Verify that interface comes back UP and L3 connectivity (ping) and L3 traffic is restored successfully

### Test case # 7 - Breakout interface flap with L3 configuration (4x200G) for IPv4 and IPv6
1. Apply breakout configuration on DUT using sudo config interface breakout Ethernet0 4x200G[100G] -f
2. Configure IPv4 addresses on breakout interfaces (Ethernet1 and Ethernet4) and establish L3 connectivity with peers
3. Shutdown and bring up one breakout interface using config interface shutdown/startup
4. Verify that interface comes back UP and L3 connectivity (ping) and L3 traffic is restored successfully

### Test case # 8 - Breakout interface flap with L3 configuration (8x100G) on Random Interface for IPv4 and IPv6
1. Apply breakout configuration on DUT using sudo config interface breakout Ethernet0 8x100G[50G] -f
2. Configure IPv4 and IPv6 addresses on breakout interfaces and establish L3 connectivity with peers
3. Shutdown and bring up one breakout interface using config interface shutdown/startup
4. Verify that interface comes back UP and L3 connectivity (ping) and L3 traffic is restored successfully

### Test case # 9 - Breakout Interface Flap with L3 Configuration (1x800G) on Random Interface for IPv4 and IPv6
1. Apply breakout configuration on DUT using sudo config interface breakout Ethernet0 1x800G[400G] -f
2. Configure IPv4 and IPv6 address on the interface and establish L3 connectivity with peer
3. Shutdown and bring up the interface using config interface shutdown/startup
4. Verify that interface comes back UP and L3 connectivity (ping) and L3 traffic is restored successfully

### Test case # 10 - MTU change on breakout interface on Random Interface for IPv4 and IPv6
1. Apply breakout configuration on DUT using sudo config interface breakout Ethernet0 2x400G[200G] -f
2. Configure IPv4 and IPv6 addresses on breakout interfaces
3. Change MTU on one breakout interface using config interface mtu <InterfaceName> 9100
4. Verify MTU update using show interface status and validate traffic forwarding with large packet size.
      For IPv4:
         ping <IPv4-peer> -s 8972 -M do
      For IPv6:
         ping6 <IPv6-peer> -s 8972

### Test Case # 11 - LLDP neighbors, advertised port ID and description, flap, lldp and orchagent restart on breakout children (T0 VLAN/PortChannel and T1 routed)
This case checks the LLDP behavior that changes with a breakout: one neighbor for each child (not one for the parent), the data that the DUT advertises for a child (the chassis ID, the system description, the port ID = the `alias` of the child and the port description = the `description` of the child in `PORT|<child>`), the neighbor data that the DUT learns, and the recovery after the flap of a child, the restart of `lldp` and the restart of `orchagent`. `tests/lldp/test_lldp.py` (topology `t0`, `t1`, `t2`, `m0`, `mx`, `m1`, `device_type('vs')`) does `test_lldp` (the neighbor name and port against `DEVICE_NEIGHBOR` of the config), `test_lldp_neighbor` (the data that the neighbor receives from the DUT) and `test_lldp_neighbor_post_orchagent_reboot` (the same after `orchagent` is killed or `swss` is restarted, with the number of entries equal to the number before). A child has an LLDP neighbor only if its fanout port is connected to a device that sends LLDP. `$IF` is `Vlan100`, `PortChannel10` or `Ethernet0`.
1. Baseline in the original mode `1x800G[400G]`:

   ```text
   show lldp table | tee /tmp/lldp_before.txt
   docker exec lldp lldpctl -f json > /tmp/lldpctl_before.json
   redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sort | tee /tmp/lldp_keys_before.txt
   redis-cli -n 4 HGET "PORT|Ethernet0" alias
   redis-cli -n 4 HGET "PORT|Ethernet0" description
   docker exec lldp lldpcli show chassis
   docker exec lldp supervisorctl status
   docker exec lldp lldpcli show running-configuration | head -30
   ```

   On the fanout (or the neighbor): `show lldp table` (or `show lldp neighbors` on EOS) and note the neighbor of the parent port. `ls /var/core` (no core file).
2. Apply the breakout on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); `show interfaces breakout current-mode Ethernet0`; `show interfaces status`.
3. Configure the variant:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`.
4. One neighbor for each child (wait 90 s after the links are up; the LLDP interval is 30 s):

   ```text
   show lldp table
   redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sort | diff /tmp/lldp_keys_before.txt -
   for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do echo "== $p"; show lldp neighbors $p; done
   ```

   The key `LLDP_ENTRY_TABLE:Ethernet0` (parent) is now the first child, and `Ethernet2`, `Ethernet4`, `Ethernet6` have their own entries if their fanout ports send LLDP; the `diff` shows only the added keys.
5. Neighbor data on each child (`test_lldp`): `docker exec lldp lldpctl -f json`; for each child `docker exec lldp lldpcli show neighbors ports <child> details` and `redis-cli -n 0 HGETALL "LLDP_ENTRY_TABLE:<child>" | paste - -`; the neighbor name `lldp_rem_sys_name` is the `name` in `DEVICE_NEIGHBOR|<child>` (`redis-cli -n 4 HGETALL "DEVICE_NEIGHBOR|<child>"` or `show lldp table`), the remote port `lldp_rem_port_id` is the `port` of `DEVICE_NEIGHBOR` for a physical peer (on a virtual switch the remote port description `lldp_rem_port_desc` is used); `lldp_rem_chassis_id`, `lldp_rem_sys_desc`, `lldp_rem_man_addr`, `lldp_rem_sys_cap_supported` and `lldp_rem_sys_cap_enabled` are the same in the database and in `lldpctl`.
6. Data that the neighbor receives from the DUT (`test_lldp_neighbor`):
   - DUT side: `ip link show eth0` (the MAC is the chassis ID of the DUT); `docker exec -i lldp lldpcli show chassis | grep SysDescr`; for each child `redis-cli -n 4 HGET "PORT|<child>" alias` (the port ID) and `redis-cli -n 4 HGET "PORT|<child>" description` (the port description).
   - Neighbor side (fanout or EOS or SONiC peer): `show lldp neighbors` / `lldpctl` / `show lldp table`; the chassis ID is the MAC of the DUT, the system description is the SysDescr, the port ID is the alias of the child and the port description is the description of the child; each child shows its own alias and description (not the one of the parent).
   - Change the description: `sudo config interface description Ethernet0 breakout-child-0`; wait 60 s; the neighbor shows `breakout-child-0` as the port description of `Ethernet0` and the siblings keep their descriptions; set the original description again.
7. Flap a child with the neighbors present: `sudo config interface shutdown Ethernet0`, wait 20 s; `redis-cli -n 0 EXISTS "LLDP_ENTRY_TABLE:Ethernet0"` (`0`); `show lldp table` has no `Ethernet0`, while `Ethernet2`, `Ethernet4` and `Ethernet6` keep their entries; `sudo config interface startup Ethernet0`, wait 90 s; the entry for `Ethernet0` is back with the same fields as in step 5 (`redis-cli -n 0 HGETALL "LLDP_ENTRY_TABLE:Ethernet0"`), and `ping -c 5 <PEER_IP>` works (`192.168.100.2` for T0 VLAN and `192.0.2.0` for the others).
8. Restart the `lldp` service: `sudo systemctl restart lldp`; wait 60 s; `sudo systemctl status lldp | grep "active (running)"`; `docker exec lldp supervisorctl status` (`lldpd`, `lldp-syncd` and `lldpmgrd` are `RUNNING`); `show lldp table` and `redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sort` are the same as in step 4; the children stay `up` and `lldpd` learns the children again (`docker exec lldp lldpcli show running-configuration | head -30`, no change of the interface pattern).
9. Restart `orchagent` (`restart_orchagent` of `test_lldp_neighbor_post_orchagent_reboot`): `sudo config feature autorestart swss disabled`; `docker exec swss supervisorctl pid orchagent` (`<PID>`); `docker exec swss kill -9 <PID>`; `docker exec swss supervisorctl start orchagent`; `show lldp table | grep -c Ethernet` equals the number of step 4 within 300 s; wait 30 s; `sudo config feature autorestart swss enabled`; `show interfaces breakout current-mode Ethernet0` (`4x200G[100G]`); `show interfaces status` (the four children `up`); the neighbor data of step 6 are the same. For a VOQ chassis use `sudo systemctl reset-failed; sudo systemctl restart swss` and wait 600 s until `show system-health summary` is OK.
10. Change the mode with the neighbors present: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `sudo config interface startup Ethernet0` (and `Ethernet4`); wait 90 s; `redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sort` has no key for `Ethernet2` and `Ethernet6` (no stale entry), `show lldp table` has the same ports as the database; `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`; `sudo config interface startup Ethernet0` (repeat for the other children); wait 90 s; the keys of step 4 are back; re-apply the variant of step 3 if it was removed.
11. Restore the original mode: remove the variant (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config interface startup Ethernet0`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y`; wait 90 s; `redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sort | diff /tmp/lldp_keys_before.txt -` (no output); `show lldp table | diff /tmp/lldp_before.txt -` (the age column can differ); `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.
12. Run the repository tests in the original mode (before step 2) and in the breakout state (after step 3): `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c lldp/test_lldp.py` (virtual switch only); the result is the same; `rm -f /tmp/lldp_*.txt /tmp/lldpctl_before.json`.

**Expected:** Step 4: one `LLDP_ENTRY_TABLE` key and one `show lldp table` line for each child that has a neighbor, and no entry for a child that has no neighbor. Step 5: the neighbor name, port, chassis ID, system description and capabilities are the same in the database and in `lldpctl`, and the neighbor name and port match `DEVICE_NEIGHBOR`. Step 6: the neighbor receives the chassis ID, the system description, the alias as the port ID and the description of that child; a changed description is visible on the neighbor within 60 s and only for that child. Step 7: only the entry of the flapped child is removed and it returns with the same data; the siblings are not affected. Steps 8 and 9: the entries return, the number of LLDP neighbors is the number before the restart and the breakout mode is not changed. Step 10: no entry for a removed child. Step 11: the keys and the table are the same as in step 1, and the mode is `1x800G[400G]`.

Run steps 1 to 12 once per variant (T0 VLAN, T0 PortChannel, T1 routed). `test_lldp.py` is `device_type('vs')` (the optional run is on a virtual switch only), so on a physical DUT the manual steps 4 to 10 are the check. The LLDP field names, the `lldp_rem_port_id` content, `lldpmgrd` in `supervisorctl status`, the VOQ restart and the alias of the children depend on the image and on the platform. A child that has no LLDP peer on the fanout has no entry; the fanout wiring must be checked first. Steps 9 and 10 restart `orchagent` and change the port mode; run them on a lab DUT. On a multi-ASIC DUT use `docker exec lldp<N>`, `sudo config interface -n <asic> ...` and the namespace for `redis-cli`.

### Test Case # 12 - LLDP_ENTRY_TABLE keys and content against `show lldp table` and `lldpctl` after breakout, flap, restart and reboot (T0 and T1)
This case checks the `lldp-syncd` data (`LLDP_ENTRY_TABLE` in APPL_DB, DB `0`) against `show lldp table` and `docker exec lldp /usr/sbin/lldpctl -f json` for the children. `tests/lldp/test_lldp_syncd.py` (topology `any`) has five tests: `test_lldp_entry_table_content` (the three views and every field), `test_lldp_entry_table_after_syncd_orchagent` (restart of `swss`), `test_lldp_entry_table_after_flap` (shutdown and startup of every interface except `eth0`), `test_lldp_entry_table_after_lldp_restart` and `test_lldp_entry_table_after_reboot` (cold reboot, keys within 90 s). It ignores `Ethernet-BP` and `Ethernet-IB` ports. This case runs the same checks with a breakout parent, where the interface list is `Ethernet0`, `Ethernet2`, `Ethernet4`, `Ethernet6` and `eth0`.
1. Baseline in the original mode `1x800G[400G]` (the helper script is the same for every check and is called `/tmp/lldp_views.sh`; it writes the three sorted interface lists):

   ```text
   cat > /tmp/lldp_views.sh <<'EOF'
   redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sed 's/LLDP_ENTRY_TABLE://' | sort > /tmp/lldp_db.txt
   show lldp table | tail -n +4 | head -n -2 | awk '{print $1}' | sort > /tmp/lldp_show.txt
   docker exec lldp /usr/sbin/lldpctl -f json | python3 -c 'import sys,json; d=json.load(sys.stdin)["lldp"]["interface"]; l=d if isinstance(d,list) else [d]; print("\n".join(sorted(k for i in l for k in i)))' > /tmp/lldp_ctl.txt
   diff /tmp/lldp_db.txt /tmp/lldp_show.txt && echo "OK db=show"
   diff /tmp/lldp_db.txt /tmp/lldp_ctl.txt && echo "OK db=lldpctl"
   EOF
   chmod +x /tmp/lldp_views.sh; /tmp/lldp_views.sh; cp /tmp/lldp_db.txt /tmp/lldp_db_before.txt
   ```

   `show interfaces breakout current-mode Ethernet0` is `1x800G[400G]`. `ls /var/core`.
2. Apply the breakout on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); wait 90 s.
3. Configure the variant: T0 VLAN (`SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; T0 PortChannel (`SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; T1 routed (`SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`.
4. Keys and content (`test_lldp_entry_table_content`): `/tmp/lldp_views.sh` prints `OK db=show` and `OK db=lldpctl`; `diff /tmp/lldp_db_before.txt /tmp/lldp_db.txt` shows only the added children; then for each child:

   ```text
   for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do
     echo "== $p"
     redis-cli -n 0 HGETALL "LLDP_ENTRY_TABLE:$p" | paste - -
     docker exec lldp /usr/sbin/lldpctl -f json show neighbors ports $p
   done
   ```

   For each child `lldp_rem_chassis_id` is the chassis ID, `lldp_rem_port_id` is the port ID, `lldp_rem_sys_name` is the chassis name, `lldp_rem_sys_desc` and `lldp_rem_port_desc` are the descriptions, `lldp_rem_man_addr` is the management address (a comma separated list for several addresses), and `lldp_rem_sys_cap_supported` and `lldp_rem_sys_cap_enabled` are `28 00` or `20 00` (a router or a bridge and router) as in the `lldpctl` capability list.
5. Flap every child (`test_lldp_entry_table_after_flap`): `for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do sudo config interface shutdown $p; sudo config interface startup $p; sleep 60; redis-cli -n 0 EXISTS "LLDP_ENTRY_TABLE:$p"; done` (each `EXISTS` is `1` within 60 s, the test waits up to 60 s with a 2 s interval and 10 s delay); `/tmp/lldp_views.sh` (`OK` for both); the content of step 4 is the same for the child that flapped; on a multi-ASIC DUT use `sudo config interface -n <asic> shutdown <child>`.
6. Restart of `lldp` (`test_lldp_entry_table_after_lldp_restart`): `sudo systemctl restart lldp`; wait 60 s; `show lldp table` has output; `sudo systemctl status lldp | grep "active (running)"`; `/tmp/lldp_views.sh` (`OK` for both); the key list is the same as before the restart: `diff /tmp/lldp_db.txt <(redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sed 's/LLDP_ENTRY_TABLE://' | sort)`.
7. Restart of `swss` (`test_lldp_entry_table_after_syncd_orchagent`; disruptive: `orchagent` and `syncd` restart): `/tmp/lldp_views.sh` (`OK`); `sudo systemctl reset-failed`; `sudo systemctl restart swss`; wait up to 600 s until `show system-health summary` is OK or `docker ps --format '{{.Names}} {{.Status}}' | grep -E "swss|syncd|lldp|database"` is `Up`; `sudo config interface startup Ethernet0` (and the other children if down); wait up to 300 s until every key of `/tmp/lldp_db.txt` has an entry again (`redis-cli -n 0 EXISTS "LLDP_ENTRY_TABLE:<child>"` is `1`); `/tmp/lldp_views.sh`; the fields of step 4 are the same; `show interfaces breakout current-mode Ethernet0` (`4x200G[100G]`).
8. Cold reboot (`test_lldp_entry_table_after_reboot`; disruptive): `sudo config save -y`; `sudo reboot`; wait until SSH is available and `show system-health summary` is OK; `show interfaces breakout current-mode Ethernet0` (`4x200G[100G]`, kept from the saved file); `sudo config interface startup Ethernet0` (and the other children if down); wait up to 90 s plus 30 s until `/tmp/lldp_views.sh` prints `OK` for both; `diff /tmp/lldp_db.txt <(redis-cli -n 0 KEYS "LLDP_ENTRY_TABLE:*" | sed 's/LLDP_ENTRY_TABLE://' | sort)` (no output); the content of step 4 is the same.
9. Stale entries after the change of the mode: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `sudo config interface startup Ethernet0` (and `Ethernet4`); wait 90 s; `/tmp/lldp_views.sh` (`OK` for both); `grep -E "^Ethernet(2|6)$" /tmp/lldp_db.txt /tmp/lldp_show.txt /tmp/lldp_ctl.txt` (no line); `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`; `sudo config interface startup Ethernet0` (repeat for the others); wait 90 s; `/tmp/lldp_views.sh`; the keys of step 4 are back.
10. Restore: remove the variant (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config interface startup Ethernet0`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y`; wait 90 s; `/tmp/lldp_views.sh` (`OK` for both); `diff /tmp/lldp_db_before.txt /tmp/lldp_db.txt` (no output); `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.
11. Run the repository test in the original mode (before step 2) and with the breakout (after step 3): `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c lldp/test_lldp_syncd.py`; the result is the same; `rm -f /tmp/lldp_*.txt /tmp/lldp_views.sh`.

**Expected:** Steps 4 to 9: the three interface lists are identical (`OK db=show` and `OK db=lldpctl`) and every field of `LLDP_ENTRY_TABLE` equals the `lldpctl` value (chassis ID, port ID, system name, system and port description, management address, capabilities). Step 5: every flapped child has its entry again within 60 s. Steps 6 to 8: the key list after the restart of `lldp`, the restart of `swss` and the reboot is the same as before, and the breakout mode is kept. Step 9: no `Ethernet2` or `Ethernet6` in any view after the change to `2x400G[200G]`. Step 10: the key list is the same as in step 1 and the mode is `1x800G[400G]`.


### Test Case # 13 - SNMP interface, FDB, LLDP, queue and PFC objects of breakout children (T0 VLAN/PortChannel and T1 routed)
This is the one SNMP case for the breakout. It checks the SNMP objects that depend on the ports: the interface table (`ifIndex`, `ifName` = the alias of the port, `ifType`, `ifMtu`, `ifSpeed`, `ifHighSpeed`, `ifAdminStatus`, `ifOperStatus`, `ifAlias`, the counters), the bridge FDB (`dot1qTpFdbPort`, `dot1dTpFdbPort`, `dot1dBasePortIfIndex`), the LLDP tables (`lldpLocPortTable`, `lldpRemTable`), the queue counters and the PFC counters (`cpfc*`). `test_snmp_interfaces.py` (`test_snmp_interfaces`, `test_snmp_interfaces_mibs`, `test_snmp_interfaces_error_discard`, `device_type('vs')`) compares the MIBs with `PORT` of CONFIG_DB, `PORT_TABLE` of APPL_DB and the counters of COUNTERS_DB; `test_snmp_fdb.py` (topology `t0`, `m0`, `mx`, `m1`) sends frames from PTF and compares the FDB MIBs; `test_snmp_lldp.py` checks `lldpLocPortTable` for all ports and `lldpRemTable`; `test_snmp_queue.py` checks that every port with `QUEUE|<port>|<n>` has the queue OIDs and that their number is the number of `UC` queues of `show queue counters`; `test_snmp_queue_counters.py` checks the number of queue counters of a port; `test_snmp_pfc_counters.py` requires `cpfcIfRequests`, `cpfcIfIndications`, `requestsPerPriority` and `indicationsPerPriority` for every `Ethernet` port. Variables: `COMM` is the read-only community of the DUT (`snmp_rocommunity` of the credentials), `DUT_IP` is the management IP, `<ALIAS>` is `alias` of `PORT|<child>`; `$IF` is `Vlan100`, `PortChannel10` or `Ethernet0`.
1. Baseline in the original mode `1x800G[400G]`:

   ```text
   export COMM=<COMMUNITY> DUT_IP=<DUT_IP>
   sudo docker exec snmp supervisorctl status
   for o in 2.2.1.1 2.2.1.2 31.1.1.1.1 31.1.1.1.18 2.2.1.3 2.2.1.4 2.2.1.5 31.1.1.1.15 2.2.1.7 2.2.1.8; do echo "== 1.3.6.1.2.1.$o"; snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.$o; done | tee /tmp/snmp_if_before.txt
   sonic-db-cli CONFIG_DB HMGET "PORT|Ethernet0" alias speed admin_status description mtu index | tee /tmp/snmp_port0_before.txt
   snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.17.1.4.1.2 | tee /tmp/snmp_baseport_before.txt
   snmpwalk -v2c -c $COMM $DUT_IP 1.0.8802.1.1.2.1.3.7 | tee /tmp/snmp_lldploc_before.txt
   snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.4.1.9.9.813 | tee /tmp/snmp_pfc_before.txt
   ```

   The OIDs are `ifIndex` 2.2.1.1, `ifDescr` 2.2.1.2, `ifName` 31.1.1.1.1, `ifAlias` 31.1.1.1.18, `ifType` 2.2.1.3, `ifMtu` 2.2.1.4, `ifSpeed` 2.2.1.5, `ifHighSpeed` 31.1.1.1.15, `ifAdminStatus` 2.2.1.7 and `ifOperStatus` 2.2.1.8, all under `1.3.6.1.2.1.`. Note the alias of `Ethernet0` (the old alias of the parent). `snmpd` and `snmp-subagent` are `RUNNING`. `show interfaces breakout current-mode Ethernet0` is `1x800G[400G]`; `ls /var/core`.
2. Apply the breakout on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); `show interfaces breakout current-mode Ethernet0`; `show interfaces status`; wait 90 s for the SNMP agent to refresh the interface list.
3. Configure the variant:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; peer `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; peer `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; peer `192.0.2.0`.
   Check `ping -c 5 <PEER_IP>`.
4. Interface MIBs of every child (`test_snmp_interfaces`, `test_snmp_interfaces_mibs`): repeat the `snmpwalk` loop of step 1 into `/tmp/snmp_if_after.txt`, and read the expected values from the DUT:

   ```text
   for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do
     echo "== $p"
     sonic-db-cli CONFIG_DB HMGET "PORT|$p" alias speed admin_status description mtu
     sonic-db-cli APPL_DB HGET "PORT_TABLE:$p" oper_status
     ip link show $p | grep -o "mtu [0-9]*"
   done
   ```

   For each child: `ifName` = `<ALIAS>` of the child (`snmpwalk ... 31.1.1.1.1 | grep "<ALIAS>"`); `ifType` = `6`; `ifMtu` = the MTU of `ip link show`; `ifSpeed` = `speed` x 1000000 (for `100000` Mbps it is above 4294967295, so `ifSpeed` = `4294967295`) and `ifHighSpeed` = `speed` (`100000`); `ifAdminStatus` = `1` for `up` and `2` for `down`; `ifOperStatus` = `1` for `up` and `2` for `down`; `ifAlias` = `description`; the four `ifIndex` values are different (`snmpwalk ... 2.2.1.1 | sort | uniq -d` gives no line). The PortChannel (T0 PortChannel) has `ifType` `161` and its own `ifIndex`. Check that the old alias of the parent does not exist twice: `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.31.1.1.1.1 | grep -c "<OLD_ALIAS>"` is at most `1`, and no line for an alias that is not in `PORT`.
5. Counters of a child (`test_snmp_interfaces_error_discard`, T1; for T0 only the port counters): the test sets the counters in COUNTERS_DB, so stop the polling first: `sudo counterpoll port disable`; `rm -rf /tmp/cache/intfstat /tmp/cache/portstat`; `OID=$(redis-cli -n 2 HGET COUNTERS_PORT_NAME_MAP Ethernet0)`; `for c in SAI_PORT_STAT_IF_IN_ERRORS SAI_PORT_STAT_IF_IN_DISCARDS SAI_PORT_STAT_IF_OUT_ERRORS SAI_PORT_STAT_IF_OUT_DISCARDS; do redis-cli -n 2 HSET COUNTERS:$OID $c 5; done`; T1 only: `RIF=$(redis-cli -n 2 HGET COUNTERS_RIF_NAME_MAP Ethernet0)`; `redis-cli -n 2 HSET COUNTERS:$RIF SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS 5`; `redis-cli -n 2 HSET COUNTERS:$RIF SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS 5`; `show interfaces counters -i Ethernet0` (`RX_ERR`, `TX_ERR`, `RX_DRP`, `TX_DRP` are `5`); wait 30 s; `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.2.2.1.14` (`ifInErrors`), `.20` (`ifOutErrors`), `.13` (`ifInDiscards`), `.19` (`ifOutDiscards`) of the `Ethernet0` index. Also the traffic counters: `ping -f -c 2000 <PEER_IP>`; the `ifHCInOctets` (`1.3.6.1.2.1.31.1.1.1.6`) and `ifHCOutOctets` (`1.3.6.1.2.1.31.1.1.1.10`) of the child increase and the ones of the siblings do not. Restore: `sudo counterpoll port enable`; `redis-cli -n 2 HDEL COUNTERS:$OID SAI_PORT_STAT_IF_IN_ERRORS SAI_PORT_STAT_IF_IN_DISCARDS SAI_PORT_STAT_IF_OUT_ERRORS SAI_PORT_STAT_IF_OUT_DISCARDS` (the counters are written again by the polling).
6. FDB (`test_snmp_fdb`, T0 VLAN and T0 PortChannel; for T1 skip): from the peer `ping -c 5 192.168.100.1` (T0 VLAN) or send a frame from the PTF/peer behind `PortChannel10`; wait 30 s; `show mac | grep -E "Ethernet0|PortChannel10"`; `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.17.7.1.2.2.1.2` (`dot1qTpFdbPort`, the MAC of the peer in VLAN `100` with a bridge port number); `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.17.4.3.1.2` (`dot1dTpFdbPort`); `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.2.1.17.1.4.1.2` (`dot1dBasePortIfIndex`): the bridge port number of the MAC maps to the `ifIndex` of `Ethernet0` (VLAN member) or of `PortChannel10`; `sudo sonic-clear fdb all`; wait 15 s; the MAC is gone from the three tables. The `test_snmp_fdb` needs LACP between the DUT and the PTF for the PortChannel part, so the fanout must pass LACP (see the note).
7. LLDP (`test_snmp_lldp`): `snmpwalk -v2c -c $COMM $DUT_IP 1.0.8802.1.1.2.1.3.7` (`lldpLocPortTable`: `lldpLocPortIdSubtype`, `lldpLocPortId` and `lldpLocPortDesc` for every child, the port ID is the alias of the child); `snmpwalk -v2c -c $COMM $DUT_IP 1.0.8802.1.1.2.1.4.1` (`lldpRemTable`: the neighbor of each child that has a peer on the fanout; the remote port and system name are the same as in `show lldp table`); `diff /tmp/snmp_lldploc_before.txt <(snmpwalk -v2c -c $COMM $DUT_IP 1.0.8802.1.1.2.1.3.7)` (only the added children).
8. Queues (`test_snmp_queues`, `test_snmp_queue_counters`): `redis-cli -n 4 KEYS "QUEUE|Ethernet0|*"` (the queue indexes; if the children have no queue, `sudo config qos reload` and `sudo config save -y` - image dependent); `show queue counters Ethernet0 | grep -c UC` (the number of unicast queues); `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.4.1.9.9.580.1.5.5.1.4.<IFINDEX_OF_Ethernet0>` (the queue counters of the child: the number of the egress queue indexes is the number of `UC` queues, a queue index `n` of the table is `n + 1` in the OID); repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`; the number is the same as for the parent in step 1.
9. PFC: `snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.4.1.9.9.813` (`cpfcIfRequests`, `cpfcIfIndications`, `requestsPerPriority` and `indicationsPerPriority` for every child `ifIndex`); `diff /tmp/snmp_pfc_before.txt <(snmpwalk -v2c -c $COMM $DUT_IP 1.3.6.1.4.1.9.9.813)` (only the added children).
10. Flap a child: `sudo config interface shutdown Ethernet0`, wait 30 s; `ifAdminStatus` and `ifOperStatus` of `Ethernet0` are `2` (`snmpwalk ... 2.2.1.7`, `2.2.1.8`), the siblings stay `1`; the `ifIndex` is the same as before; `sudo config interface startup Ethernet0`, wait 60 s; both are `1` again; `ping -c 5 <PEER_IP>` works.
11. Restart the SNMP service: `sudo systemctl restart snmp`; wait 60 s; `sudo docker exec snmp supervisorctl status` (`snmpd` and `snmp-subagent` `RUNNING`); repeat the loop of step 1 into `/tmp/snmp_if_after2.txt`; `diff /tmp/snmp_if_after.txt /tmp/snmp_if_after2.txt` (no difference except the counters and the uptime; the `ifIndex` of the children does not change).
12. Change the mode with the objects present: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `sudo config interface startup Ethernet0` (and `Ethernet4`); wait 90 s; `snmpwalk ... 31.1.1.1.1` has no alias of `Ethernet2` and `Ethernet6`; `ifHighSpeed` of `Ethernet0` and `Ethernet4` is `200000`; `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`; `sudo config interface startup Ethernet0` (repeat for the others); wait 90 s; the table of step 4 is back and `ifHighSpeed` is `100000`.
13. Run the repository tests in the original mode (before step 2) and in the breakout state (after step 3): `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c snmp/test_snmp_interfaces.py`, and the same with `-c snmp/test_snmp_fdb.py`, `-c snmp/test_snmp_lldp.py`, `-c snmp/test_snmp_queue.py`, `-c snmp/test_snmp_queue_counters.py` and `-c snmp/test_snmp_pfc_counters.py`; the results are the same as in the original mode.
14. Restore the original mode: remove the variant (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config interface startup Ethernet0`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; wait 90 s; the loop of step 1 into `/tmp/snmp_if_end.txt`; `diff /tmp/snmp_if_before.txt /tmp/snmp_if_end.txt` (only counters and uptime differ); no `Ethernet2`, `Ethernet4` or `Ethernet6` alias in `ifName`; `sudo counterpoll port enable`; `rm -f /tmp/snmp_*.txt`.

**Expected:** Step 4: every child has its own SNMP interface entry with `ifName` = alias, `ifType` 6, the MTU of the port, `ifHighSpeed` = the speed in Mbps (`100000`) with `ifSpeed` capped at `4294967295`, the admin and oper status of the DB, `ifAlias` = description and a unique `ifIndex`; the old parent alias is not duplicated. Step 5: `ifInErrors`, `ifOutErrors` (and for T1 `ifInDiscards` and `ifOutDiscards`) follow the counters of the child, and only the child counters increase with the traffic. Step 6: the MAC of the peer is in `dot1qTpFdbPort` and `dot1dTpFdbPort` with the bridge port that maps to the `ifIndex` of the child (or the PortChannel), and it is removed by `sonic-clear fdb all`. Step 7: `lldpLocPortTable` has one entry for each child and `lldpRemTable` the neighbor of each child that has a peer. Step 8: the queue OIDs of a child have the number of `UC` queues. Step 9: the four PFC objects exist for each child. Step 10: only the flapped child changes its status and `ifIndex` is not changed. Step 11: the table is the same after the restart of `snmp`. Step 12: no entry for a removed child and `ifHighSpeed` is `200000` for the two 200G children. Step 14: the table is the same as in step 1 and the mode is `1x800G[400G]`.

### Test case # 14 - gNMI telemetry verification for breakout interfaces on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv6 and IPv4 to L3 interfaces
2. Enable gNMI telemetry on DUT
3. Subscribe to interface state paths (e.g., interface status, counters)
4. Verify breakout interfaces are reported correctly with accurate operational data

### Test case # 15 - Breakout Interface Traffic Forwarding After Reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 16 - Breakout interface traffic forwarding after warm-reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using warm-reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 17 - Breakout interface traffic forwarding after fast-reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using fast-reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 18 - Breakout interface traffic forwarding after soft-reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using soft-reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 19 - Interface counter validation on breakout ports
1. Apply breakout configuration and configure L3 interfaces
2. Send traffic between DUT and peers
3. Check interface counters using show interface counters
4. Verify packet counters increment correctly on respective breakout interfaces

### Test Case # 20 - BGP link flap on breakout child
1. Establish IPv4 or IPv6 BGP on an individual breakout child.
2. Shutdown the child.
3. Verify neighbor/session withdrawal and link down state.
4. Startup the child and verify session re-establishment.

### Test Case # 21 - IPv4/IPv6 BGP over breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and ping the peer. `<PORT>` is the tested child:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`, `sudo config interface ip add Vlan100 2001:db8:100::1/64`; `ping -c 5 192.168.100.2`, `ping6 -c 5 2001:db8:100::2`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`, `<PEER_IP6>` = `2001:db8:100::2`, `<DUT_IP>` = `192.168.100.1`, `<DUT_IP6>` = `2001:db8:100::1`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`, `sudo config interface ip add PortChannel10 2001:db8:1::1/127`; `ping -c 5 192.0.2.0`, `ping6 -c 5 2001:db8:1::`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`, `<PEER_IP6>` = `2001:db8:1::`, `<DUT_IP>` = `192.0.2.1`, `<DUT_IP6>` = `2001:db8:1::1`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`, `sudo config interface ip add Ethernet0 2001:db8:1::1/127`; `ping -c 5 192.0.2.0`, `ping6 -c 5 2001:db8:1::`. `<PORT>` = `Ethernet0`, same peer and DUT addresses as the PortChannel run.
3. Configure the BGP neighbors on the DUT and on the peer (ARISTA):
   - DUT (`vtysh`): `vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "neighbor <PEER_IP> remote-as <PEER_ASN>" -c "neighbor <PEER_IP6> remote-as <PEER_ASN>" -c "address-family ipv6 unicast" -c "neighbor <PEER_IP6> activate"` (or the ConfigDB `BGP_NEIGHBOR` table).
   - Peer (EOS): `router bgp <PEER_ASN>`, `neighbor <DUT_IP> remote-as <DUT_ASN>`, `neighbor <DUT_IP6> remote-as <DUT_ASN>`, `address-family ipv6`, `neighbor <DUT_IP6> activate`.
4. Verify the sessions: `show ip bgp summary`; `show bgp ipv6 summary`; `show ip route bgp`; `show ipv6 route bgp`.
5. Advertise 10 prefixes from the peer and ping into them. On the peer (EOS) create `Loopback1` to `Loopback10` with `ip address 10.60.<n>.1/24` and `ipv6 address 2001:db8:60:<n>::1/64` and announce them with `router bgp <PEER_ASN>`, `network 10.60.<n>.0/24`, `address-family ipv6`, `network 2001:db8:60:<n>::/64`. On the DUT: `show ip route bgp`, `show ipv6 route bgp`, `ping -c 5 10.60.1.1`, `ping6 -c 5 2001:db8:60:1::1`, `show interfaces counters -i <PORT>`.
6. Flap the tested child: `sudo config interface shutdown <PORT>`; wait 10 s; `show ip bgp summary`; `show bgp ipv6 summary`; `show ip route bgp`; `sudo config interface startup <PORT>`; wait 60 s; `show ip bgp summary`; `show bgp ipv6 summary`; `ping -c 5 10.60.1.1`.
7. Cleanup: remove the BGP neighbors (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor <PEER_IP> remote-as <PEER_ASN>" -c "no neighbor <PEER_IP6> remote-as <PEER_ASN>"`) and the peer loopbacks; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** Step 4: the IPv4 and IPv6 sessions are `Established`. Step 5: 10 IPv4 and 10 IPv6 prefixes are received, the next hop interface of the BGP routes is the tested child (`Vlan100`, `PortChannel10` or `Ethernet0`), pings into the prefixes have 0 % loss and the counters of `<PORT>` increment. Step 6: after `shutdown <PORT>` the sessions leave `Established` (`Idle` or `Active`) and the BGP routes are withdrawn; after `startup <PORT>` the sessions return to `Established` with 10 prefixes each and the pings work again. After cleanup the mode is `1x800G[400G]`.

### Test Case # 22 - VLAN access port on individual breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Remove the IP configuration from the child if present: `show ip interface | grep Ethernet0`, `show ipv6 interface | grep Ethernet0`; if listed: `sudo config interface ip remove Ethernet0 192.0.2.1/31`, `sudo config interface ip remove Ethernet0 2001:db8:1::1/127`; verify with `redis-cli -n 4 KEYS "INTERFACE|Ethernet0*"` (empty).
3. Configure the child on the DUT:
   - T0 (access port): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`, `sudo config interface ip add Vlan100 2001:db8:100::1/64`; verify with `show vlan brief` (`Ethernet0` `untagged`) and `redis-cli -n 4 HGETALL "VLAN_MEMBER|Vlan100|Ethernet0"` (`tagging_mode` = `untagged`).
   - T1 (routed port, VLANs are not used on T1): `sudo config interface ip add Ethernet0 192.0.2.1/31`, `sudo config interface ip add Ethernet0 2001:db8:1::1/127`; verify with `show ip interface`.
4. Add the matching configuration to the peer (`<peer child>` is the peer interface connected to `Ethernet0`):
   - T0 (Arista EOS): `vlan 100`, `interface <peer child>`, `switchport mode access`, `switchport access vlan 100`, `interface Vlan100`, `ip address 192.168.100.2/24`, `ipv6 address 2001:db8:100::2/64`.
   - T1 (Arista EOS): `interface <peer child>`, `no switchport`, `ip address 192.0.2.0/31`, `ipv6 address 2001:db8:1::/127`.
5. Send traffic and verify forwarding and MAC learning:
   - `sonic-clear counters`
   - `ping -c 10 <peer IP>` and `ping6 -c 10 <peer IPv6>` (T0 `192.168.100.2` and `2001:db8:100::2`, T1 `192.0.2.0` and `2001:db8:1::`); `ping -c 10 -s 1400 <peer IP>`
   - T0: `show mac` (peer MAC learned on `Ethernet0` in `Vlan100`, type `Dynamic`), `show arp`, `show ndp`
   - T1: `show arp`, `show ndp` (neighbor learned on `Ethernet0`; there is no MAC table for a routed port)
   - `show interfaces counters -i Ethernet0` (only `Ethernet0` increments; `Ethernet2`, `Ethernet4`, `Ethernet6` stay at about zero)
   - MAC aging: `sonic-clear fdb all`, repeat the ping, then `show mac` (T0, the MAC is learned again).
6. Cleanup: T0 `sudo config vlan member del 100 Ethernet0`, `sudo config interface ip remove Vlan100 192.168.100.1/24`, `sudo config interface ip remove Vlan100 2001:db8:100::1/64`, `sudo config vlan del 100`; T1 `sudo config interface ip remove Ethernet0 192.0.2.1/31`, `sudo config interface ip remove Ethernet0 2001:db8:1::1/127`; remove the peer VLAN configuration; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

**Expected:** Step 2: no IP remains on `Ethernet0` before it is added to the VLAN. Step 3: `Ethernet0` is an untagged member of `Vlan100` (T0) or a routed port with one IPv4/IPv6 address (T1). Step 5: IPv4 and IPv6 ping have 0 % loss (including 1400-byte packets); on T0 the peer MAC is learned on `Ethernet0` in `Vlan100` and is learned again after `sonic-clear fdb all`; on T1 ARP/NDP entries point to `Ethernet0`; the counters increment on `Ethernet0` only. After cleanup the mode is `1x800G[400G]` and no `Vlan100` remains.

### Test Case # 23 - VLAN tagged port on individual breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Add the selected breakout child in tagged mode:
   - T0 (tagged VLAN member, no `-u`): `sudo config vlan add 100`, `sudo config vlan member add 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`, `sudo config interface ip add Vlan100 2001:db8:100::1/64`; verify with `show vlan brief` (`Ethernet0` `tagged`) and `redis-cli -n 4 HGETALL "VLAN_MEMBER|Vlan100|Ethernet0"` (`tagging_mode` = `tagged`).
   - T1 (tagged routed sub-interface, image dependent): `sudo config subinterface add Ethernet0.100 100`, `sudo config interface ip add Ethernet0.100 192.0.2.1/31`; verify with `show subinterfaces status` and `show ip interface`.
3. Configure the matching tagged VLAN on the peer (`<peer child>` is the peer interface connected to `Ethernet0`):
   - T0 (Arista EOS): `vlan 100`, `interface <peer child>`, `switchport mode trunk`, `switchport trunk allowed vlan 100`, `interface Vlan100`, `ip address 192.168.100.2/24`, `ipv6 address 2001:db8:100::2/64`.
   - T1 (Arista EOS): `interface <peer child>.100`, `encapsulation dot1q vlan 100`, `ip address 192.0.2.0/31`.
4. Send tagged traffic and verify forwarding:
   - `ping -c 10 <peer IP>` (T0 `192.168.100.2`, T1 `192.0.2.0`) and `ping6 -c 10 2001:db8:100::2` (T0).
   - Capture the tag on the peer (Linux/EOS bash): `sudo tcpdump -e -nn -i <peer child> vlan 100 and icmp` (frames carry VLAN 100).
   - T0 only: `show mac` (peer MAC learned on `Ethernet0` in `Vlan100`).
   - Negative test (Linux peer): `sudo ip link add link <peer child> name <peer child>.200 type vlan id 200`, `sudo ip addr add 192.168.200.2/24 dev <peer child>.200`, `sudo ip link set <peer child>.200 up`, `ping -c 5 -I <peer child>.200 192.168.100.1` fails (VLAN 200 is not configured on the DUT).
   - Counters: `sonic-clear counters`, repeat the ping, `show interfaces counters -i Ethernet0` (only `Ethernet0` increments).
5. Cleanup: T0 `sudo config vlan member del 100 Ethernet0`, `sudo config interface ip remove Vlan100 192.168.100.1/24`, `sudo config interface ip remove Vlan100 2001:db8:100::1/64`, `sudo config vlan del 100`; T1 `sudo config interface ip remove Ethernet0.100 192.0.2.1/31`, `sudo config subinterface del Ethernet0.100`; remove the peer VLAN/sub-interface and `sudo ip link del <peer child>.200`; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

**Expected:** `Ethernet0` is a tagged member of `Vlan100` (T0) or carries the tagged sub-interface `Ethernet0.100` (T1), and the peer is configured with the same VLAN 100. IPv4 and IPv6 ping have 0 % loss, the captured frames carry the 802.1Q tag VLAN 100, the peer MAC is learned on `Ethernet0` in `Vlan100` (T0), and the counters increment on `Ethernet0` only. Tagged frames of VLAN 200 are not forwarded. After cleanup the mode is `1x800G[400G]` and no `Vlan100` or `Ethernet0.100` remains.


### Test Case # 24 - VLAN member removal before breakout (T0 and T1)
1. Breakout the parent port and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`.
2. Add the breakout child to the dependency:
   - T0 (VLAN member): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; verify with `show vlan brief` (`Vlan100` has `Ethernet0` untagged), `redis-cli -n 4 KEYS "VLAN_MEMBER|*"`, `ping -c 5 192.168.100.2`.
   - T1 (VLANs are not used on T1; the equivalent child dependency is the routed IP): `sudo config interface ip add Ethernet0 192.0.2.1/31`; verify with `show ip interface`, `redis-cli -n 4 KEYS "INTERFACE|Ethernet0*"`, `ping -c 5 192.0.2.0`.
3. Attempt the breakout mode change without force: `sudo config interface breakout Ethernet0 '2x400G[200G]' -y`. Verify nothing changed: `show interfaces breakout current-mode Ethernet0` (still `4x200G[100G]`), `show vlan brief` (T0) or `show ip interface` (T1), `show interfaces status`, `ping -c 5 <peer IP>`.
4. Remove the dependency and retry:
   - T0: `sudo config vlan member del 100 Ethernet0`; check `redis-cli -n 4 KEYS "VLAN_MEMBER|*"` (no `Vlan100|Ethernet0`).
   - T1: `sudo config interface ip remove Ethernet0 192.0.2.1/31`; check `redis-cli -n 4 KEYS "INTERFACE|Ethernet0*"` (empty).
   - Retry: `sudo config interface breakout Ethernet0 '2x400G[200G]' -y`.
   - Verify: `show interfaces breakout current-mode Ethernet0`, `show interfaces status | grep -E "Ethernet(0|4) "`.
5. Re-add the recreated child and verify: `sudo config interface startup Ethernet0`, `sudo config interface startup Ethernet4`; T0: `sudo config vlan member add -u 100 Ethernet0`, `show vlan brief`, `ping -c 5 192.168.100.2`; T1: `sudo config interface ip add Ethernet0 192.0.2.1/31`, `ping -c 5 192.0.2.0`.
6. Cleanup: T0 `sudo config vlan member del 100 Ethernet0`, `sudo config interface ip remove Vlan100 192.168.100.1/24`, `sudo config vlan del 100`; T1 `sudo config interface ip remove Ethernet0 192.0.2.1/31`; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

**Expected:** Step 3: the command without `-f` is refused with a dependency message that lists the `VLAN_MEMBER` entry (T0) or the `INTERFACE` IP entry (T1) of `Ethernet0`; the mode stays `4x200G[100G]`, the VLAN membership or IP is unchanged and traffic is not interrupted. Step 4: after the member (or IP) is removed the same command succeeds (`Breakout process got successfully completed`), the mode is `2x400G[200G]`, `Ethernet0` and `Ethernet4` are 400G, `Ethernet2` and `Ethernet6` are gone, `Vlan100` still exists with its IP (T0) and no stale `VLAN_MEMBER` or `INTERFACE` entry of a removed port remains. Step 5: the recreated `Ethernet0` becomes a VLAN member (T0) or gets its IP (T1) and ping is restored. After cleanup the mode is `1x800G[400G]` and no `Vlan100` remains.

### Test Case # 25 - LAG member individual breakout child (T0 and T1)
1. Breakout the parent port and start the children on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Create the PortChannel/LAG on the DUT and on the peer:
   - DUT: `sudo config portchannel add PortChannel10`, `sudo config interface startup PortChannel10`.
   - Peer (ARISTA/EOS, `<peer child>` is the interface connected to `Ethernet2`): `interface <peer child>`, `channel-group 10 mode active`, `interface Port-Channel10`, `no switchport`.
3. Add one breakout child to the LAG on the DUT: `sudo config portchannel member add PortChannel10 Ethernet2`; verify with `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|*"`.
4. Configure the IP on the PortChannel, not on the physical member:
   - DUT: `sudo config interface ip add PortChannel10 192.0.2.1/31`, `sudo config interface ip add PortChannel10 2001:db8:1::1/127`.
   - Peer (EOS): `interface Port-Channel10`, `ip address 192.0.2.0/31`, `ipv6 address 2001:db8:1::/127`.
   - Check that the member has no IP: `show ip interface` and `show ipv6 interface` list `PortChannel10` and do not list `Ethernet2`.
5. Verify the LAG state and traffic forwarding:
   - LAG: `show interfaces portchannel` (`PortChannel10` `LACP(A)(Up)`, `Ethernet2(S)`), `teamdctl PortChannel10 state`, `show interfaces status Ethernet2`.
   - IPv4/IPv6 forwarding: `ping -c 10 192.0.2.0`, `ping6 -c 10 2001:db8:1::`, `ping -c 10 -s 1400 192.0.2.0`; `show arp`, `show ndp`.
   - T1 only (routed forwarding): `sudo config route add prefix 10.50.0.0/24 nexthop 192.0.2.0`, `show ip route 10.50.0.0/24`, `ping -c 10 <host behind peer in 10.50.0.0/24>`.
   - Counters: `sonic-clear counters`, repeat the ping, then `show interfaces counters -i Ethernet2` (only the LAG member increments; `Ethernet0`, `Ethernet4` and `Ethernet6` stay at about zero).
6. LAG state flap: `sudo config interface shutdown Ethernet2`, wait 10 s, `show interfaces portchannel` (`PortChannel10` down), `sudo config interface startup Ethernet2`, wait for LACP, `show interfaces portchannel`, `ping -c 10 192.0.2.0`.
7. Cleanup: T1 `sudo config route del prefix 10.50.0.0/24 nexthop 192.0.2.0`; `sudo config interface ip remove PortChannel10 192.0.2.1/31`; `sudo config interface ip remove PortChannel10 2001:db8:1::1/127`; `sudo config portchannel member del PortChannel10 Ethernet2`; `sudo config portchannel del PortChannel10`; remove the peer `Port-Channel10` and `channel-group 10`; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

**Expected:** `PortChannel10` is `LACP(A)(Up)` with `Ethernet2(S)` and the peer shows the same LAG up. The IP addresses are only on `PortChannel10`; `Ethernet2` has no IP. IPv4 and IPv6 ping have 0 % loss (including 1400-byte packets), ARP and NDP entries point to `PortChannel10`, and on T1 the static route is installed and forwards traffic. Counters increment on `Ethernet2` only. After the member flap the LAG goes down and comes back up with `Ethernet2(S)` and traffic is restored. After cleanup the mode is `1x800G[400G]` and no `PortChannel10` remains.


### Test Case # 26 - LAG member removal before breakout (T0 and T1)
1. Breakout the parent port and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`.
2. Configure two individual breakout children as LAG members (`Ethernet0` and `Ethernet2`; configure the matching PortChannel with the same two links on the peer):
   - Common: `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet0`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface startup PortChannel10`.
   - T0 (PortChannel as VLAN member): `sudo config vlan add 100`, `sudo config vlan member add -u 100 PortChannel10`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`.
   - T1 (L3 PortChannel): `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
   - Verify: `show interfaces portchannel` (`PortChannel10` `LACP(A)(Up)`, `Ethernet0(S)`, `Ethernet2(S)`), `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|*"`.
3. Attempt the breakout mode change without force: `sudo config interface breakout Ethernet0 '2x400G[200G]' -y`. Verify nothing changed: `show interfaces breakout current-mode Ethernet0` (still `4x200G[100G]`), `show interfaces portchannel`, `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|*"`, `show interfaces status`, `ping -c 5 <peer IP>`.
4. Remove the LAG members and retry:
   - `sudo config portchannel member del PortChannel10 Ethernet0`
   - `sudo config portchannel member del PortChannel10 Ethernet2`
   - `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|*"` (no `Ethernet0` or `Ethernet2` entry)
   - `sudo config interface breakout Ethernet0 '2x400G[200G]' -y`
   - Verify: `show interfaces breakout current-mode Ethernet0`, `show interfaces status | grep -E "Ethernet(0|4) "`, `show interfaces portchannel`.
5. Re-add a recreated child to the LAG and verify: `sudo config interface startup Ethernet0`, `sudo config interface startup Ethernet4`, `sudo config portchannel member add PortChannel10 Ethernet0`, `show interfaces portchannel`, `ping -c 5 <peer IP>`.
6. Cleanup: T0 `sudo config vlan member del 100 PortChannel10`, `sudo config interface ip remove Vlan100 192.168.100.1/24`, `sudo config vlan del 100`; T1 `sudo config interface ip remove PortChannel10 192.0.2.1/31`; `sudo config portchannel member del PortChannel10 Ethernet0`; `sudo config portchannel del PortChannel10`; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

**Expected:** Step 3: the command without `-f` is refused with a dependency message that lists the `PORTCHANNEL_MEMBER` entries of `Ethernet0` and `Ethernet2`; the mode stays `4x200G[100G]`, `PortChannel10` stays up with both members `Selected` and traffic is not interrupted. Step 4: after the members are removed the same command succeeds (`Breakout process got successfully completed`), the mode is `2x400G[200G]`, `Ethernet0` and `Ethernet4` are 400G, `Ethernet2` and `Ethernet6` are gone, and `PortChannel10` still exists with no members (oper down). Step 5: the recreated `Ethernet0` joins `PortChannel10`, LACP comes up with `Ethernet0(S)` and ping is restored. After cleanup the mode is `1x800G[400G]` and no `PortChannel10` or `PORTCHANNEL_MEMBER` entry remains.

### Test Case # 27 - ACL binding on individual breakout child (T0 and T1)
1. Apply breakout mode and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`.
2. Configure the tested child and ping the peer. `<ACL_PORT>` is the binding location:
   - T0 VLAN: `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<ACL_PORT>` = `Ethernet0`, `<DUT_IP>` = `192.168.100.1`.
   - T0 PortChannel: `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<ACL_PORT>` = `PortChannel10` (a PortChannel member cannot be bound directly), `<DUT_IP>` = `192.0.2.1`.
   - T1 routed: `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<ACL_PORT>` = `Ethernet0`, `<DUT_IP>` = `192.0.2.1`.
3. Create the ACL table and rules bound to `<ACL_PORT>` only (files below): `sonic-cfggen -j /tmp/bind_acl_table.json --write-to-db`, `sonic-cfggen -j /tmp/bind_acl_rules.json --write-to-db`; verify with `show acl table BK_BIND_ACL` (Ports = `<ACL_PORT>`), `show acl rule BK_BIND_ACL`, `redis-cli -n 4 HGETALL "ACL_TABLE|BK_BIND_ACL"`.
4. Verify allowed and denied traffic from the peer: allowed: `ping -c 10 <DUT_IP>`; denied: `echo test | nc -u -w1 <DUT_IP> 9999`; then `aclshow -a` (`RULE_2` and `RULE_1` counters increment) and `show interfaces counters -i <child>`. Also send UDP 9999 through a sibling child that is not bound (for example `Ethernet4`, if it has a peer) and confirm it is not dropped.
5. Change the breakout mode with the binding still configured: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; verify the old binding removal: `show interfaces breakout current-mode Ethernet0`, `show acl table BK_BIND_ACL`, `redis-cli -n 4 HGETALL "ACL_TABLE|BK_BIND_ACL"` (no removed port, for example `Ethernet2`, in `ports`), `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER:*"` (no member of a removed port), `show logging | grep -i acl`.
6. Verify the new binding behavior on the recreated child: `sudo config interface startup Ethernet0`; re-add the L3 config of step 2; bind the table to the recreated port with `sonic-cfggen -j /tmp/bind_acl_table.json --write-to-db` (`<ACL_PORT>` = `Ethernet0` or `PortChannel10` with `Ethernet0` as the member); `show acl table BK_BIND_ACL`; repeat the traffic tests of step 4.
7. Cleanup: `redis-cli -n 4 DEL "ACL_RULE|BK_BIND_ACL|RULE_1" "ACL_RULE|BK_BIND_ACL|RULE_2"`, `redis-cli -n 4 DEL "ACL_TABLE|BK_BIND_ACL"`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

Files used by Test Case # 23:

```text
# /tmp/bind_acl_table.json
{"ACL_TABLE": {"BK_BIND_ACL": {"policy_desc": "BK_BIND_ACL", "type": "L3", "stage": "ingress", "ports": ["<ACL_PORT>"]}}}

# /tmp/bind_acl_rules.json
{"ACL_RULE": {
  "BK_BIND_ACL|RULE_1": {"PRIORITY": "9999", "PACKET_ACTION": "DROP",    "IP_PROTOCOL": "17", "L4_DST_PORT": "9999"},
  "BK_BIND_ACL|RULE_2": {"PRIORITY": "9000", "PACKET_ACTION": "FORWARD", "IP_PROTOCOL": "1"}}}
```

**Expected:** Before the mode change, `BK_BIND_ACL` is bound only to `<ACL_PORT>`: ICMP is forwarded, UDP 9999 is dropped, the `RULE_2` and `RULE_1` counters increment, and the unbound sibling child is not filtered. After the mode change the binding to the removed or recreated port is removed (or re-bound by the platform) and no `ports` entry, ASIC ACL group member or log error refers to a removed port. After re-binding to the recreated child the same allow/deny results are obtained. After cleanup no `BK_BIND_ACL` remains and the mode is `1x800G[400G]`.

### Test Case # 28 - ACL table persistence during breakout of an unrelated port (T0 and T1)
1. Breakout the tested parent port and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`.
2. Configure the tested child and ping the peer. `<ACL_PORT>` is the port the ACL is bound to:
   - T0 VLAN: `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<ACL_PORT>` = `Ethernet0`.
   - T0 PortChannel: `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<ACL_PORT>` = `PortChannel10`.
   - T1 routed: `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<ACL_PORT>` = `Ethernet0`.
3. Configure the ACL table and rules (set `<ACL_PORT>` in `/tmp/acl_table.json`): `sonic-cfggen -j /tmp/acl_table.json --write-to-db`, `sonic-cfggen -j /tmp/acl_rules.json --write-to-db`; verify with `show acl table BK_ACL`, `show acl rule BK_ACL`, `aclshow -a`.
4. Record the baseline: `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:*" > /tmp/acl_tbl_before.txt`, `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*" > /tmp/acl_ent_before.txt`, `redis-cli -n 4 HGETALL "ACL_TABLE|BK_ACL"`. From the peer send UDP port 9999 traffic (`echo test | nc -u -w1 <DUT_IP> 9999`) and check that the drop counter of `RULE_1` increments in `aclshow -a`. Start a continuous ping from the peer: `ping -i 0.2 -c 600 <DUT_IP>`.
5. Change the breakout mode on another, unrelated parent port (`Ethernet8`, any other breakout-capable parent from `show interfaces breakout`): `sudo config interface breakout Ethernet8 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet8` (repeat for `Ethernet10`, `Ethernet12`, `Ethernet14`); break out the matching fanout port if the link is used.
6. Verify the ACL persisted and no traffic hole occurred: `show acl table BK_ACL` (ports still `<ACL_PORT>` only), `show acl rule BK_ACL`, `redis-cli -n 4 HGETALL "ACL_TABLE|BK_ACL"`; `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:*" > /tmp/acl_tbl_after.txt` and the same for ACL_ENTRY to `/tmp/acl_ent_after.txt`; `diff /tmp/acl_tbl_before.txt /tmp/acl_tbl_after.txt`; `diff /tmp/acl_ent_before.txt /tmp/acl_ent_after.txt`; check the ping summary of step 4 (packet loss); repeat the UDP 9999 test and read `aclshow -a`; `show logging | grep -i acl`.
7. Cleanup: `redis-cli -n 4 DEL "ACL_RULE|BK_ACL|RULE_1" "ACL_RULE|BK_ACL|RULE_2"`, `redis-cli -n 4 DEL "ACL_TABLE|BK_ACL"`; `sudo config interface breakout Ethernet8 '1x800G[400G]' -f -y`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`.

Files used by Test Case # 22:

```text
# /tmp/acl_table.json
{"ACL_TABLE": {"BK_ACL": {"policy_desc": "BK_ACL", "type": "L3", "stage": "ingress", "ports": ["<ACL_PORT>"]}}}

# /tmp/acl_rules.json
{"ACL_RULE": {
  "BK_ACL|RULE_1": {"PRIORITY": "9999", "PACKET_ACTION": "DROP",    "IP_PROTOCOL": "17", "L4_DST_PORT": "9999"},
  "BK_ACL|RULE_2": {"PRIORITY": "9000", "PACKET_ACTION": "FORWARD", "IP_PROTOCOL": "1"}}}
```

**Expected:** `BK_ACL` and its two rules stay `Active` and bound only to `<ACL_PORT>`; the new children of `Ethernet8` are not added to the table. The ASIC ACL table and entry lists are identical before and after the unrelated breakout (the ACL objects are not deleted and recreated), the CONFIG_DB entries are unchanged and the `RULE_1` counter keeps its value instead of resetting. The continuous ping on the tested child has 0 % packet loss (no traffic hole), UDP 9999 stays dropped and `RULE_2` keeps forwarding ICMP. After cleanup

### Test Case # 29 - Mirror session dependency on breakout interface (T0 and T1)
1. Breakout the parent port and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`. `Ethernet4` is used as the monitor port and has no IP or VLAN/PortChannel configuration.
2. Configure the source child and ping the peer:
   - T0 VLAN: `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. Mirror source = `Ethernet0`.
   - T0 PortChannel: `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. Mirror source = `Ethernet2`.
   - T1 routed: `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. Mirror source = `Ethernet0`.
3. Configure the mirror session with the breakout child as source:
   - T0 (SPAN): `sudo config mirror_session span add span1 Ethernet4 <source child> both`.
   - T1 (ERSPAN, image dependent): `sudo config route add prefix 10.1.0.33/32 nexthop 192.0.2.0`, then `sudo config mirror_session erspan add erspan1 10.1.0.32 10.1.0.33 8 64 0x88be 0 Ethernet0 both`.
   - Breakout child as destination (where supported): `sudo config mirror_session span add span2 Ethernet6 <other non-breakout port> both`.
4. Verify the session and mirrored traffic: `show mirror_session`; `redis-cli -n 4 HGETALL "MIRROR_SESSION|span1"`; `redis-cli -n 6 HGETALL "MIRROR_SESSION_TABLE|span1"`; send `ping -c 10 <peer IP>` and capture on the peer side of the monitor port with `tcpdump -i <monitor peer interface> icmp`; `show interfaces counters -i Ethernet4`.
5. Change the breakout mode with the session still configured: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; then `show interfaces breakout current-mode Ethernet0`, `show mirror_session`, `redis-cli -n 4 KEYS "MIRROR_SESSION*"`, `redis-cli -n 6 KEYS "MIRROR_SESSION_TABLE*"`.
6. Cleanup: `sudo config mirror_session remove span1` (also `span2` and `erspan1` if created), remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`), then restore: `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`.

**Expected:** The session is `active` in `show mirror_session` and the monitor port transmits the mirrored copies of the source child traffic (counters on `Ethernet4` increment). After the breakout mode change the platform either rejects the change with a dependency message and the session stays valid, or removes/reconfigures the session; in both cases no session refers to a removed child port and no stale `MIRROR_SESSION` entry remains in CONFIG_DB or STATE_DB. After cleanup the mode is `1x800G[400G]` and `show mirror_session` is empty.

### Test Case # 30 - CACL on breakout interface (T0 and T1)
1. Breakout the parent port and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`.
2. Configure the breakout child and ping the peer:
   - T0 VLAN: `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`.
   - T0 PortChannel: `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
   - T1 routed: `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
3. Create a CACL table for SSH and a rule that permits the peer IP and drops all other sources: `sonic-cfggen -j /tmp/cacl_table.json --write-to-db`, `sonic-cfggen -j /tmp/cacl_rules.json --write-to-db`; verify with `show acl table` and `show acl rule`.
4. From the peer SSH to the DUT IP of the VLAN/PortChannel/routed interface, then SSH from another source; check the rule counters with `sudo iptables -L INPUT -v -n` and `show interfaces counters`.
5. Remove the CACL rule and table, remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`), and restore the port: `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`.

### Test Case # 31 - BMP monitoring of BGP over breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and ping the peer. `<PORT>` is the tested child:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
3. Configure BGP to the peer on the DUT and on the peer (ARISTA), as in the `bgp` row of 6.5:
   - DUT: `vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "neighbor <PEER_IP> remote-as <PEER_ASN>"` (or ConfigDB `BGP_NEIGHBOR`).
   - Peer (EOS): `router bgp <PEER_ASN>`, `neighbor <DUT_IP> remote-as <DUT_ASN>`, `redistribute static`.
   - Verify: `show ip bgp summary` (`Established`), `show ip route bgp`.
4. Enable the BMP target in FRR (image dependent, `bgpd` must have the BMP module): `vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "bmp targets t1" -c "bmp connect <COLLECTOR_IP> port 5000" -c "bmp monitor ipv4 unicast pre-policy"`; verify with `vtysh -c "show bgp bmp"`.
5. Advertise 10 prefixes from the peer (EOS `ip route 10.60.<n>.0/24 Null0`, n = 1..10, redistributed by `redistribute static`) and capture BMP on the collector: `tcpdump -nn -i any port 5000 -c 20` (or a BMP collector log); on the DUT `show ip route bgp`, `ping -c 5 10.60.1.1`.
6. Flap the tested child: `sudo config interface shutdown <PORT>`, wait 10 s, check the collector and `show ip bgp summary`; `sudo config interface startup <PORT>`, wait 60 s, check the collector and `show ip bgp summary`.
7. Cleanup: `vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no bmp targets t1"`; remove the BGP neighbor; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** The BGP session to the peer is `Established` with 10 prefixes (next hop interface is the tested child). The BMP session to the collector is established (`show bgp bmp` shows `Up`). The collector receives Peer Up and Route Monitoring messages for `<PEER_IP>` and the 10 prefixes. On `shutdown <PORT>` the collector receives a Peer Down message and the routes are withdrawn; after `startup <PORT>` it receives Peer Up and the Route Monitoring updates again (10 prefixes). After cleanup the mode is `1x800G[400G]`.

### Test Case # 32 - BFD over breakout child and link recovery (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and ping the peer. `<PORT>` is the tested child:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`, `<DUT_IP>` = `192.168.100.1`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`, `<DUT_IP>` = `192.0.2.1`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet0`, same addresses as the PortChannel run.
3. Establish BGP to the peer and enable BFD on the neighbor, on the DUT and on the peer (ARISTA):
   - DUT: `vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "neighbor <PEER_IP> remote-as <PEER_ASN>" -c "neighbor <PEER_IP> bfd"`.
   - Peer (EOS): `router bgp <PEER_ASN>`, `neighbor <DUT_IP> remote-as <DUT_ASN>`, `neighbor <DUT_IP> bfd`, and on the peer interface `bfd interval 300 min-rx 300 multiplier 3`.
   - Advertise one prefix from the peer: `interface Loopback200`, `ip address 10.200.0.1/24`, `router bgp <PEER_ASN>`, `network 10.200.0.0/24`.
4. Verify BFD and the learned route: `show bfd summary`; `vtysh -c "show bfd peers"`; `show ip bgp summary`; `show ip route 10.200.0.0/24` (next hop interface is the tested child); `ping -c 5 10.200.0.1`.
5. Flap the tested child and observe BFD: `sudo config interface shutdown <PORT>`; within 1 s (detect time = 300 ms x 3) run `vtysh -c "show bfd peers"`, `show ip bgp summary`, `show ip route 10.200.0.0/24`; `sudo config interface startup <PORT>`; wait 60 s; `show bfd summary`, `vtysh -c "show bfd peers"`, `show ip bgp summary`, `show ip route 10.200.0.0/24`, `ping -c 5 10.200.0.1`.
6. Cleanup: remove BFD and the BGP neighbor (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor <PEER_IP> bfd" -c "no neighbor <PEER_IP> remote-as <PEER_ASN>"`) and the peer `Loopback200`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** Step 4: the BFD peer is `up` on the tested child, BGP is `Established` and `10.200.0.0/24` is installed with the tested child as next hop interface. Step 5: after `shutdown <PORT>` BFD goes `down` within the detect time, BGP leaves `Established` and the route `10.200.0.0/24` is withdrawn; after `startup <PORT>` BFD returns to `up`, BGP is `Established` again, the route is installed and the ping works. After cleanup the mode is `1x800G[400G]`.

### Test Case # 33 - Service autorestart while breakout is active (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and ping the peer. `<PORT>` is the tested child:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; establish BGP to `192.0.2.0` (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "neighbor 192.0.2.0 remote-as <PEER_ASN>"`, and the peer side); `ping -c 5 192.0.2.0`; `show ip bgp summary`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
3. Record the baseline and start a continuous ping: `show feature status`, `show feature autorestart`, `docker ps`, `show interfaces breakout current-mode Ethernet0`, `redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"`; `ping -i 0.2 -c 600 <PEER_IP> | tee /tmp/ping_autorestart.txt` (run in the background or a second session).
4. Restart services while the breakout stays active:
   - T0: `sudo config feature autorestart lldp enabled`; `docker exec lldp pkill -9 lldpd`; `sudo systemctl restart bgp`.
   - T1: `docker exec lldp pkill -9 lldpd`; `sudo systemctl restart bgp`; `sudo systemctl restart swss` (image dependent; the whole data plane restarts, wait for recovery).
   - Wait for recovery (up to 5 minutes): `docker ps`, `show system-health summary`.
5. Verify after the restarts: `show feature status`; `show interfaces status`; `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"`; `show vlan brief` (T0 VLAN) or `show interfaces portchannel` (T0 PortChannel) or `show ip bgp summary` (T1); `ping -c 5 <PEER_IP>`; `tail -5 /tmp/ping_autorestart.txt` (packet loss summary); `show logging | grep -iE "lldp|bgp|swss|syncd" | tail -50`.
6. Cleanup: T1 remove the BGP neighbor (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor 192.0.2.0 remote-as <PEER_ASN>"`); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** The `lldp` and `bgp` containers (and `swss` on T1) restart automatically and return to `running` in `show feature status` and `docker ps`. `Ethernet0`, `Ethernet2`, `Ethernet4` and `Ethernet6` return to `up/up`, the breakout mode stays `4x200G[100G]` and `BREAKOUT_CFG|Ethernet0` is unchanged. The VLAN membership, PortChannel member or routed IP is intact, BGP re-establishes on T1, and ping to `<PEER_IP>` recovers; packet loss occurs only during the restart. After cleanup the mode is `1x800G[400G]`.

### Test Case # 34 - Audit records for breakout configuration changes (T0 and T1)
1. Check auditd and the audit rules, and record the start time: `systemctl is-active auditd`, `sudo auditctl -s`, `sudo auditctl -l`, `date '+%m/%d/%Y %H:%M:%S'` (use this value as `<START>` below). If `auditctl -l` shows no rule that records command execution (for example `execve`), add the image's audit rules for `config` first (image dependent).
2. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
3. Configure the breakout child and ping the peer:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
4. Search the audit records of the commands:
   - `sudo ausearch -ts <START> -i | grep -E "breakout|startup"` (breakout and startup commands)
   - T0: `sudo ausearch -ts <START> -i | grep -E "vlan|portchannel"`
   - T1: `sudo ausearch -ts <START> -i | grep -E "interface ip"`
   - `sudo ausearch -ts <START> -m EXECVE -i | tail -50` (user, command line and timestamp)
5. Summarize the records: `sudo aureport -x -ts <START> --summary`; `sudo aureport -u -ts <START> --summary`; `sudo aureport -e -ts <START> | tail -30`; check for gaps with `sudo auditctl -s` (`lost` = 0, `backlog` below the limit).
6. Cleanup and audit the cleanup commands: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `sudo ausearch -ts <START> -i | grep -E "1x800G"`; `systemctl is-active auditd`.

**Expected:** `auditd` is `active` before, during and after the test and `auditctl -s` shows `lost 0`. There is an audit record for every configuration command (breakout with `4x200G[100G]` and `1x800G[400G]`, `startup`, and `vlan`, `portchannel` or `interface ip` as applicable) with the user, the command line, the timestamp and `success=yes`; no command is missing. The breakout and configuration commands themselves succeed as in the other cases and the mode is `1x800G[400G]` after cleanup.

### Test Case # 35 - ARP/NDP on breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child. `<PORT>` is the tested child and `<L3_IF>` the interface that holds the IP:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`, `sudo config interface ip add Vlan100 2001:db8:100::1/64`. `<PORT>` = `Ethernet0`, `<L3_IF>` = `Vlan100`, `<PEER_IP>` = `192.168.100.2`, `<PEER_IP6>` = `2001:db8:100::2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`, `sudo config interface ip add PortChannel10 2001:db8:1::1/127`. `<PORT>` = `Ethernet2`, `<L3_IF>` = `PortChannel10`, `<PEER_IP>` = `192.0.2.0`, `<PEER_IP6>` = `2001:db8:1::`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`, `sudo config interface ip add Ethernet0 2001:db8:1::1/127`. `<PORT>` = `Ethernet0`, `<L3_IF>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`, `<PEER_IP6>` = `2001:db8:1::`.
3. Clear the neighbor tables: `sonic-clear arp`; `sonic-clear ndp`; `show arp`; `show ndp` (no entry for the peer).
4. Resolve the neighbors: `ping -c 3 <PEER_IP>`; `ping6 -c 3 <PEER_IP6>`.
5. Verify the entries: `show arp`; `show ndp`; `redis-cli -n 0 KEYS "NEIGH_TABLE:*"`; `redis-cli -n 0 HGETALL "NEIGH_TABLE:<L3_IF>:<PEER_IP>"`; `ip neigh show dev <L3_IF>`; T0: `show mac` (peer MAC on `<PORT>`).
6. Flap the tested child: `sudo config interface shutdown <PORT>`; wait 10 s; `show arp`; `show ndp`; `sudo config interface startup <PORT>`; wait 30 s; `ping -c 3 <PEER_IP>`; `ping6 -c 3 <PEER_IP6>`; `show arp`; `show ndp`.
7. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <L3_IF> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** Step 3: no neighbor entry for the peer after the clear. Step 5: the ARP and NDP entries for the peer are resolved on `<L3_IF>` (`Vlan100`, `PortChannel10` or `Ethernet0`) with the peer MAC, `NEIGH_TABLE` entries exist in APPL_DB, and on T0 the peer MAC is learned on `<PORT>`. Step 6: after `shutdown <PORT>` the entries are removed; after `startup <PORT>` they are learned again with the same MAC and ping works. After cleanup the mode is `1x800G[400G]`.

### Test Case # 36 - Time and event ordering during breakout (T0 and T1)
1. Check the time and NTP before the test: `show clock`, `show ntp`, `date -u`, `timedatectl`, `chronyc tracking` (or `ntpq -p`, depending on the NTP daemon of the image). Record `System time` offset and the NTP state as the baseline.
2. Apply breakout mode on the DUT and the fanout, recording the time before and after each command (`date -u +%FT%T.%3N`):

   ```text
   date -u +%FT%T.%3N | tee -a /tmp/clock_ts.txt
   sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y
   date -u +%FT%T.%3N | tee -a /tmp/clock_ts.txt
   for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do sudo config interface startup $p; date -u +%FT%T.%3N | tee -a /tmp/clock_ts.txt; done
   sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y
   ```

3. Configure the breakout child and ping the peer, recording `date -u +%FT%T.%3N | tee -a /tmp/clock_ts.txt` before and after each command:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
4. Check the log ordering: `show logging | grep -E "Ethernet(0|2|4|6)" | tail -100`; `cat /tmp/clock_ts.txt`; compare the log timestamps with the recorded times (the events must be in the same order as the commands, and in each recorded interval).
5. Check the time and NTP after the test: `show clock`, `show ntp`, `date -u`, `chronyc tracking` (or `ntpq -p`); calculate the time difference between consecutive `date -u` values and compare with the elapsed time.
6. Cleanup: `sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `show ntp`; `rm /tmp/clock_ts.txt`.

**Expected:** `show ntp` reports the NTP server as synchronized (selected peer, small offset) before and after the breakout. The recorded timestamps increase monotonically, there is no time jump above 1 s between consecutive recorded times beyond the real elapsed time, and the `show logging` entries for `Ethernet0`, `Ethernet2`, `Ethernet4` and `Ethernet6` appear in the same order as the commands with timestamps inside the recorded intervals. NTP stays synchronized after cleanup and the mode is `1x800G[400G]`.

### Test Case # 37 - GCU patch, rollback and member/IP removal on breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child. `<PORT>` is the tested child:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<PORT>` = `Ethernet0`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet2`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PORT>` = `Ethernet0`.
3. Create the checkpoint and the patch files:

   ```text
   sudo config checkpoint before_gcu
   sudo config list-checkpoints

   cat > /tmp/patch_add_desc.json <<'EOF'
   [{"op": "add", "path": "/PORT/<PORT>/description", "value": "bk-test"}]
   EOF

   # T0 VLAN
   cat > /tmp/patch_remove_member.json <<'EOF'
   [{"op": "remove", "path": "/VLAN_MEMBER/Vlan100|Ethernet0"}]
   EOF
   # T0 PortChannel
   cat > /tmp/patch_remove_member.json <<'EOF'
   [{"op": "remove", "path": "/PORTCHANNEL_MEMBER/PortChannel10|Ethernet2"}]
   EOF
   # T1 routed
   cat > /tmp/patch_remove_ip.json <<'EOF'
   [{"op": "remove", "path": "/INTERFACE/Ethernet0|192.0.2.1~131"}]
   EOF

   cat > /tmp/patch_bad_port.json <<'EOF'
   [{"op": "add", "path": "/PORT/Ethernet1/description", "value": "bk-test"}]
   EOF
   ```

   Create only the member patch of the variant being tested.
4. Apply the description patch and verify: `sudo config apply-patch /tmp/patch_add_desc.json`; `show runningconfiguration all | grep bk-test`; `redis-cli -n 4 HGET "PORT|<PORT>" description`; `show interfaces description <PORT>`; `ping -c 3 <PEER_IP>` (the link stays up).
5. T1 only: apply the IP removal patch and check the routes: `sudo config apply-patch /tmp/patch_remove_ip.json`; `show ip interfaces`; `show ip route 192.0.2.0/31`; `show arp`; `ping -c 3 192.0.2.0` (must fail).
6. Roll back to the checkpoint: `sudo config rollback before_gcu`; `show runningconfiguration all | grep bk-test` (no output); T1: `show ip interfaces`; `show ip route 192.0.2.0/31`; `ping -c 5 192.0.2.0`; T0: `show vlan brief` or `show interfaces portchannel`.
7. T0 only: apply the member removal patch and check the cleanup: `sudo config apply-patch /tmp/patch_remove_member.json`; VLAN: `show vlan brief`, `redis-cli -n 4 KEYS "VLAN_MEMBER|Vlan100|*"`; PortChannel: `show interfaces portchannel`, `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|*"`; `show mac` (no entries on `<PORT>`); `show arp` (no peer entry on the removed member); `ping -c 3 <PEER_IP>` (must fail).
8. Apply the patch for the non-existing port and check the result: `sudo config apply-patch /tmp/patch_bad_port.json` (must print an error); `echo $?` (non-zero); `redis-cli -n 4 EXISTS "PORT|Ethernet1"` (0); `show interfaces status` (no `Ethernet1`).
9. Cleanup: roll back if needed (`sudo config rollback before_gcu`); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm /tmp/patch_*.json`.

**Expected:** Step 4: the patch is applied successfully, `bk-test` appears in the running configuration and in `PORT|<PORT>`, and the link and ping are not affected. Step 5 (T1): after the IP removal the connected route `192.0.2.0/31` and the ARP entry disappear and ping fails. Step 6: the rollback removes the description and restores the checkpoint configuration (the IP on T1, the VLAN or PortChannel member on T0), and ping works again. Step 7 (T0): the member is removed with its FDB and ARP entries and ping fails. Step 8: the patch for `Ethernet1` is rejected with an error, no `PORT|Ethernet1` is created and the configuration is unchanged. After cleanup the mode is `1x800G[400G]`.

### Test Case # 38 - Packet and byte counters on breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child. `<PORT>` is the tested child and `<L3_IF>` the interface that holds the IP:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `Ethernet0`, `<L3_IF>` = `Vlan100`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PORT>` = `Ethernet2`, `<L3_IF>` = `PortChannel10`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`. `<PORT>` = `Ethernet0`, `<L3_IF>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
3. Make sure the counters are polled and the peer is reachable: `counterpoll show` (PORT_STAT and RIF_STAT `enable`; if RIF_STAT is disabled run `sudo counterpoll rif enable`); `ping -c 3 <PEER_IP>`.
4. Clear the counters and check that they are zero: `sonic-clear counters`; `sonic-clear rifcounters`; wait 15 s; `show interfaces counters -i <PORT>`; `show interfaces counters -i Ethernet0,Ethernet2,Ethernet4,Ethernet6`.
5. Send a known amount of traffic (1000 packets of 1000 bytes at the IP layer, 1014 bytes on the wire): `sudo ping -c 1000 -s 972 -i 0.01 <PEER_IP>`; check the loss in the ping summary (0%).
6. Wait 15 s for the counter poll, then read the counters:
   - `show interfaces counters -i <PORT>`
   - `portstat -i <PORT>`
   - `portstat -i Ethernet0,Ethernet2,Ethernet4,Ethernet6` (sibling children)
   - `show interfaces counters rif` (shows `<L3_IF>`)
   - `redis-cli -n 2 HGETALL "COUNTERS:$(redis-cli -n 2 HGET COUNTERS_PORT_NAME_MAP <PORT>)"` (RX/TX packets and bytes, errors, discards)
7. Compare with the expected values: `RX_OK` and `TX_OK` of `<PORT>` increased by about 1000 packets each (ping request out and reply in), `RX_BYTE` and `TX_BYTE` by about 1,000,000 to 1,020,000 bytes, `RX_ERR`, `TX_ERR`, `RX_DRP` and `TX_DRP` are 0.
8. Clear the counters again and check that they reset: `sonic-clear counters`; wait 15 s; `show interfaces counters -i <PORT>` (values near 0).
9. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <L3_IF> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** Step 4: counters of `<PORT>` are near 0 after the clear. Steps 6 and 7: `RX_OK` and `TX_OK` on `<PORT>` rise by about 1000 packets and `RX_BYTE` and `TX_BYTE` by about 1 MB; `show interfaces counters rif` shows the same traffic on `<L3_IF>`; the sibling children are near zero (only control traffic such as LLDP); errors and drops are 0 and the ping loss is 0%. Step 8: the counters are reset. After cleanup the mode is `1x800G[400G]`.

### Test Case # 39 - ConfigDB migration with breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and check the connectivity:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. If BGP is configured (see the bgp case), `show ip bgp summary` shows the neighbor `Established`.
3. Save the configuration and dump the ConfigDB before the migration:

   ```text
   sudo config save -y
   sonic-db-cli CONFIG_DB HGET "VERSIONS|DATABASE" VERSION
   redis-cli -n 4 KEYS "*" | sort > /tmp/before.txt
   sonic-cfggen -d --print-data > /tmp/before.json
   redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"
   ```

4. Run the migration: `sudo db_migrator.py -o get_version`; `sudo db_migrator.py -o migrate`; `echo $?` (0); `sudo db_migrator.py -o get_version`; `show logging | grep -i db_migrator | tail -20`.
5. Dump the ConfigDB after the migration and compare:

   ```text
   redis-cli -n 4 KEYS "*" | sort > /tmp/after.txt
   sonic-cfggen -d --print-data > /tmp/after.json
   diff /tmp/before.txt /tmp/after.txt
   diff /tmp/before.json /tmp/after.json
   diff <(grep -E "PORT|BREAKOUT_CFG|VLAN_MEMBER|PORTCHANNEL_MEMBER|INTERFACE|BGP_NEIGHBOR" /tmp/before.txt) <(grep -E "PORT|BREAKOUT_CFG|VLAN_MEMBER|PORTCHANNEL_MEMBER|INTERFACE|BGP_NEIGHBOR" /tmp/after.txt)
   ```

6. Verify the state and the connectivity after the migration: `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"`; `show interfaces status`; T0 VLAN: `show vlan brief`; T0 PortChannel: `show interfaces portchannel`; T1: `show ip interfaces`, `show ip route 192.0.2.0/31`, `show ip bgp summary` (if configured); `ping -c 5 <PEER_IP>` (`192.168.100.2` for T0 VLAN, `192.0.2.0` for T0 PortChannel and T1).
7. Check that the configuration still loads after a reload: `sudo config save -y`; `sudo config reload -y`; wait until the containers are up (`docker ps`, `show system-health summary`); repeat the checks of step 6.
8. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm /tmp/before.* /tmp/after.*`.

**Expected:** `db_migrator.py -o migrate` returns 0 and reports the version without errors. There is no diff for `PORT`, `BREAKOUT_CFG`, `VLAN_MEMBER`, `PORTCHANNEL_MEMBER`, `INTERFACE` (and `BGP_NEIGHBOR` on T1); only keys related to the database version (`VERSIONS|DATABASE`) may differ if the image performs a version upgrade. The breakout mode stays `4x200G[100G]`, `BREAKOUT_CFG|Ethernet0` is unchanged, the VLAN membership, PortChannel member or routed IP is intact, BGP stays `Established` where configured, and ping to the peer works before the migration, after it and after the reload. After cleanup the mode is `1x800G[400G]`.

### Test Case # 40 - Disk and memory health during breakout cycles (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and check the connectivity. `<PEER_IP>` is the peer address:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; configure the BGP neighbor `192.0.2.0` as in the bgp case (6.18) and check `show ip bgp summary` (`Established`). `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>`.
3. Collect the baseline and save it:

   ```text
   df -h / /var/log | tee /tmp/disk_before.txt
   free -m | tee /tmp/mem_before.txt
   docker stats --no-stream | tee /tmp/docker_before.txt
   sudo du -sh /var/log /var/core 2>/dev/null
   ls /var/core 2>/dev/null | wc -l
   sudo monit summary
   show system-health summary
   ```

4. Run the traffic for 5 minutes and check the health during the traffic: `sudo ping -i 0.2 -w 300 <PEER_IP> | tail -3` (about 1500 packets, 0% loss); while it runs, in a second session: `free -m`; `docker stats --no-stream`; `df -h /`.
5. Run 10 breakout cycles (the `-f` option removes the VLAN/PortChannel/IP config of the child, so it is re-applied each cycle). Define the function of the variant:

   ```text
   # T0 VLAN
   apply_child() { sudo config vlan add 100; sudo config vlan member add -u 100 Ethernet0; sudo config interface ip add Vlan100 192.168.100.1/24; }
   # T0 PortChannel
   apply_child() { sudo config portchannel add PortChannel10; sudo config portchannel member add PortChannel10 Ethernet2; sudo config interface ip add PortChannel10 192.0.2.1/31; }
   # T1 routed
   apply_child() { sudo config interface ip add Ethernet0 192.0.2.1/31; }
   ```

   Then run the loop (the fanout port stays in `4x200G[100G]`):

   ```text
   for i in $(seq 1 10); do
     echo "cycle $i $(date -u +%FT%T)"
     sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y; sleep 30
     sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y; sleep 30
     for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do sudo config interface startup $p; done
     apply_child; sleep 30
     ping -c 5 <PEER_IP> | tail -2
     free -m | sed -n 2p; df -h / | tail -1
   done | tee /tmp/breakout_cycles.txt
   ```

   If a cycle fails (breakout rejected, ping loss after 60 s), stop and record the cycle number.
6. Re-collect the metrics and compare with the baseline:

   ```text
   df -h / /var/log | tee /tmp/disk_after.txt
   free -m | tee /tmp/mem_after.txt
   docker stats --no-stream | tee /tmp/docker_after.txt
   diff /tmp/disk_before.txt /tmp/disk_after.txt
   diff /tmp/mem_before.txt /tmp/mem_after.txt
   diff /tmp/docker_before.txt /tmp/docker_after.txt
   sudo du -sh /var/log /var/core 2>/dev/null
   ls /var/core 2>/dev/null | wc -l
   sudo monit summary
   ```

7. Check the memory and OOM events: `show logging | grep -i -E "oom|out of memory|memory_checker|killed process"`; `sudo dmesg | grep -i -E "oom|out of memory"`; `show system-health summary`; `docker ps` (all containers `Up`, no restarts in `docker ps -a --format '{{.Names}} {{.Status}}'`); T1: `show ip bgp summary` (`Established`).
8. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`) and the BGP neighbor on T1; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm /tmp/disk_*.txt /tmp/mem_*.txt /tmp/docker_*.txt /tmp/breakout_cycles.txt`.

**Expected:** Step 4: 0% ping loss. Step 5: each cycle ends with 0% ping loss to `<PEER_IP>` and `free -m` and `df -h` stay stable. Step 6: disk usage on `/` grows by less than 1%, no new files in `/var/core`, no container memory growth above the memory checker threshold (`docker stats` values close to the baseline). Step 7: no `oom` or `memory_checker` messages, all containers stay `Up` without restarts, `show system-health summary` is `OK`, and on T1 BGP stays `Established`. After cleanup the mode is `1x800G[400G]`.

### Test Case # 41 - FIPS, password hardening and container hardening with breakout traffic (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and start the traffic. `<PORT>` is the tested child and `<PEER_IP>` the peer:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>`, then start the traffic in the background: `nohup ping -i 0.2 <PEER_IP> > /tmp/ping_security.txt 2>&1 &`.
3. Check FIPS (the FIPS mode is an image-level setting):
   - `sudo sonic-installer get-fips` (`FIPS is enabled` or disabled)
   - `grep -o "sonic_fips=1" /proc/cmdline`
   - `show fips` and `sudo config fips enable` (image dependent; reboot is needed if the image enables FIPS only at boot); `sudo apt list --installed 2>/dev/null | grep fips`
   - From the sonic-mgmt controller or another host: `ssh -Q cipher` (supported ciphers); `ssh -o Ciphers=aes128-cbc admin@<DUT_MGMT_IP>` (non-approved cipher) and `ssh -o Ciphers=aes256-ctr admin@<DUT_MGMT_IP>` (approved cipher).
4. Check the password hardening:

   ```text
   sudo config passw-hardening policies state enabled
   sudo config passw-hardening policies len-min 8
   sudo config passw-hardening policies upper-class true
   sudo config passw-hardening policies lower-class true
   sudo config passw-hardening policies digits-class true
   sudo config passw-hardening policies special-class true
   show passw-hardening policies
   cat /etc/pam.d/common-password

   sudo useradd bk_user_test
   echo 'bk_user_test:abc' | sudo chpasswd
   echo "rc=$?"
   echo 'bk_user_test:Str0ng#Passw0rd' | sudo chpasswd
   echo "rc=$?"
   ```

   The weak password `abc` must be rejected (non-zero rc and a message about the password policy); the compliant password must be accepted (rc=0).
5. Check the container hardening: `docker ps --format '{{.Names}}'`; for each container that is not `pmon`, `syncd` or `gbsyncd` (for example `bgp`, `lldp`, `snmp`, `teamd`, `swss`, `database`): `docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' <container>` (must be `false`); `docker exec <container> bash -c "mount | grep /etc/hosts" | awk '{print $1}'` and `docker exec <container> bash -c "ls <device>"` (the `/dev/...` device of the host must not be accessible).
6. Check the breakout ports and the traffic while the checks run: `show interfaces status` (all four children `up/up`); `show interfaces breakout current-mode Ethernet0`; T0: `show vlan brief` or `show interfaces portchannel`; T1: `show ip interfaces`; `pkill -SIGINT ping`; `tail -3 /tmp/ping_security.txt` (packet loss summary).
7. Cleanup: restore the password policy and remove the test user: `sudo config passw-hardening policies state disabled`; `sudo userdel -r bk_user_test`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm /tmp/ping_security.txt`.

**Expected:** Step 3: when FIPS is enabled, the `sonic_fips=1` flag and the FIPS packages are present, the non-approved cipher `aes128-cbc` is rejected (`no matching cipher found`) and the approved cipher works. Step 4: the weak password is rejected, the compliant password is accepted, and `show passw-hardening policies` and `/etc/pam.d/common-password` show the configured policy. Step 5: the hardened containers are not privileged and cannot access the host partition (`pmon`, `syncd` and `gbsyncd` are excluded). Step 6: the four breakout children stay `up/up`, the VLAN membership, PortChannel member or routed IP is intact, the breakout mode stays `4x200G[100G]`, and the ping runs without interruption (0% loss, apart from the first packet). After cleanup the mode is `1x800G[400G]`.

### Test Case # 42 - SSH, SCP, HTTP and DNS with a filter ACL on breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and the sources. `<SRC1>` is the permitted source (the peer address) and `<SRC2>` the second source that will be filtered; the commands of the peer run in a Linux shell (for an Arista peer use `bash`, or a server host behind the peer):
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<ACL_PORT>` = `Ethernet0`, `<DUT_IP>` = `192.168.100.1`, `<SRC1>` = `192.168.100.2`, `<SRC2>` = `192.168.100.3` (add it on the peer: `sudo ip addr add 192.168.100.3/24 dev <peer_if>`).
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<ACL_PORT>` = `PortChannel10`, `<DUT_IP>` = `192.0.2.1`, `<SRC1>` = `192.0.2.0`, `<SRC2>` = `10.10.10.2` (peer: `sudo ip addr add 10.10.10.2/32 dev lo`; DUT: `sudo config route add prefix 10.10.10.2/32 nexthop 192.0.2.0`).
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`. `<ACL_PORT>` = `Ethernet0`, `<DUT_IP>` = `192.0.2.1`, `<SRC1>` = `192.0.2.0`, `<SRC2>` = `10.10.10.2` (same loopback and route as the PortChannel variant).
   - Check `ping -c 5 <DUT_IP>` from the peer and `ping -c 5 <SRC1>` from the DUT.
3. Prepare the test data. On the peer: `dd if=/dev/urandom of=/tmp/1MB.bin bs=1M count=1`; `md5sum /tmp/1MB.bin`. `<SERVER_IP>` is an HTTP server and `<DNS_SERVER>` a DNS server that are reachable through the DUT (testbed servers behind another DUT port); `<NAME>` is a name that the DNS server resolves.
4. Run the flows without a filter, first from `<SRC1>` and then from `<SRC2>`:
   - SSH: `ssh -o StrictHostKeyChecking=no admin@<DUT_IP> true; echo "rc=$?"` (for `<SRC2>` add `-b <SRC2>`)
   - SCP: `scp -o StrictHostKeyChecking=no /tmp/1MB.bin admin@<DUT_IP>:/tmp/` (for `<SRC2>` add `-o BindAddress=<SRC2>`); on the DUT: `md5sum /tmp/1MB.bin` (same as the peer)
   - HTTP: `curl -s -o /dev/null -w "%{http_code}\n" http://<SERVER_IP>` (for `<SRC2>` add `--interface <SRC2>`)
   - DNS: `nslookup <NAME> <DNS_SERVER>` (or `dig +short @<DNS_SERVER> <NAME>`; for `<SRC2>` add `-b <SRC2>` to `dig`)
5. Create the filter ACL that drops TCP port 22 from `<SRC2>` on `<ACL_PORT>` (files below): `sonic-cfggen -j /tmp/filter_acl_table.json --write-to-db`, `sonic-cfggen -j /tmp/filter_acl_rules.json --write-to-db`; verify with `show acl table BK_FILTER`, `show acl rule BK_FILTER`, `redis-cli -n 4 HGETALL "ACL_TABLE|BK_FILTER"`.
6. Repeat the flows of step 4 from `<SRC1>` and from `<SRC2>` (SSH and SCP from `<SRC2>` use a time limit: `ssh -o ConnectTimeout=10 ...`, `scp -o ConnectTimeout=10 ...`); then `aclshow -a` (`RULE_1` counter increments for the blocked SSH/SCP packets) and `show interfaces counters -i <PORT>` (`<PORT>` = `Ethernet0` or `Ethernet2`).
7. Remove the filter and check that the flow of `<SRC2>` works again: `redis-cli -n 4 DEL "ACL_RULE|BK_FILTER|RULE_1" "ACL_RULE|BK_FILTER|RULE_2"`, `redis-cli -n 4 DEL "ACL_TABLE|BK_FILTER"`; `show acl table`; repeat SSH and SCP from `<SRC2>`.
8. Cleanup: remove the second source (peer: `sudo ip addr del <SRC2>/32 dev lo` or `sudo ip addr del 192.168.100.3/24 dev <peer_if>`; DUT on PortChannel and T1: `sudo config route del prefix 10.10.10.2/32 nexthop 192.0.2.0`); `rm /tmp/1MB.bin` on the peer and on the DUT; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

Files used by Test Case # 42:

```text
# /tmp/filter_acl_table.json
{"ACL_TABLE": {"BK_FILTER": {"policy_desc": "BK_FILTER", "type": "L3", "stage": "ingress", "ports": ["<ACL_PORT>"]}}}

# /tmp/filter_acl_rules.json
{"ACL_RULE": {
  "BK_FILTER|RULE_1": {"PRIORITY": "9999", "PACKET_ACTION": "DROP",    "IP_PROTOCOL": "6", "L4_DST_PORT": "22", "SRC_IP": "<SRC2>/32"},
  "BK_FILTER|RULE_2": {"PRIORITY": "1000", "PACKET_ACTION": "FORWARD", "ETHER_TYPE": "2048"}}}
```

**Expected:** Step 4 (no filter): for both sources SSH returns `rc=0`, SCP completes at 100% with the same `md5sum` on the DUT, HTTP returns `200` and DNS returns the answer. Step 6 (filter active): `<SRC1>` still passes all four flows; `<SRC2>` is blocked for SSH and SCP (connection timeout, `RULE_1` counter increases) while its HTTP and DNS flows still work. Step 7: after removing the filter `<SRC2>` can use SSH and SCP again. The breakout child stays `up/up` and the ping to the peer works during the test. After cleanup the mode is `1x800G[400G]`.

### Test Case # 43 - Pre-test, post-test, repeatability and logs with breakout cycles (T0 and T1)
Steps 1, 5, 6 and 8 run on the sonic-mgmt controller in the `tests` folder; the other steps run on the DUT.
1. Run the pre-test and check the result: `cd tests`; `./run_tests.sh -n <testbed> -d <dut> -f testbed.yaml -i ../ansible/veos -u -c test_pretest.py`; `echo $?` (0); check the report (`pretest.xml` and `pretest.log` under the log path printed by `run_tests.sh`) and that no test of `test_pretest.py` is `failed` or `error`.
2. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
3. Configure the breakout child with the function of the variant, check the connectivity, and save the log baseline. `<PEER_IP>` is the peer address:

   ```text
   # T0 VLAN (apply SETUP-T0-VLAN, 6.3), <PEER_IP> = 192.168.100.2
   apply_child() { sudo config vlan add 100; sudo config vlan member add -u 100 Ethernet0; sudo config interface ip add Vlan100 192.168.100.1/24; }
   # T0 PortChannel (apply SETUP-T0-PO, 6.3), <PEER_IP> = 192.0.2.0
   apply_child() { sudo config portchannel add PortChannel10; sudo config portchannel member add PortChannel10 Ethernet2; sudo config interface ip add PortChannel10 192.0.2.1/31; }
   # T1 routed (apply SETUP-T1, 6.3), <PEER_IP> = 192.0.2.0
   apply_child() { sudo config interface ip add Ethernet0 192.0.2.1/31; }

   apply_child
   ping -c 5 <PEER_IP>
   show logging | grep -E "ERR|CRIT" > /tmp/errs_before.txt; wc -l /tmp/errs_before.txt
   ```

4. Repeat the breakout 3 times and record the state of each cycle (the `-f` option removes the config of the child, so it is re-applied; the fanout port stays in `4x200G[100G]`). Save the state of the first configured state as `/tmp/state_0.txt` with the same commands as in the loop:

   ```text
   state() { show interfaces breakout current-mode Ethernet0; redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"; show interfaces status | grep -E "Ethernet(0|2|4|6) "; show vlan brief; show interfaces portchannel; show ip interfaces; }
   state > /tmp/state_0.txt 2>&1

   for i in 1 2 3; do
     echo "cycle $i $(date -u +%FT%T)"
     sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y; sleep 30
     sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y; sleep 30
     for p in Ethernet0 Ethernet2 Ethernet4 Ethernet6; do sudo config interface startup $p; done
     apply_child; sleep 30
     ping -c 5 <PEER_IP> | tail -2
     state > /tmp/state_$i.txt 2>&1
     diff /tmp/state_0.txt /tmp/state_$i.txt && echo "cycle $i state identical"
   done
   ```

5. Run the post-test and check the result: `./run_tests.sh -n <testbed> -d <dut> -f testbed.yaml -i ../ansible/veos -u -c test_posttest.py`; `echo $?` (0); check `posttest.xml` and `posttest.log` (no `failed` or `error` test).
6. Check the parallel-mode file used by the parallel run: `python3 -m json.tool test_parallel_modes.json > /dev/null && echo valid`; `python3 -c "import json,os; d=json.load(open('test_parallel_modes.json')); print([k for k in d if not os.path.exists(k)]); print(sorted(set(d.values())))"` (empty list of missing files; values `FULL_PARALLEL` and `RP_FIRST` only); the file is used by the pipeline only for chassis parallel runs (`--parallel-modes-file`), so on a single-DUT T0 or T1 testbed it is checked as a configuration file.
7. Check the logs of the DUT for new errors: `show logging | grep -E "ERR|CRIT" > /tmp/errs_after.txt`; `diff /tmp/errs_before.txt /tmp/errs_after.txt`; `show logging | grep -E "ERR|CRIT" | grep -iE "Ethernet(0|2|4|6)|breakout|portsyncd|syncd|orchagent"`; `show system-health summary`; `docker ps` (all containers `Up`); T1: `show ip bgp summary` if BGP is configured.
8. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm /tmp/state_*.txt /tmp/errs_*.txt`.

**Expected:** The pre-test and the post-test return 0 with no failed test. Each of the 3 cycles ends with the same state as the first configured state (`diff` has no output), `BREAKOUT_CFG|Ethernet0` is `4x200G[100G]`, the four children are `up/up` and ping to `<PEER_IP>` has 0% loss. `test_parallel_modes.json` is valid and lists only existing test files with `FULL_PARALLEL` or `RP_FIRST`. The new `ERR` and `CRIT` messages in `diff /tmp/errs_before.txt /tmp/errs_after.txt` are only the known messages of the breakout (for example the temporary port or link events), with no `CRIT` and no error from `orchagent` or `syncd` that remains after the last cycle. After cleanup the mode is `1x800G[400G]`.

### Test Case # 44 - Port metadata after breakout (T0 and T1)
1. Find the platform files of the DUT: `PLATFORM=$(sonic-cfggen -d -v DEVICE_METADATA.localhost.platform)`; `HWSKU=$(sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku)`; `ls /usr/share/sonic/device/$PLATFORM/platform.json /usr/share/sonic/device/$PLATFORM/$HWSKU/port_config.ini`. Save the metadata of the parent port before the breakout: `show interfaces status | grep -E "Ethernet0 "`; `redis-cli -n 4 HGETALL "PORT|Ethernet0"`; `python3 -c "import json; print(json.load(open('/usr/share/sonic/device/$PLATFORM/platform.json'))['interfaces']['Ethernet0'])"`.
2. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`; `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`. Check the metadata before the startup (the children must be admin `down`): `show interfaces breakout current-mode Ethernet0`; `show interfaces status | grep -E "Ethernet(0|2|4|6) "`; `redis-cli -n 4 HGET "PORT|Ethernet0" admin_status` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`).
3. Start the children and read the port metadata of each child: `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); for each child `redis-cli -n 4 HGETALL "PORT|<child>"` (`alias`, `index`, `lanes`, `speed`, `fec`, `mtu`, `admin_status`); `redis-cli -n 0 HGETALL "PORT_TABLE:<child>"` (APPL_DB); `redis-cli -n 6 HGETALL "PORT_TABLE|<child>"` (STATE_DB); `redis-cli -n 2 HGET COUNTERS_PORT_NAME_MAP <child>` (the child has a counter OID).
4. Check the metadata of the four children together (lanes do not overlap, alias unique, speed and index as expected):

   ```text
   sonic-cfggen -d --var-json PORT | python3 -c '
   import json,sys
   p=json.load(sys.stdin)
   lanes=[]; als=[]
   for c in ["Ethernet0","Ethernet2","Ethernet4","Ethernet6"]:
       d=p[c]; lanes+=d["lanes"].split(","); als.append(d["alias"])
       print(c, d["alias"], d["index"], d["lanes"], d["speed"], d.get("fec"), d.get("mtu"), d.get("admin_status"))
   print("lanes overlap:", len(lanes)!=len(set(lanes)))
   print("alias unique:", len(als)==len(set(als)))
   '
   ```

5. Compare with the platform files of step 1: `grep -E "^Ethernet(0|2|4|6)[[:space:]]" /usr/share/sonic/device/$PLATFORM/$HWSKU/port_config.ini` (the `4x200G[100G]` HWSKU may list the children, or only the parent port); `python3 -c "import json; i=json.load(open('/usr/share/sonic/device/$PLATFORM/platform.json'))['interfaces']['Ethernet0']; print(i['lanes']); print(i['index']); print(i['breakout_modes']['4x200G[100G]'])"` (the alias of each child is in `breakout_modes`, the lanes of the four children together are the lanes of the parent port, split in 4 groups).
6. Configure the breakout child and check the variant metadata:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `show vlan brief`; `redis-cli -n 4 HGETALL "VLAN_MEMBER|Vlan100|Ethernet0"` (`tagging_mode` = `untagged`); `ping -c 5 192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `show interfaces portchannel`; `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|PortChannel10|*"`; `ping -c 5 192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `show ip route 192.0.2.0/31` (connected, via `Ethernet0`); `redis-cli -n 4 KEYS "INTERFACE|Ethernet0*"` (`INTERFACE|Ethernet0` and `INTERFACE|Ethernet0|192.0.2.1/31`); `redis-cli -n 0 KEYS "ROUTE_TABLE:192.0.2.0/31"`; `ip route show 192.0.2.0/31`; `ping -c 5 192.0.2.0`.
7. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 HGETALL "PORT|Ethernet0"` (the metadata of the parent port is the same as in step 1) and `redis-cli -n 4 KEYS "PORT|Ethernet[246]"` (no keys).

**Expected:** Step 2: the mode is `4x200G[100G]` and the four children have `admin_status` `down` before the startup. Steps 3 and 4: each child has an `alias`, `index`, `lanes`, `speed` = `200000`, `fec`, `mtu` and `admin_status` = `up` after the startup, the entries exist in CONFIG_DB, APPL_DB and STATE_DB and in `COUNTERS_PORT_NAME_MAP`, the lanes of the four children do not overlap (`lanes overlap: False`) and the aliases are unique. Step 5: the lanes, alias, index, speed, fec and mtu match `platform.json` and `port_config.ini` of the HWSKU, and the lanes of the four children together equal the lanes of the parent port. Step 6: T0: the VLAN member or PortChannel member of the child exists and ping works; T1: `192.0.2.0/31` is a connected route via `Ethernet0`, `INTERFACE|Ethernet0|192.0.2.1/31` exists in ConfigDB and ping works. After cleanup the mode is `1x800G[400G]`, the metadata of `Ethernet0` is the same as before the test and `Ethernet2`, `Ethernet4` and `Ethernet6` are removed.

### Test Case # 45 - Breakout children in PortChannel/MCLAG with VLAN exclusivity (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the base setup of the variant:
   - T0 (VLAN and PortChannel together): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24` (apply `SETUP-T0-VLAN`, 6.3); `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31` (apply `SETUP-T0-PO`, 6.3). Configure the matching PortChannel and VLAN on the peer. Check `ping -c 5 192.168.100.2` and `ping -c 5 192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
3. T0 only: add the second child to the PortChannel (add the matching second fanout link to the peer PortChannel, for example `channel-group 10 mode active` on the peer port) and verify the LACP state:
   - `sudo config portchannel member add PortChannel10 Ethernet4`; `sudo config interface startup PortChannel10`
   - `show interfaces portchannel` (`PortChannel10` `LACP(A)(Up)`, `Ethernet2(S)` and `Ethernet4(S)`)
   - `docker exec teamd teamdctl PortChannel10 state` (both ports `selected`, `runner` = `lacp`, `partner` present)
   - `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|PortChannel10|*"`; `redis-cli -n 6 KEYS "LAG_MEMBER_TABLE|PortChannel10|*"`
4. T0 only: check the exclusivity (each command must be rejected, with no change in the configuration):
   - `sudo config vlan member add 100 Ethernet2` (the child is a PortChannel member; expected message similar to `Ethernet2 is part of portchannel!`)
   - `sudo config portchannel member add PortChannel10 Ethernet0` (the child is a VLAN member of `Vlan100`)
   - `redis-cli -n 4 KEYS "VLAN_MEMBER|Vlan100|*"` (only `Ethernet0`); `redis-cli -n 4 KEYS "PORTCHANNEL_MEMBER|*"` (only `Ethernet2` and `Ethernet4`); `show vlan brief`; `show interfaces portchannel`; `ping -c 5 192.168.100.2`; `ping -c 5 192.0.2.0`.
5. T0 only: check the forwarding over both members:
   - `sonic-clear counters`; from the peer send several flows: `iperf3 -c 192.0.2.1 -u -P 8 -b 10M -t 10` (8 streams with different source ports; or several `ping -c 100 -s <size>` flows; the hash depends on the ASIC)
   - `show interfaces counters -i Ethernet2,Ethernet4` (TX and RX packets increase on both members)
   - Failover: `sudo config interface shutdown Ethernet4`; `show interfaces portchannel` (`Ethernet4(D)`, `Ethernet2(S)`); `ping -c 20 192.0.2.0` (reachable over `Ethernet2`); `sudo config interface startup Ethernet4`; wait 30 s; `show interfaces portchannel` (both `(S)`).
6. T0 only, MCLAG if the image supports it: `show feature status iccpd`; `docker ps | grep iccpd`; `mclagdctl dump state`; `mclagdctl dump portlist local` (`PortChannel10` listed). If the `iccpd` container is not present, record `MCLAG not supported` and skip.
7. T1 only: move `Ethernet0` from the routed interface to a routed PortChannel (configure the matching PortChannel `channel-group 20 mode active` and the peer IP on the peer):
   - `sudo config interface ip remove Ethernet0 192.0.2.1/31`
   - `sudo config portchannel add PortChannel20`; `sudo config portchannel member add PortChannel20 Ethernet0`; `sudo config interface startup PortChannel20`; `sudo config interface ip add PortChannel20 192.0.2.1/31`
   - `show interfaces portchannel` (`PortChannel20` `LACP(A)(Up)`, `Ethernet0(S)`); `docker exec teamd teamdctl PortChannel20 state`; `show ip route 192.0.2.0/31` (connected via `PortChannel20`); `ping -c 5 192.0.2.0`
   - Optional second member: `sudo config portchannel member add PortChannel20 Ethernet2` and verify `show interfaces portchannel` and `ping -c 5 192.0.2.0`.
   - If a command is rejected, record the message and `supported` or `not supported`.
8. Cleanup: T1 `sudo config interface ip remove PortChannel20 192.0.2.1/31`, `sudo config portchannel member del PortChannel20 Ethernet0` (and `Ethernet2` if added), `sudo config portchannel del PortChannel20`; T0 `sudo config interface ip remove Vlan100 192.168.100.1/24`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config interface ip remove PortChannel10 192.0.2.1/31`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel member del PortChannel10 Ethernet4`, `sudo config portchannel del PortChannel10`; `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `show interfaces portchannel` (no PortChannel left).

**Expected:** T0: `PortChannel10` has two members `Ethernet2` and `Ethernet4`, both `selected` and LACP `Up`; the VLAN member and the PortChannel member commands for a child that is already in the other group are rejected without a change of the configuration; traffic forwards over both members and continues over the remaining member when one member is shut down; MCLAG state is shown when supported or recorded as not supported. T1: the routed PortChannel `PortChannel20` with `Ethernet0` comes up, the connected route is via `PortChannel20` and ping works, or the CLI rejects the configuration with a clear message that is recorded as `not supported`. After cleanup the mode is `1x800G[400G]` and no PortChannel or VLAN remains.

### Test Case # 46 - Interface, neighbor and port statistics on breakout child (T0 and T1)
Steps 4 and 5 run on the sonic-mgmt controller in the `tests` folder; the other steps run on the DUT.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and the neighbor. `<PORT>` is the tested child and `<PEER_IP>` the peer:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; configure the BGP neighbor `192.0.2.0` as in the bgp case (6.18). `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>`.
3. Check the status and the statistics on the DUT:
   - `show interfaces status` (the four children and `<PORT>` `up/up`)
   - `show lldp table` (the neighbor of `<PORT>`); T1: `show ip bgp summary` (neighbor `Established`)
   - `portstat -i <PORT>`; `portstat -a`; `portstat -j | head -50`; `portstat -p 1`
   - Clear and check: `portstat -c`; wait 1 s; `portstat -i <PORT>` (counters near 0); `ping -c 100 -i 0.1 <PEER_IP>`; wait 15 s; `portstat -i <PORT>` (`RX_OK` and `TX_OK` increase by about 100; `RX_ERR`, `TX_ERR`, `RX_DRP`, `TX_DRP` are 0)
   - Tag handling: `portstat -c -t bk_tag`; `portstat -t bk_tag -i <PORT>`; `portstat -d -t bk_tag`; `portstat -D`
4. Run the statistics test and the interface test of the repository (`<TESTBED>`, `<DUT>` as in the other cases):
   - `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c portstat/test_portstat.py`
   - `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c test_interfaces.py`
   - Check `echo $?` and the number of `passed`, `failed` and `skipped` tests in each run.
5. Run the neighbor health test: `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c test_nbr_health.py`; check `echo $?` and that `test_neighbors_health` is `passed`.
6. Check the statistics after the tests: `show interfaces status`; `portstat -a` (the four children are listed, `STATE` = `U` for the children with a link); `show interfaces counters errors`; `show logging | grep -iE "ERR|CRIT" | grep -iE "Ethernet(0|2|4|6)" | tail -20`.
7. Cleanup: remove the BGP neighbor on T1 (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor 192.0.2.0 remote-as <PEER_ASN>"`); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** Step 3: all breakout children `up/up`, LLDP shows the neighbor, T1 BGP is `Established`; after `portstat -c` the counters of `<PORT>` are near 0 and rise by about the number of packets sent, with no errors or drops; the `-a`, `-j`, `-p` and tag options run without an exception. Step 4: `test_portstat.py` passes; `test_interfaces.py` passes or is skipped (see the note). Step 5: `test_neighbors_health` passes (neighbor BGP and interface state are correct). Step 6: no port errors and no new `ERR` or `CRIT` message for the children. After cleanup the mode is `1x800G[400G]`.

### Test Case # 47 - Interface, neighbor and port statistics on breakout child (T0 and T1)
Steps 4 and 5 run on the sonic-mgmt controller in the `tests` folder; the other steps run on the DUT.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and the neighbor. `<PORT>` is the tested child and `<PEER_IP>` the peer:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; configure the BGP neighbor `192.0.2.0` as in the bgp case (6.18). `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>`.
3. Check the status and the statistics on the DUT:
   - `show interfaces status` (the four children and `<PORT>` `up/up`)
   - `show lldp table` (the neighbor of `<PORT>`); T1: `show ip bgp summary` (neighbor `Established`)
   - `portstat -i <PORT>`; `portstat -a`; `portstat -j | head -50`; `portstat -p 1`
   - Clear and check: `portstat -c`; wait 1 s; `portstat -i <PORT>` (counters near 0); `ping -c 100 -i 0.1 <PEER_IP>`; wait 15 s; `portstat -i <PORT>` (`RX_OK` and `TX_OK` increase by about 100; `RX_ERR`, `TX_ERR`, `RX_DRP`, `TX_DRP` are 0)
   - Tag handling: `portstat -c -t bk_tag`; `portstat -t bk_tag -i <PORT>`; `portstat -d -t bk_tag`; `portstat -D`
4. Run the statistics test and the interface test of the repository (`<TESTBED>`, `<DUT>` as in the other cases):
   - `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c portstat/test_portstat.py`
   - `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c test_interfaces.py`
   - Check `echo $?` and the number of `passed`, `failed` and `skipped` tests in each run.
5. Run the neighbor health test: `./run_tests.sh -n <TESTBED> -d <DUT> -f testbed.yaml -i ../ansible/veos -u -c test_nbr_health.py`; check `echo $?` and that `test_neighbors_health` is `passed`.
6. Check the statistics after the tests: `show interfaces status`; `portstat -a` (the four children are listed, `STATE` = `U` for the children with a link); `show interfaces counters errors`; `show logging | grep -iE "ERR|CRIT" | grep -iE "Ethernet(0|2|4|6)" | tail -20`.
7. Cleanup: remove the BGP neighbor on T1 (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor 192.0.2.0 remote-as <PEER_ASN>"`); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`.

**Expected:** Step 3: all breakout children `up/up`, LLDP shows the neighbor, T1 BGP is `Established`; after `portstat -c` the counters of `<PORT>` are near 0 and rise by about the number of packets sent, with no errors or drops; the `-a`, `-j`, `-p` and tag options run without an exception. Step 4: `test_portstat.py` passes; `test_interfaces.py` passes or is skipped (see the note). Step 5: `test_neighbors_health` passes (neighbor BGP and interface state are correct). Step 6: no port errors and no new `ERR` or `CRIT` message for the children. After cleanup the mode is `1x800G[400G]`.

### Test Case # 48 - MAC learning, aging, move, flush and MAC metadata on breakout child (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`. Check the MAC metadata of the DUT and the MTU of the children: `redis-cli -n 4 HGET "DEVICE_METADATA|localhost" mac` (format `XX:XX:XX:XX:XX:XX`); `ip link show Ethernet0 | grep ether` (the port MAC equals the DUT MAC); `redis-cli -n 4 HGET "PORT|Ethernet0" mtu` (`9100`, repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`).
2. Configure the variant. `<PORT>` is the port where the MACs are learned and `<PORT2>` the second port used for the MAC move (the matching ports on the peer, `<PEER_IF>` and `<PEER_IF2>`, are in the same VLAN):
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config vlan member add -u 100 Ethernet4`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `Ethernet0`, `<PORT2>` = `Ethernet4`, `<VLAN>` = `Vlan100`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3, as a VLAN member): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config vlan add 100`, `sudo config vlan member add -u 100 PortChannel10`, `sudo config vlan member add -u 100 Ethernet4`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `PortChannel10`, `<PORT2>` = `Ethernet4`, `<VLAN>` = `Vlan100`.
   - Check `ping -c 5 192.168.100.2`; `show vlan brief`.
3. Clear the FDB and learn 10 source MACs on `<PORT>`:
   - `sonic-clear fdb all`; `show mac` (no entry)
   - On the peer (a Linux host or the PTF container, scapy installed), send 10 frames with different source MACs from `<PEER_IF>`:

     ```text
     sudo python3 -c "from scapy.all import *; [sendp(Ether(src='00:11:22:33:44:%02x'%i, dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, hwsrc='00:11:22:33:44:%02x'%i, psrc='192.168.100.%d'%(100+i), pdst='192.168.100.1'), iface='<PEER_IF>', verbose=0) for i in range(1,11)]"
     ```

   - `show mac | grep -c "00:11:22:33:44"` (10); `show mac | grep "00:11:22:33:44" | head -3` (port = `<PORT>`, VLAN = 100, type `Dynamic`)
   - `redis-cli -n 6 KEYS "FDB_TABLE|Vlan100:*"`; `redis-cli -n 6 HGETALL "FDB_TABLE|Vlan100:00:11:22:33:44:01"` (`port` = `<PORT>`)
4. Move one MAC to `<PORT2>`: send the frame with the source MAC `00:11:22:33:44:01` from `<PEER_IF2>` (same command as step 3 with `iface='<PEER_IF2>'` and `range(1,2)`); `show mac | grep "00:11:22:33:44:01"` (port = `<PORT2>`); `show mac | grep -c "00:11:22:33:44"` (still 10).
5. Check the aging: `sudo config mac aging_time 60`; `show mac aging-time`; wait 70 s (up to 130 s, the hardware aging can take up to twice the time); `show mac | grep -c "00:11:22:33:44"` (0). Restore the default: `sudo config mac aging_time 600`.
6. Learn the MACs again (step 3 command) and flush the port: `sonic-clear fdb port <PORT>`; `show mac | grep "00:11:22:33:44"` (no entry on `<PORT>`; the MAC moved to `<PORT2>` in step 4 is learned again only if the frame is sent again); `sonic-clear fdb vlan Vlan100`; `show mac` (no entry).
7. Learn the MACs again on `<PORT>` and `<PORT2>`, then change the breakout mode with the FDB still present: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show interfaces breakout current-mode Ethernet0`; `show mac` (no entry for the removed `Ethernet0`, `Ethernet2`, `Ethernet4`, `Ethernet6` or `PortChannel10`); `redis-cli -n 6 KEYS "FDB_TABLE|*"`; `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*" | wc -l`; `show logging | grep -iE "fdb|mac" | tail -20`.
8. T1 routed variant (use this instead of steps 2 to 7): apply `SETUP-T1` (6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`.
   - `show mac` (no entry for `Ethernet0`); `show arp` (the peer `192.0.2.0` on `Ethernet0`); `redis-cli -n 6 KEYS "FDB_TABLE|*"` (none for `Ethernet0`)
   - `sudo config vlan add 200`; `sudo config vlan member add -u 200 Ethernet2`; send the frames with the 10 source MACs from the peer port of `Ethernet2` into VLAN 200 (step 3 command with `iface='<PEER_IF>'` of `Ethernet2`); `show mac` (10 MACs on `Ethernet2` in VLAN 200 and none on `Ethernet0`)
   - `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show mac` (no entry for `Ethernet2`); `show arp` (no stale entry for `192.0.2.0` and `Ethernet0`); `redis-cli -n 6 KEYS "FDB_TABLE|*"`
9. Cleanup: `sudo config mac aging_time 600`; remove the VLAN/PortChannel/IP that is still configured (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del <vlan_id> <port>`, `sudo config vlan del <vlan_id>`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 HGET "DEVICE_METADATA|localhost" mac` (unchanged); `redis-cli -n 4 HGET "PORT|Ethernet0" mtu` (`9100`).

**Expected:** Step 1: the DUT MAC is valid, the child MAC equals the DUT MAC and the MTU is `9100`. Step 3: the 10 MACs are learned on `<PORT>` in VLAN 100 (`show mac` and `FDB_TABLE` in STATE_DB). Step 4: the moved MAC is shown on `<PORT2>` and the total stays 10. Step 5: all entries age out after the aging time. Step 6: `sonic-clear fdb port` removes only the entries of `<PORT>`, and `sonic-clear fdb vlan` removes the rest. Step 7: after the mode change no FDB entry (in `show mac`, STATE_DB or ASIC_DB) refers to a removed port. Step 8 (T1): no L2 FDB on the routed `Ethernet0`, the ARP entry for the peer is present, FDB only on `Ethernet2` in VLAN 200, and no stale ARP or FDB entry after the mode change. After cleanup the mode is `1x800G[400G]` and the aging time is `600`.

### Test Case # 49 - Reload, reboot, upgrade, container restart and factory reset with breakout child (T0 and T1)
Warning: steps 5 and 7 are disruptive. Run them in a maintenance window with console access to the DUT, because the management IP, the users and the files of the DUT can be reset. Steps with `ssh` and `scp` run on the sonic-mgmt controller; the state files are kept on the controller because `/tmp` is lost after a reboot and `/home` is deleted by a factory reset.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the breakout child and the neighbor. `<PEER_IP>` is the peer address:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; configure the BGP neighbor `192.0.2.0` as in the bgp case (6.18). `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>`.
3. Save the configuration and the baseline state. On the DUT: `sudo config save -y`; `grep -c "BREAKOUT_CFG" /etc/sonic/config_db.json`. On the controller (`<STEP>` = the name of the step; the same command is used after each step below):

   ```text
   ssh admin@<DUT_MGMT_IP> 'show interfaces breakout current-mode Ethernet0; redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"; show interfaces status | grep -E "Ethernet(0|2|4|6) "; show vlan brief; show interfaces portchannel; show ip interfaces; show ip bgp summary | grep -E "Established|Active|Idle|Connect"; ping -c 5 <PEER_IP> | grep -o "[0-9]*% packet loss"' > state_<STEP>.txt
   scp admin@<DUT_MGMT_IP>:/etc/sonic/config_db.json ./config_db_before.json
   ```

   Use `STEP` = `before` now. After each step run the same command with the step name and `diff state_before.txt state_<STEP>.txt` (the BGP uptime and the counters can differ, the mode, the children, the VLAN or PortChannel, the IP, the neighbor state and the loss must be the same).
4. Reload and reboot (the configuration is restored from `config_db.json`):
   - `sudo config reload -y`; wait until the containers are up (`docker ps`, `show system-health summary`); state check with `STEP` = `reload`.
   - `sudo reboot`; wait for the DUT (`ssh` works again, about 5 minutes); state check with `STEP` = `reboot`.
5. Upgrade (image dependent; use an image of the same family that supports dynamic port breakout): `show version`; `sonic-installer list`; `sudo sonic-installer install -y <IMAGE_URL_OR_PATH>`; `sonic-installer list` (`Next` is the new image); `sudo reboot`; wait for the DUT; `show version` (new version); state check with `STEP` = `upgrade`; `show logging | grep -i db_migrator | tail -10`.
6. Container restart/upgrade (image dependent): `docker images`; `sudo docker pull <REGISTRY>/<IMAGE>:<TAG>` (if a new container image is used); `sudo systemctl restart lldp` (or the container under test, for example `snmp`; avoid `swss` and `syncd`, which restart all ports); `docker ps`; state check with `STEP` = `container`.
7. Factory reset (run each flavor separately and restore the configuration between runs, see step 8):
   - `sudo reset-factory keep-all-config` (keep all configuration; logs and files are deleted)
   - `sudo reset-factory only-config` (the configuration is reset to factory default; logs and files are kept)
   - `sudo reset-factory keep-basic` (basic configuration kept; logs and files are deleted)
   - `sudo reset-factory` (the configuration is reset to factory default; logs and files are deleted)
   - After the DUT is back (use the console if SSH does not return): `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"`; `show interfaces status | grep -E "Ethernet(0|2|4|6) "`; `show vlan brief`; `show interfaces portchannel`; `show ip interfaces`; `ls /etc/sonic`; `docker ps`.
8. After a flavor that reset the configuration, restore the DUT and show that the breakout can be created again: recover the management access (console or `config load_minigraph -y`), `scp ./config_db_before.json admin@<DUT_MGMT_IP>:/tmp/config_db_before.json`; `sudo cp /tmp/config_db_before.json /etc/sonic/config_db.json`; `sudo config reload -y`; or repeat steps 1 and 2 from the factory default (`sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, startup of the children and the variant configuration); state check with `STEP` = `restored`; `ping -c 5 <PEER_IP>`.
9. Cleanup: if the image was upgraded, return to the original image: `sonic-installer list`; `sudo sonic-installer set-default <ORIGINAL_IMAGE>`; `sudo reboot`; remove the BGP neighbor on T1 (`vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor 192.0.2.0 remote-as <PEER_ASN>"`); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; delete `state_*.txt` and `config_db_before.json` on the controller.

**Expected:** Steps 4, 5 and 6 (reload, reboot, upgrade, container restart) and the `keep-all-config` flavor: the mode is still `4x200G[100G]`, `BREAKOUT_CFG|Ethernet0` is unchanged, `Ethernet0`, `Ethernet2`, `Ethernet4` and `Ethernet6` return to `up/up`, the VLAN member, PortChannel member or routed IP is restored, the T1 BGP neighbor is `Established`, `ping -c 5 <PEER_IP>` has 0% loss, and `diff` shows no difference in the state (the upgrade also keeps the breakout after the database migration). Step 7 with a reset of the configuration (`only-config`, `keep-basic` and the default flavor): the parent port is back to the default mode `1x800G[400G]`, no VLAN, PortChannel, IP or BGP neighbor of the test remains, `Ethernet2`, `Ethernet4` and `Ethernet6` do not exist, and the files are kept (`only-config`) or deleted (the others) as described. Step 8: after the restore the breakout mode is `4x200G[100G]` again and ping works. After cleanup the mode is `1x800G[400G]`.

### Test Case # 50 - VLAN sub-interface on breakout child, L3 forwarding and L2 isolation (T0 and T1)
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y`; verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the base setup of the variant and a sibling routed child (`Ethernet4`, used to show that the other children are unaffected). `<PARENT>` is the parent of the sub-interface, `<SUB>` = `<PARENT>.10`, `<PEER_IF>` the matching port on the peer and `<PEER_IF4>` the peer port of `Ethernet4`:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. `<PARENT>` = `Ethernet0`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PARENT>` = `PortChannel10` (a PortChannel member cannot have a sub-interface).
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. `<PARENT>` = `Ethernet0`.
   - Sibling (all variants): `sudo config interface ip add Ethernet4 172.16.4.1/31`; peer `<PEER_IF4>` `172.16.4.0/31`; `ping -c 5 172.16.4.0`. Start a background ping that runs during the test: `nohup ping -i 0.2 172.16.4.0 > /tmp/ping_sibling.txt 2>&1 &`.
3. Free the parent port or PortChannel for the sub-interface (the parent must not be a VLAN member and should have no IP):
   - T0 VLAN: `sudo config vlan member del 100 Ethernet0`; `show vlan brief` (`Ethernet0` is not in `Vlan100`)
   - T0 PortChannel: `sudo config interface ip remove PortChannel10 192.0.2.1/31`
   - T1: `sudo config interface ip remove Ethernet0 192.0.2.1/31`
4. Create the sub-interface on the DUT with VLAN 10 and IPv4/IPv6 addresses: `sudo config subinterface add <SUB> 10`; `sudo config interface ip add <SUB> 10.10.10.1/24`; `sudo config interface ip add <SUB> 2001:db8:10::1/64`; verify with `show subinterfaces status` (`<SUB>` `up/up`, VLAN 10), `redis-cli -n 4 HGETALL "VLAN_SUB_INTERFACE|<SUB>"`, `ip link show <SUB>`, `show ip interfaces`.
5. Create the matching sub-interface on the peer (Linux shell; on an Arista peer use `interface <PEER_IF>.10` with `encapsulation dot1q vlan 10` and the same addresses): `sudo ip link add link <PEER_IF> name <PEER_IF>.10 type vlan id 10`; `sudo ip addr add 10.10.10.2/24 dev <PEER_IF>.10`; `sudo ip -6 addr add 2001:db8:10::2/64 dev <PEER_IF>.10`; `sudo ip link set <PEER_IF>.10 up`.
6. Verify the L3 forwarding and the VLAN tag: `ping -c 5 10.10.10.2`; `ping6 -c 5 2001:db8:10::2`; `ping -c 5 -s 1400 10.10.10.2`; on the peer `sudo tcpdump -nn -e -i <PEER_IF> -c 5 vlan 10 and icmp` (frames with `vlan 10`); `show interfaces counters -i <PARENT>`; `redis-cli -n 4 HGETALL "VLAN_SUB_INTERFACE|<SUB>"`.
7. Verify that an untagged frame is not routed and that the sub-port has no L2 forwarding:
   - Untagged: on the peer `sudo arping -I <PEER_IF> -c 3 10.10.10.1` (no reply).
   - L2: on the peer capture on the sibling link `sudo tcpdump -nn -e -i <PEER_IF4> -c 5 -w /tmp/sibling.pcap vlan 10` and send VLAN 10 broadcast frames from the sub-interface `sudo arping -I <PEER_IF>.10 -c 5 10.10.10.200`; no frame with `vlan 10` appears on the sibling link, and `portstat -i Ethernet4` shows no VLAN 10 traffic.
8. Verify the admin status and the MTU: `sudo config interface shutdown <SUB>`; `show subinterfaces status` (`<SUB>` admin `down`); `ping -c 3 10.10.10.2` (fails); `ping -c 3 172.16.4.0` (sibling still works); `sudo config interface startup <SUB>`; wait 10 s; `ping -c 5 10.10.10.2` (works); `ip link show <SUB> | grep mtu` equals `ip link show <PARENT> | grep mtu` (the MTU of the sub-interface is inherited from the parent, for example `9100`).
9. Change the breakout mode with the sub-interface still configured, and record the result: `sudo config interface breakout Ethernet0 '2x400G[200G]' -y` (without `-f`); `echo $?`; `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 KEYS "VLAN_SUB_INTERFACE|*"`. If the change is rejected, the mode stays `4x200G[100G]` and the sub-interface remains. If it is accepted, no `VLAN_SUB_INTERFACE|<SUB>` entry remains for a removed parent port; re-apply `4x200G[100G]` and the sub-interface before continuing.
10. Remove the sub-interface first and then change the breakout mode: `sudo config interface ip remove <SUB> 10.10.10.1/24`; `sudo config interface ip remove <SUB> 2001:db8:10::1/64`; `sudo config subinterface del <SUB>` (if the command is not available in the image: `redis-cli -n 4 DEL "VLAN_SUB_INTERFACE|<SUB>"`); `show subinterfaces status` (no `<SUB>`); `redis-cli -n 4 KEYS "VLAN_SUB_INTERFACE|*"` (no entry); `ip link show <SUB>` (does not exist); peer: `sudo ip link del <PEER_IF>.10`; `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show interfaces breakout current-mode Ethernet0`; `show interfaces status`.
11. Cleanup: `pkill -SIGINT ping`; `tail -3 /tmp/ping_sibling.txt` (loss summary); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config interface ip remove Ethernet4 172.16.4.1/31`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm /tmp/ping_sibling.txt /tmp/sibling.pcap`.

**Expected:** Step 4: `<SUB>` is `up/up` with VLAN 10 in `show subinterfaces status` and `VLAN_SUB_INTERFACE|<SUB>` exists in ConfigDB. Step 6: IPv4, IPv6 and the 1400-byte ping have 0% loss and the frames on the wire carry the VLAN 10 tag. Step 7: the untagged ARP gets no reply and no VLAN 10 frame is forwarded to the sibling link (the sub-port is routed only). Step 8: with `<SUB>` shut down ping fails and the sibling ping still works; after `startup` ping works; the MTU of `<SUB>` equals the MTU of `<PARENT>`. Step 9: the breakout change is rejected or leaves no stale `VLAN_SUB_INTERFACE` entry. Step 10: after the sub-interface removal the breakout change succeeds, and no `<SUB>` remains in the DB or in the kernel. Throughout, the sibling ping (`Ethernet4`) is not interrupted (0% loss, apart from the first packet). After cleanup the mode is `1x800G[400G]`.


### Test Case # 51 - QoS/buffer on breakout child (T0 and T1)
1. Breakout the parent port and start the children: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); verify with `show interfaces breakout current-mode Ethernet0`.
2. Configure the breakout child and ping the peer:
   - T0 VLAN: `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `ping -c 5 192.168.100.2`. Tested child = `Ethernet0`.
   - T0 PortChannel: `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `ping -c 5 192.0.2.0`. Tested child = `Ethernet2`.
   - T1 routed: `sudo config interface ip add Ethernet0 192.0.2.1/31`; `ping -c 5 192.0.2.0`. Tested child = `Ethernet0`.
3. Configure and verify QoS/buffer/queue settings on the child (`<child>`):
   - Generate the defaults for the child (image dependent): `sudo config qos reload --ports <child>`.
   - Set a port setting: `sudo pfc config asymmetric on <child>`; `show pfc asymmetric <child>`.
   - Verify the entries: `redis-cli -n 4 KEYS "*|<child>|*"`, `redis-cli -n 4 HGETALL "PORT_QOS_MAP|<child>"`, `redis-cli -n 4 KEYS "BUFFER_PG|<child>|*"`, `redis-cli -n 4 KEYS "BUFFER_QUEUE|<child>|*"`.
   - Send marked traffic: `ping -Q 0x68 -c 20 <peer IP>` and check `show queue counters <child>` (the queue mapped to that DSCP increments).
   - Record the ASIC queue count: `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:*" | wc -l`.
4. Change the breakout mode: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show interfaces breakout current-mode Ethernet0`.
5. Verify old settings do not remain on removed ports (`Ethernet2` and `Ethernet6` no longer exist): `redis-cli -n 4 KEYS "*|Ethernet2|*"`, `redis-cli -n 4 KEYS "*|Ethernet6|*"`, `redis-cli -n 4 KEYS "PORT_QOS_MAP|Ethernet2"`, `show queue counters Ethernet2`, `show interfaces status`; compare `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:*" | wc -l` with the count from step 3 (no leftover queues of removed ports).
6. Configure and verify settings on the recreated children (`Ethernet0` 400G and `Ethernet4` 400G):
   - `sudo config interface startup Ethernet0`, `sudo config interface startup Ethernet4`
   - `sudo config qos reload --ports Ethernet0,Ethernet4` (image dependent)
   - `redis-cli -n 4 HGETALL "PORT_QOS_MAP|Ethernet0"`, `redis-cli -n 4 KEYS "BUFFER_PG|Ethernet0|*"`, `redis-cli -n 4 KEYS "BUFFER_QUEUE|Ethernet0|*"`
   - Re-add the L3 config of step 2 on the recreated child, then `ping -Q 0x68 -c 20 <peer IP>` and `show queue counters Ethernet0`.
7. Cleanup: remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`), `sudo pfc config asymmetric off Ethernet0`, restore `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`, then `sudo config qos reload` and `sudo config save -y`.

**Expected:** The child has PORT_QOS_MAP, BUFFER_PG and BUFFER_QUEUE entries and its queue counters increment for the marked traffic. After the mode change no QoS, buffer or queue entry in CONFIG_DB, no queue counter and no ASIC queue object remains for the removed ports (`Ethernet2`, `Ethernet6`). The recreated children get QoS/buffer entries generated for their new speed (400G), forward traffic, and their queue counters increment. After cleanup the mode is `1x800G[400G]` and the default QoS is restored.

### Test Case # 52 - Service health (monit, containers, procdockerstatsd) during breakout child flap (T0 and T1)
This case checks that a breakout child that is flapped 20 times (shutdown and startup) does not disturb the system services: no `monit` failure, no container restart, `procdockerstatsd` keeps exporting, and the neighbor recovers after each flap. All commands run on the DUT unless it is written otherwise. `<PORT>` is the flapped child and `<PEER_IP>` the neighbor.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the variant:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`. `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`. `<PORT>` = `Ethernet2`, `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; configure the BGP neighbor `192.0.2.0` as in the bgp case (6.18). `<PORT>` = `Ethernet0`, `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>` (T1 also `show ip bgp summary`, `Established`).
3. Baseline of the services (the container start time is used as the restart counter, because SONiC containers are restarted by `systemd`):

   ```text
   sudo monit summary | tee /tmp/monit_before.txt
   sudo monit status | head -40
   show feature status | tee /tmp/feature_before.txt
   show feature autorestart | tee /tmp/autorestart_before.txt
   docker ps --format '{{.Names}} {{.Status}}' | sort | tee /tmp/docker_before.txt
   docker inspect -f '{{.Name}} {{.State.StartedAt}}' $(docker ps -q) | sort | tee /tmp/started_before.txt
   docker exec lldp supervisorctl status
   docker exec lldp cat /etc/supervisor/critical_processes
   systemctl show procdockerstatsd -p ActiveState -p SubState
   redis-cli -n 6 KEYS "DOCKER_STATS|*" | wc -l
   redis-cli -n 6 KEYS "PROCESS_STATS|*" | wc -l
   redis-cli -n 6 HGETALL "PROCESS_STATS|<pid>" | tee /tmp/pstats_before.txt
   show system-health summary
   ```

   `<pid>` is a key from `redis-cli -n 6 KEYS "PROCESS_STATS|*" | head -1`. Start a background ping: `nohup ping -i 0.2 <PEER_IP> > /tmp/ping_flap.txt 2>&1 &`.
4. Flap `<PORT>` 20 times with a time stamp per cycle:

   ```text
   for i in $(seq 20); do
     echo "flap $i $(date -u +%FT%T)"
     sudo config interface shutdown <PORT>; sleep 3
     sudo config interface startup <PORT>; sleep 10
   done | tee /tmp/flap_loop.txt
   ```

   T1: after each flap (or at least after the last one) `show ip bgp summary` shows `Established`. T0 PortChannel: `show interfaces portchannel` shows `LACP(A)(Up)`. Wait 60 s after the loop.
5. Re-collect the services and compare with step 3:

   ```text
   sudo monit summary | tee /tmp/monit_after.txt
   sudo monit summary | grep -iE "not ok|fail|error|stopped|timeout|does not exist"
   show feature status | diff /tmp/feature_before.txt -
   show feature autorestart | diff /tmp/autorestart_before.txt -
   docker ps --format '{{.Names}} {{.Status}}' | sort | diff /tmp/docker_before.txt -
   docker inspect -f '{{.Name}} {{.State.StartedAt}}' $(docker ps -q) | sort | diff /tmp/started_before.txt -
   systemctl show procdockerstatsd -p ActiveState -p SubState
   redis-cli -n 6 KEYS "DOCKER_STATS|*" | wc -l
   redis-cli -n 6 KEYS "PROCESS_STATS|*" | wc -l
   redis-cli -n 6 HGETALL "PROCESS_STATS|<pid>" | diff /tmp/pstats_before.txt -
   show system-health summary
   sudo grep 'ERR monit' /var/log/syslog | tail -20
   show logging | grep -iE "monit|container_checker|critical_process|procdockerstatsd" | tail -30
   pkill -SIGINT ping; tail -3 /tmp/ping_flap.txt
   ```

   The `diff` of the process statistics shows refreshed values (for example the update time); the other `diff` commands and the `grep` for errors are empty. If `<pid>` no longer exists, take another key.
6. Check that the breakout and the neighbor are unchanged after the flaps: `show interfaces breakout current-mode Ethernet0` (`4x200G[100G]`); `redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"`; `show interfaces status | grep -E "Ethernet(0|2|4|6) "` (all four children `up/up`); T0 VLAN: `show vlan brief`; T0 PortChannel: `show interfaces portchannel`; T1: `show ip bgp summary`; `ping -c 5 <PEER_IP>`.
7. Cleanup: T1: `vtysh -c "configure terminal" -c "router bgp <DUT_ASN>" -c "no neighbor 192.0.2.0 remote-as <PEER_ASN>"`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout); `rm -f /tmp/*_before.txt /tmp/*_after.txt /tmp/ping_flap.txt /tmp/flap_loop.txt`.

**Expected:** After the 20 flaps all `monit` services are OK (the `grep` for errors has no output), the containers are `Up` with an unchanged start time, `show feature status` and `show feature autorestart` are unchanged, `procdockerstatsd` is `active` and `running`, `DOCKER_STATS` and `PROCESS_STATS` have entries and their values are refreshed, `show system-health summary` is `OK`, and `monit` and `container_checker` log no alert. The ping recovers after every flap; T1: BGP re-establishes after every flap; T0 PortChannel: LACP returns to `Up`. Step 6: the breakout mode stays `4x200G[100G]`, the four children are `up/up` and the VLAN member, PortChannel member or BGP neighbor is unchanged. After cleanup the mode is `1x800G[400G]`.

### Test Case # 53 - SRv6 uN SID, static route and dataplane forwarding through a breakout child (T0 and T1)
This case checks the SRv6 uN SID configuration and the forwarding of an SRv6 packet (uSID shift) out of a breakout child. All commands run on the DUT unless it is written otherwise. `<L3_IF>` is the interface of the variant (`Vlan100`, `PortChannel10` or `Ethernet0`), `<PORT>` the breakout child of the variant (`Ethernet0` or `Ethernet2`), `<PEER_IPV6>` the IPv6 address of the neighbor, `<PEER_IF>` the peer port of `<PORT>` and `<PEER_IF4>` the peer port of `Ethernet4` (the ingress child that sends the SRv6 packet). `<DUT_MAC>` is `ip link show Ethernet4 | grep link/ether`.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the variant (egress side) and the ingress child `Ethernet4`:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`, `sudo config interface ip add Vlan100 2001:db8:100::1/64`; `<PEER_IPV6>` = `2001:db8:100::2`, `<L3_IF>` = `Vlan100`, `<PORT>` = `Ethernet0`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`, `sudo config interface ip add PortChannel10 2001:db8:1::1/127`; `<PEER_IPV6>` = `2001:db8:1::`, `<L3_IF>` = `PortChannel10`, `<PORT>` = `Ethernet2`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`, `sudo config interface ip add Ethernet0 2001:db8:1::1/127`; `<PEER_IPV6>` = `2001:db8:1::`, `<L3_IF>` = `Ethernet0`, `<PORT>` = `Ethernet0`.
   - Ingress child (all variants): `sudo config interface ip add Ethernet4 172.16.4.1/31`, `sudo config interface ip add Ethernet4 2001:db8:4::1/127`; peer `<PEER_IF4>`: `2001:db8:4::`.
   - Check `ping6 -c 5 <PEER_IPV6>` and `ping6 -c 5 2001:db8:4::`.
3. Configure the locator and the uN SID (`test_srv6_static_config.py` `test_uN_config`) and check that they are programmed:

   ```text
   sonic-db-cli CONFIG_DB HSET "SRV6_MY_LOCATORS|loc1" prefix fcbb:bbbb:1:: func_len 0
   sonic-db-cli CONFIG_DB HSET "SRV6_MY_SIDS|loc1|fcbb:bbbb:1::/48" action uN decap_dscp_mode pipe
   sleep 5
   vtysh -c "show running-config" | grep -E "locator loc1|sid fcbb:bbbb:1::/48 locator loc1 behavior uN"
   sonic-db-cli APPL_DB hget "SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::" action
   redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY:*"
   ```

4. Configure the static routes (as in `test_srv6_dataplane.py` and `test_srv6_vlan_forwarding.py`): the route toward the next uSID `fcbb:bbbb:2::/48` through the variant and the blackhole route for the rest of the block:

   ```text
   sonic-db-cli CONFIG_DB HSET "STATIC_ROUTE|default|fcbb:bbbb:2::/48" nexthop <PEER_IPV6> ifname <L3_IF>
   sonic-db-cli CONFIG_DB HSET "STATIC_ROUTE|default|fcbb:bbbb::/32" blackhole true
   show ipv6 route fcbb:bbbb:2::/48
   show ipv6 route fcbb:bbbb::/32
   ```

   T0 VLAN only: enable the proxy ARP/NDP of the VLAN as `test_srv6_vlan_forwarding.py` does: `sudo config vlan proxy_arp 100 enabled`; `sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|Vlan100" proxy_arp` (`enabled`).
5. Forward an SRv6 packet from the ingress child to the variant (`test_srv6_dataplane` and `test_srv6_vlan_forwarding`). On the peer of `<PORT>` capture: `sudo tcpdump -nn -e -i <PEER_IF> -c 5 ip6 and dst fcbb:bbbb:2::`. On the peer of `Ethernet4` send 5 packets with the destination `fcbb:bbbb:1:2::` (uN SID `fcbb:bbbb:1::/48`, next uSID `2`):

   ```text
   sudo python3 -c "from scapy.all import *; sendp(Ether(dst='<DUT_MAC>')/IPv6(src='2001:db8:4::', dst='fcbb:bbbb:1:2::', hlim=64)/ICMPv6EchoRequest(), iface='<PEER_IF4>', count=5)"
   ```

   Then `show interfaces counters -i Ethernet4,<PORT>` (the RX counter of `Ethernet4` and the TX counter of `<PORT>` increase by 5). The optional SRH variant (`with_srh`) adds `IPv6ExtHdrSegmentRouting(addresses=['fcbb:bbbb:2::'], segleft=0)` after the IPv6 header.
6. Flap the egress child: `sudo config interface shutdown <PORT>`, wait 10 s, `show ipv6 route fcbb:bbbb:2::/48` (the route is inactive or not installed), repeat the traffic of step 5 (no packet on `<PEER_IF>`); `sudo config interface startup <PORT>`, wait 30 s (T0 PortChannel: wait for LACP), `ping6 -c 5 <PEER_IPV6>`, `show ipv6 route fcbb:bbbb:2::/48` (installed), repeat the traffic of step 5 (the packets are forwarded again). `redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY:*"` still lists the SID entry.
7. Persistency (`test_srv6_dataplane_after_config_reload`): `sudo config save -y`; `sudo config reload -y`; wait 180 s; `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6` if a child is down); `show interfaces breakout current-mode Ethernet0` (`4x200G[100G]`); repeat the checks of step 3 and the traffic of step 5.
8. Recreate the child with the SRv6 route configured: remove the L3 configuration of the variant (`sudo config interface ip remove <L3_IF> <ip>`, then the VLAN member or PortChannel member); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `show ipv6 route fcbb:bbbb:2::/48` (the route is not installed, the SID entry in step 3 stays); `redis-cli -n 4 KEYS "STATIC_ROUTE|default|fcbb:bbbb:*"` (both entries stay); `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`; `sudo config interface startup Ethernet0` (and `Ethernet2`, `Ethernet4`, `Ethernet6`); apply the variant of step 2 again; the route of step 4 is installed again and the traffic of step 5 is forwarded.
9. Cleanup: `sonic-db-cli CONFIG_DB DEL "SRV6_MY_SIDS|loc1|fcbb:bbbb:1::/48"`; `sonic-db-cli CONFIG_DB DEL "SRV6_MY_LOCATORS|loc1"`; `sonic-db-cli CONFIG_DB DEL "STATIC_ROUTE|default|fcbb:bbbb:2::/48"`; `sonic-db-cli CONFIG_DB DEL "STATIC_ROUTE|default|fcbb:bbbb::/32"`; T0 VLAN: `sonic-db-cli CONFIG_DB HDEL "VLAN_INTERFACE|Vlan100" proxy_arp`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config interface ip remove Ethernet4 172.16.4.1/31`, `sudo config interface ip remove Ethernet4 2001:db8:4::1/127`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout).

**Expected:** Step 3: FRR has `locator loc1` and `sid fcbb:bbbb:1::/48 locator loc1 behavior uN`, APPL_DB `SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::` has `action` `un`, and ASIC_DB has a `MY_SID_ENTRY`. Step 4: `fcbb:bbbb:2::/48` is installed with the nexthop `<PEER_IPV6>` on `<L3_IF>`. Step 5: the 5 packets arrive on `<PEER_IF>` with the destination `fcbb:bbbb:2::` (the uSID is shifted) and a hop limit lower by 1. Step 6: no forwarding while `<PORT>` is down, forwarding again after `startup`, and the SID entry is not removed. Step 7: after the reload the mode is `4x200G[100G]`, the SID and the routes are present and the traffic is forwarded. Step 8: the route is removed with the child and installed again after the child is recreated; the SID and the `STATIC_ROUTE` entries in ConfigDB remain. After cleanup the mode is `1x800G[400G]` and no `SRV6_*` or `STATIC_ROUTE|default|fcbb:*` entry remains.

### Test Case # 54 - MPLS pop, swap and push through breakout children (T1 and T0 PortChannel)
This case checks the MPLS label operations (pop, swap, push) with a breakout child as the ingress and another breakout child as the egress, as `tests/mpls/test_mpls.py` does with `src_port` and `dst_port`. `<SRC_IF>` is the ingress (`Ethernet0` for T1, `PortChannel10` for T0 PortChannel), `<PEER_IF>` the peer port of `Ethernet0`, `<PEER_IF4>` the peer port of the egress `Ethernet4`, and `<DUT_MAC>` is `ip link show Ethernet0 | grep link/ether`. `test_mpls.py` runs on `t1` only; for the T0 PortChannel variant the case is image dependent. A VLAN interface does not carry MPLS labels, so T0 VLAN is not applicable.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the variant and the egress child:
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `<SRC_IF>` = `Ethernet0`; `<SRC_PEER>` = `192.0.2.0`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet0`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `<SRC_IF>` = `PortChannel10`; `<SRC_PEER>` = `192.0.2.0`.
   - Egress child (all variants): `sudo config interface ip add Ethernet4 172.16.4.1/31`; peer `<PEER_IF4>` `172.16.4.0/31`; `<DST_PEER>` = `172.16.4.0`.
   - Check `ping -c 5 192.0.2.0` and `ping -c 5 172.16.4.0`.
3. Enable MPLS on both interfaces (`config interface mpls add` is the command of the repository test) and check it: `sudo config interface mpls add <SRC_IF>`; `sudo config interface mpls add Ethernet4`; `redis-cli -n 4 HGETALL "INTERFACE|Ethernet4"` (field `mpls` `enable`; for a PortChannel use `PORTCHANNEL_INTERFACE|PortChannel10`); `sysctl net.mpls.conf.Ethernet4.input` (`1`).
4. Pop (`test_pop_label`). Create the label routes in the SWSS container (the same JSON as `configs/label_pop_routes.j2`):

   ```text
   cat > /tmp/label_pop_routes.json <<'EOF'
   [
     {"LABEL_ROUTE_TABLE:1000001": {"nexthop": "<DST_PEER>", "ifname": "Ethernet4", "mpls_pop": "1", "weight": "1"}, "OP": "SET"},
     {"LABEL_ROUTE_TABLE:1000003": {"nexthop": "<SRC_PEER>", "ifname": "<SRC_IF>", "mpls_pop": "1", "weight": "1"}, "OP": "SET"}
   ]
   EOF
   docker exec -i swss swssconfig /dev/stdin < /tmp/label_pop_routes.json
   redis-cli -n 0 HGETALL "LABEL_ROUTE_TABLE:1000001"
   redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_INSEG_ENTRY:*"
   ```

   On the peer of `Ethernet4` capture `sudo tcpdump -nn -e -i <PEER_IF4> -c 3 icmp`; on the peer of `Ethernet0` send label 1000001:

   ```text
   sudo python3 -c "from scapy.all import *; sendp(Ether(dst='<DUT_MAC>')/MPLS(label=1000001, ttl=64)/IP(src='10.10.10.1', dst='10.10.10.2')/ICMP(), iface='<PEER_IF>', count=3)"
   ```

   The frames on `<PEER_IF4>` have no MPLS header (the label is popped). Remove the routes with the same file name pattern (`OP` `DEL` for `LABEL_ROUTE_TABLE:1000001` and `LABEL_ROUTE_TABLE:1000003`, as `configs/label_del_routes.j2`).
5. Swap (`test_swap_label`). Repeat step 4 with `"mpls_nh": "swap1000002"` and `"mpls_pop": "1"` in `LABEL_ROUTE_TABLE:1000001` (as `configs/label_swap_routes.j2`) and the same packet. The frames on `<PEER_IF4>` carry `MPLS label 1000002` with the TTL decremented by 1. Remove the routes.
6. Push (`test_push_label`). Create the IP route with a label in the SWSS container (as `configs/label_push_routes.j2`): `{"ROUTE_TABLE:192.168.0.1": {"nexthop": "<DST_PEER>", "ifname": "Ethernet4", "mpls_nh": "push1000001", "weight": "1"}, "OP": "SET"}` in `/tmp/label_push_routes.json`, `docker exec -i swss swssconfig /dev/stdin < /tmp/label_push_routes.json`. On the peer of `Ethernet0` send an IP packet: `sudo python3 -c "from scapy.all import *; sendp(Ether(dst='<DUT_MAC>')/IP(src='10.10.10.1', dst='192.168.0.1', ttl=64)/ICMP(), iface='<PEER_IF>', count=3)"`. The frames on `<PEER_IF4>` have `MPLS label 1000001` and the IP TTL is lower by 1. Remove the route (`ROUTE_TABLE:192.168.0.1` with `OP` `DEL`).
7. Flap the egress child with the swap route configured (repeat step 5 to create the route): `sudo config interface shutdown Ethernet4`, wait 10 s, repeat the packet (no frame on `<PEER_IF4>`); `redis-cli -n 0 HGETALL "LABEL_ROUTE_TABLE:1000001"` (the entry is still in APPL_DB); `sudo config interface startup Ethernet4`, wait 30 s, `ping -c 5 172.16.4.0`, repeat the packet (the swapped frames are forwarded again).
8. Recreate the egress child: remove the label routes (step 5 `DEL`); `sudo config interface mpls remove <SRC_IF>`; `sudo config interface mpls remove Ethernet4`; `sudo config interface ip remove Ethernet4 172.16.4.1/31`; change the breakout mode of the parent: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 KEYS "INTERFACE|Ethernet*"` (no entry with the field `mpls` for a removed child); restore `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, `sudo config interface startup` on the four children, and check that `redis-cli -n 4 HGETALL "INTERFACE|Ethernet4"` has no `mpls` field (MPLS is disabled again on the new children by default).
9. Cleanup: remove the label routes if they exist; `sudo config interface mpls remove <SRC_IF>`; `sudo config interface mpls remove Ethernet4`; remove the PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config interface ip remove Ethernet4 172.16.4.1/31`, `sudo config portchannel member del PortChannel10 Ethernet0`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm -f /tmp/label_*_routes.json`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout).

**Expected:** Step 3: `mpls` is `enable` on the ingress and the egress; step 4: `LABEL_ROUTE_TABLE:1000001` is in APPL_DB and an `INSEG_ENTRY` is in ASIC_DB, and the frame on `<PEER_IF4>` has no MPLS header; step 5: the frame has the label 1000002 and a TTL lower by 1; step 6: the frame has the label 1000001; step 7: no forwarding while `Ethernet4` is down, the APPL_DB entry stays, and the forwarding returns after `startup`; step 8: no stale `mpls` field for a removed child and the new children have MPLS disabled. After cleanup no `LABEL_ROUTE_TABLE` entry remains and the mode is `1x800G[400G]`.

### Test Case # 55 - VRF create, bind, isolation, attributes and unbind on a breakout child (T0 and T1)
This case checks VRF binding of a breakout child and of its VLAN or PortChannel (`TestVrfCreateAndBind`, `TestVrfNeigh`, `TestVrfIsolation`, `TestVrfUnbindIntf` and `TestVrfDeletion` of `test_vrf.py`, and `TestVrfAttrSrcMac` and `TestVrfAttrTTL` of `test_vrf_attr.py`). `<L3_IF>` is the interface bound to `Vrf1` (`Vlan100`, `PortChannel10` or `Ethernet0`), `<PEER_IF>` is the peer port of the variant, and `<PEER_IP>` the neighbor of the variant (`192.168.100.2` for T0 VLAN, `192.0.2.0` for T0 PortChannel and T1). `Ethernet4` is bound to `Vrf2` and `Ethernet6` is a second `Vrf1` child used for the TTL test.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Create the VRFs and bind the interfaces. The `bind` removes the IP addresses of the interface, so add them again after the bind:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`; `sudo config vrf add Vrf1`; `sudo config interface vrf bind Vlan100 Vrf1`; `sudo config interface ip add Vlan100 192.168.100.1/24`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`; `sudo config vrf add Vrf1`; `sudo config interface vrf bind PortChannel10 Vrf1`; `sudo config interface ip add PortChannel10 192.0.2.1/31`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config vrf add Vrf1`; `sudo config interface vrf bind Ethernet0 Vrf1`; `sudo config interface ip add Ethernet0 192.0.2.1/31`.
   - Second and third child (all variants): `sudo config vrf add Vrf2`; `sudo config interface vrf bind Ethernet4 Vrf2`; `sudo config interface ip add Ethernet4 172.16.4.1/31` (peer `172.16.4.0/31`); `sudo config interface vrf bind Ethernet6 Vrf1`; `sudo config interface ip add Ethernet6 172.16.6.1/31` (peer `172.16.6.0/31`).
3. Check the VRF objects (`TestVrfCreateAndBind`): `show vrf`; `ip link show Vrf1`; `ip link show <L3_IF> | grep master` (`master Vrf1`); `redis-cli -n 4 HGETALL "VRF|Vrf1"`; `redis-cli -n 0 KEYS "VRF_TABLE:*"` (`Vrf1`, `Vrf2`); `redis-cli -n 0 HGETALL "INTF_TABLE:<L3_IF>"` (`vrf_name` `Vrf1`); `redis-cli -n 1 KEYS "*VIRTUAL_ROUTER*"` (at least 3 entries: default, `Vrf1`, `Vrf2`); `show ip interfaces`.
4. Neighbors and routes in the VRF (`TestVrfNeigh`, `TestVrfFib`): `ping -c 5 -I Vrf1 <PEER_IP>`; `ping -c 5 -I Vrf2 172.16.4.0`; `ip neigh show vrf Vrf1`; `ping -c 3 <PEER_IP>` in the default VRF fails; add a route in `Vrf1`: `vtysh -c "configure terminal" -c "ip route 10.60.0.0/24 172.16.6.0 vrf Vrf1"`; `show ip route vrf Vrf1`; `show ip route vrf Vrf2`; T1: `show ip bgp vrf Vrf1 summary` if a BGP neighbor is configured in `Vrf1`.
5. Isolation (`TestVrfIsolation`): `ping -c 3 -I Vrf1 172.16.4.0` fails; `ping -c 3 -I Vrf2 <PEER_IP>` fails; `ip route show vrf Vrf1 | grep 172.16.4` has no output and `ip route show vrf Vrf2 | grep -E "192.0.2|192.168.100"` has no output.
6. Source MAC attribute (`TestVrfAttrSrcMac`): `sudo redis-cli -n 4 HSET "VRF|Vrf1" src_mac 00:12:34:56:78:9a`; `redis-cli -n 4 HGET "VRF|Vrf1" src_mac`; on the peer `sudo tcpdump -nn -e -i <PEER_IF> -c 3 icmp` and on the DUT `ping -c 3 -I Vrf1 <PEER_IP>`: the source MAC of the frames is `00:12:34:56:78:9a`; `ping -c 3 -I Vrf2 172.16.4.0` on `Ethernet4` still uses the default router MAC. Remove: `sudo redis-cli -n 4 HDEL "VRF|Vrf1" src_mac`.
7. TTL attribute (`TestVrfAttrTTL`): `sudo redis-cli -n 4 HSET "VRF|Vrf1" ttl_action drop`. On the peer of `Ethernet6` capture `sudo tcpdump -nn -i <PEER_IF6> -c 3 icmp`, on the peer of the variant send packets to the `Vrf1` route of step 4: `sudo python3 -c "from scapy.all import *; sendp(Ether(dst='<DUT_MAC>')/IP(src='<PEER_IP>', dst='10.60.0.1', ttl=1)/ICMP(), iface='<PEER_IF>', count=3)"` (no packet on `<PEER_IF6>`), then the same with `ttl=2` (3 packets with `ttl=1` on `<PEER_IF6>`). `sudo redis-cli -n 4 HSET "VRF|Vrf1" ttl_action forward`; send `ttl=1` again (the packets are forwarded on `<PEER_IF6>`). Remove: `sudo redis-cli -n 4 HDEL "VRF|Vrf1" ttl_action`.
8. Unbind and delete (`TestVrfUnbindIntf`, `TestVrfDeletion`): `sudo config interface vrf unbind <L3_IF>`; `show ip interfaces` (the IP address of `<L3_IF>` is flushed); `ip neigh show dev <L3_IF>` (no neighbor); `redis-cli -n 4 HGETALL "<INTERFACE_TABLE>|<L3_IF>"` has no `vrf_name` (`<INTERFACE_TABLE>` is `VLAN_INTERFACE`, `PORTCHANNEL_INTERFACE` or `INTERFACE`); `sudo config interface ip add <L3_IF> <ip>` (the same address as in step 2); `ping -c 5 <PEER_IP>` works in the default VRF; bind again: `sudo config interface vrf bind <L3_IF> Vrf1` and add the IP; `ping -c 5 -I Vrf1 <PEER_IP>` works. Delete `Vrf2`: `sudo config interface ip remove Ethernet4 172.16.4.1/31`; `sudo config interface vrf unbind Ethernet4`; `sudo config vrf del Vrf2`; `show vrf` (only `Vrf1`).
9. Breakout change with a bound child: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show interfaces breakout current-mode Ethernet0`; `redis-cli -n 4 KEYS "*INTERFACE|Ethernet0*"` (no entry with `vrf_name` for the removed child); `show vrf` (`Vrf1` still exists); `ip link show Vrf1`; restore `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, `sudo config interface startup` on the four children, and repeat steps 2 and 4 for the variant (the new child is in the default VRF until it is bound again).
10. Cleanup: `sudo config interface ip remove Ethernet6 172.16.6.1/31`; `sudo config interface vrf unbind Ethernet6`; `vtysh -c "configure terminal" -c "no ip route 10.60.0.0/24 172.16.6.0 vrf Vrf1"`; `sudo config interface vrf unbind <L3_IF>`; `sudo config vrf del Vrf1`; `sudo config vrf del Vrf2` (if it exists); remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `show vrf` (no `Vrf1` or `Vrf2`); restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout).

**Expected:** Step 3: `Vrf1` and `Vrf2` exist in the kernel, ConfigDB, APPL_DB and ASIC_DB, and `<L3_IF>` has `master Vrf1`. Step 4: the VRF ping works, the ping without `-I` in the default VRF fails, and the static route is only in `Vrf1`. Step 5: no reachability and no route between `Vrf1` and `Vrf2`. Step 6: the frames of `Vrf1` use the new source MAC and `Vrf2` does not. Step 7: `ttl=1` is dropped with `ttl_action drop`, `ttl=2` is forwarded, and `ttl=1` is forwarded with `forward`. Step 8: after `unbind` the IP address and the neighbors are flushed, ping works in the default VRF and after the new bind in `Vrf1`; `Vrf2` is deleted. Step 9: the removed child has no stale `vrf_name` entry and `Vrf1` remains. After cleanup no VRF remains and the mode is `1x800G[400G]`.


### Test Case # 56 - Management VRF enabled while breakout children carry traffic (T0 and T1)
`mgmt` VRF binds only the management port (`eth0`); the breakout children stay in the default VRF. This case checks that enabling and disabling the management VRF does not disturb the breakout children and that the breakout change does not disturb the management VRF (`tests/mvrf/test_mgmtvrf.py`). The management connection to the DUT is lost while the command runs: use the serial console or reconnect after the command. `<MGMT_GW>` is the gateway of `eth0` and `<MGMT_IP>` the IP address of `eth0`.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the variant:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; `<PEER_IP>` = `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `<PEER_IP>` = `192.0.2.0`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `<PEER_IP>` = `192.0.2.0`.
   - Check `ping -c 5 <PEER_IP>`; start a background ping: `nohup ping -i 0.2 <PEER_IP> > /tmp/ping_mvrf.txt 2>&1 &`; `sudo cp /etc/sonic/config_db.json /tmp/config_db.before_mvrf.json`.
3. Baseline: `show mgmt-vrf` (`ManagementVRF : Disabled`); `ip -br addr show eth0`; `ip route show default`; `ip link show Ethernet0 | grep master` (no `master`).
4. Enable the management VRF (run it in the background because the session is lost): `nohup sudo config vrf add mgmt > /tmp/mvrf_add.txt 2>&1 &`; reconnect after 30 s; `show mgmt-vrf`; `ip link show mgmt`; `ip link show eth0 | grep master` (`master mgmt`); `ip link show Ethernet0 | grep master` (no `master mgmt`); `sudo ip vrf exec mgmt ping -c 5 <MGMT_GW>`; `sudo ip vrf exec mgmt ip route show`.
5. Check that the data plane is not changed: `tail -3 /tmp/ping_mvrf.txt` (no loss during the change, apart from the first packets); `ping -c 5 <PEER_IP>` in the default VRF; `show interfaces status | grep -E "Ethernet(0|2|4|6) "` (the four children `up/up`); T1: `show ip bgp summary`; T0 PortChannel: `show interfaces portchannel`; `redis-cli -n 4 HGETALL "BREAKOUT_CFG|Ethernet0"`.
6. Check the management services through the management VRF (`TestMvrfInbound`, `TestMvrfOutbound`): from an external host `ping -c 5 <MGMT_IP>`, `ssh <USER>@<MGMT_IP>` (banner `OpenSSH_... Debian`), `snmpwalk -v2c -c <COMMUNITY> <MGMT_IP> sysName.0`; on the DUT `sudo ip vrf exec mgmt curl -sI http://<HTTP_SERVER>/` and the NTP status `sudo ip vrf exec mgmt ntpstat` (or `chronyc tracking`).
7. Change the breakout mode with the management VRF enabled: `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show interfaces breakout current-mode Ethernet0`; `show mgmt-vrf` (unchanged: `Enabled`, `eth0` still `master mgmt`); the SSH session stays; `sudo ip vrf exec mgmt ping -c 5 <MGMT_GW>`; restore `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, `sudo config interface startup` on the four children, and apply the variant of step 2 again; `ping -c 5 <PEER_IP>`.
8. Disable the management VRF: `nohup sudo config vrf del mgmt > /tmp/mvrf_del.txt 2>&1 &`; reconnect after 30 s; `show mgmt-vrf` (`ManagementVRF : Disabled`); `ip link show eth0 | grep master` (no `master`); `ping -c 5 <MGMT_GW>` works in the default VRF; `ping -c 5 <PEER_IP>`; `show interfaces status | grep -E "Ethernet(0|2|4|6) "`.
9. Cleanup: `pkill -SIGINT ping`; `tail -3 /tmp/ping_mvrf.txt`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm -f /tmp/ping_mvrf.txt /tmp/mvrf_add.txt /tmp/mvrf_del.txt /tmp/config_db.before_mvrf.json`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout).

**Expected:** Step 4: `show mgmt-vrf` has `ManagementVRF : Enabled`, `mgmt` is `<NOARP,MASTER,UP,LOWER_UP>` with `vrf table 5000`, and `eth0` and `lo-m` have `master mgmt`. Step 5: the ping to the neighbor has no loss, the four children stay `up/up`, the BGP session and the LACP stay up, and the breakout children are not in the `mgmt` VRF. Step 6: ping, SSH, SNMP, NTP and the HTTP access through `mgmt` work. Step 7: the breakout change does not change the management VRF and the management session. Step 8: `show mgmt-vrf` is `Disabled`, `eth0` has no `master` and the data plane works. After cleanup the mode is `1x800G[400G]`.

### Test Case # 57 - VXLAN tunnel, VLAN-VNI map and VNET decap on a breakout underlay (T0 and T1)
This case checks the VXLAN decapsulation and the VNET (VXLAN tunnel, VLAN to VNI map, VNET interface binding) when the underlay or the overlay port is a breakout child. `<LO_IP>` is the IPv4 address of `Loopback0` (`show ip interface | grep Loopback0`), `<DUT_MAC>` is `ip link show Ethernet4 | grep link/ether`, `<PEER_IF>` is the peer port of the variant, `<PEER_IF4>` the peer port of the underlay child `Ethernet4`. The overlay packets enter on `Ethernet4` (underlay) and leave on the variant (overlay).
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the base setup and the underlay child:
   - T0 VLAN (apply `SETUP-T0-VLAN`, 6.3): `sudo config vlan add 100`, `sudo config vlan member add -u 100 Ethernet0`, `sudo config interface ip add Vlan100 192.168.100.1/24`; overlay host `192.168.100.2`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet2`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; overlay host `192.0.2.0`; `<L3_IF>` = `PortChannel10`.
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; overlay host `192.0.2.0`; `<L3_IF>` = `Ethernet0`.
   - Underlay child (all variants): `sudo config interface ip add Ethernet4 172.16.4.1/31`; peer `<PEER_IF4>` `172.16.4.0/31`; `ping -c 5 172.16.4.0`.
3. Set the VXLAN UDP port in the SWSS container (`vxlan_switch.j2`): `echo '[{"SWITCH_TABLE:switch": {"vxlan_port": "4789"}, "OP": "SET"}]' > /tmp/vxlan.switch.json`; `docker cp /tmp/vxlan.switch.json swss:/vxlan.switch.json`; `docker exec swss sh -c "swssconfig /vxlan.switch.json"`; `sleep 3`.
4. T0 VLAN: VXLAN tunnel and VLAN to VNI map (`test_vxlan_decap.py`). Create the files and load them (the VLAN ID 100 maps to the VNI 436, the base 336 plus the VLAN ID):

   ```text
   echo '{"VXLAN_TUNNEL": {"tlVxlan": {"src_ip": "<LO_IP>", "dst_ip": "8.8.8.8"}}}' > /tmp/vxlan_db.tunnel.json
   echo '{"VXLAN_TUNNEL_MAP": {"tlVxlan|mapVlan100": {"vni": 436, "vlan": "Vlan100"}}}' > /tmp/vxlan_db.maps.json
   sonic-cfggen -j /tmp/vxlan_db.tunnel.json --write-to-db
   sonic-cfggen -j /tmp/vxlan_db.maps.json --write-to-db
   redis-cli -n 4 HGETALL "VXLAN_TUNNEL|tlVxlan"
   redis-cli -n 4 HGETALL "VXLAN_TUNNEL_MAP|tlVxlan|mapVlan100"
   show vxlan interface
   redis-cli -n 1 KEYS "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL*"
   ```

   On the peer of `Ethernet0` capture `sudo tcpdump -nn -e -i <PEER_IF> -c 3 icmp`; on the peer of `Ethernet4` send a VXLAN packet (outer source `8.8.8.8`, VNI 436) that carries a frame for the host in `Vlan100`:

   ```text
   sudo python3 -c "from scapy.all import *; sendp(Ether(dst='<DUT_MAC>')/IP(src='8.8.8.8', dst='<LO_IP>')/UDP(sport=1234, dport=4789)/VXLAN(vni=436)/Ether(dst='<PEER_MAC>', src='00:11:22:33:44:55')/IP(src='192.168.100.50', dst='192.168.100.2')/ICMP(), iface='<PEER_IF4>', count=3)"
   ```

   `<PEER_MAC>` is the MAC of the peer port of `Ethernet0`. The frames on `<PEER_IF>` are the inner frames without the VXLAN header. Send the same packet with `vni=437` (no map): no frame on `<PEER_IF>`.
5. T0 PortChannel and T1: VNET with the interface bound to the VNET (`test_vnet_vxlan.py` and `test_vnet_decap.py`):

   ```text
   cat > /tmp/vnet_cfg.json <<'EOF'
   {"VXLAN_TUNNEL": {"tunnel_v4": {"src_ip": "<LO_IP>"}},
    "VNET": {"Vnet1": {"vxlan_tunnel": "tunnel_v4", "vni": "10001", "peer_list": ""}}}
   EOF
   sudo config load /tmp/vnet_cfg.json -y
   sudo config interface ip remove <L3_IF> 192.0.2.1/31
   redis-cli -n 4 HSET "<INTERFACE_TABLE>|<L3_IF>" vnet_name Vnet1
   sudo config interface ip add <L3_IF> 192.0.2.1/31
   redis-cli -n 4 HSET "NEIGH|<L3_IF>|192.0.2.0" family IPv4
   show vnet brief
   show vnet interfaces
   show vnet neighbors
   ```

   `<INTERFACE_TABLE>` is `INTERFACE` (T1) or `PORTCHANNEL_INTERFACE` (T0 PortChannel). On the peer of `<L3_IF>` capture `sudo tcpdump -nn -e -i <PEER_IF> -c 3 icmp`; on the peer of `Ethernet4` send a VXLAN packet to the DUT with VNI 10001 and the inner IPv4 packet for `192.0.2.0`:

   ```text
   sudo python3 -c "from scapy.all import *; sendp(Ether(dst='<DUT_MAC>')/IP(src='8.8.8.8', dst='<LO_IP>')/UDP(sport=1234, dport=4789)/VXLAN(vni=10001)/Ether(dst='<DUT_MAC>', src='00:11:22:33:44:55')/IP(src='10.99.0.1', dst='192.0.2.0')/ICMP(), iface='<PEER_IF4>', count=3)"
   ```

   The inner packet appears on `<PEER_IF>` without the VXLAN header (the repository VNET decap test runs only on Cisco-8000 and Mellanox ASICs, see the closing note).
6. T0 only, VNET route leak (`test_vnet_route_leak.py`, Mellanox): create a VNET route (JSON `VNET_ROUTE_TUNNEL_TABLE:Vnet1:100.1.1.1/32` with `endpoint` `200.0.0.1` loaded with `docker exec -i swss swssconfig /dev/stdin < /tmp/vnet_route.json`); `show vnet routes all`; for every BGP neighbor `show ip bgp neighbor <NEIGHBOR> advertised-routes` does not list `100.1.1.1/32` (no leak). Remove the route (`OP` `DEL`).
7. Flap the overlay child: `sudo config interface shutdown <PORT>` (`Ethernet0` for the VLAN and the T1 variant, `Ethernet2` for the PortChannel), wait 10 s, repeat the packet of step 4 or 5 (no frame on `<PEER_IF>`), `sudo config interface startup <PORT>`, wait 30 s, repeat the packet (the frames return); `redis-cli -n 4 HGETALL "VXLAN_TUNNEL|tlVxlan"` (or `tunnel_v4`) is unchanged.
8. Recreate the overlay child: remove the VNET binding and the IP (`sudo config interface ip remove <L3_IF> 192.0.2.1/31`, `redis-cli -n 4 DEL "<INTERFACE_TABLE>|<L3_IF>"`), or the VLAN member (T0 VLAN); `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `redis-cli -n 4 KEYS "VXLAN_TUNNEL*"` (tunnel and map stay), `show vxlan interface`; restore `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, `sudo config interface startup` on the four children, apply the variant of step 2 and the binding of step 5 again, and repeat the packet.
9. Cleanup: T0 VLAN: `redis-cli -n 4 DEL "VXLAN_TUNNEL_MAP|tlVxlan|mapVlan100"`, `redis-cli -n 4 DEL "VXLAN_TUNNEL|tlVxlan"`; T0 PortChannel and T1: `sudo config interface ip remove <L3_IF> 192.0.2.1/31`, `redis-cli -n 4 DEL "NEIGH|<L3_IF>|192.0.2.0"`, `redis-cli -n 4 HDEL "<INTERFACE_TABLE>|<L3_IF>" vnet_name`, `redis-cli -n 4 DEL "VNET|Vnet1"`, `redis-cli -n 4 DEL "VXLAN_TUNNEL|tunnel_v4"`; remove the VLAN/PortChannel/IP (`sudo config interface ip remove <interface> <ip>`, `sudo config interface ip remove Ethernet4 172.16.4.1/31`, `sudo config vlan member del 100 Ethernet0`, `sudo config vlan del 100`, `sudo config portchannel member del PortChannel10 Ethernet2`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm -f /tmp/vxlan_db.*.json /tmp/vxlan.switch.json /tmp/vnet_cfg.json /tmp/vnet_route.json`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout).

**Expected:** Step 4: the tunnel `tlVxlan` and the map `mapVlan100` are in ConfigDB, a tunnel object is in ASIC_DB, `show vxlan interface` lists the tunnel, the VNI 436 packet leaves `<PEER_IF>` as the inner frame and the VNI 437 packet is dropped. Step 5: `show vnet brief` lists `Vnet1` with VNI `10001`, the VNET interface and neighbor are shown, and the inner packet leaves on `<PEER_IF>`. Step 6: no VNET route is advertised to a BGP neighbor. Step 7: no forwarding while the child is down, forwarding after `startup`, and the tunnel and the VNET are unchanged. Step 8: the tunnel, the map and the VNET stay in ConfigDB when the child is recreated, and the traffic works after the variant and the binding are applied again. After cleanup no `VXLAN_TUNNEL`, `VXLAN_TUNNEL_MAP` or `VNET` entry remains and the mode is `1x800G[400G]`.

### Test Case # 58 - VXLAN overlay ECMP routes, underlay ECMP, BFD, CRM and route advertisement over breakout children (T1 and T0 PortChannel)
This case checks the VNET tunnel routes with two endpoints whose underlay paths are two breakout children, as in `test_vxlan_ecmp.py` (`Test_VxLAN_underlay_ecmp`, `Test_VxLAN_ecmp_create`). `Ethernet0` (or `PortChannel10` with the member `Ethernet0` for T0 PortChannel) and `Ethernet2` are the two underlay paths, `Ethernet4` is the overlay port in the VNET and `Ethernet6` is not used. The repository tests run on `t1` only (T0 PortChannel is image dependent; T0 VLAN is not applicable). `<DUT_MAC>` is `ip link show Ethernet4 | grep link/ether`; `<UL_IF>` is `Ethernet0` (T1) or `PortChannel10` (T0 PortChannel); `<LO_IP>` is the address of `Loopback0`.
1. Apply breakout mode on the DUT and the fanout: `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, then `sudo config interface startup Ethernet0` (repeat for `Ethernet2`, `Ethernet4`, `Ethernet6`); `sudo config interface breakout <FANOUT_PORT> '4x200G[100G]' -f -y` (on the fanout); verify with `show interfaces breakout current-mode Ethernet0` and `show interfaces status`.
2. Configure the underlay and the neighbors:
   - T1 routed (apply `SETUP-T1`, 6.3): `sudo config interface ip add Ethernet0 192.0.2.1/31`; `sudo config interface ip add Ethernet2 172.16.2.1/31`.
   - T0 PortChannel (apply `SETUP-T0-PO`, 6.3): `sudo config portchannel add PortChannel10`, `sudo config portchannel member add PortChannel10 Ethernet0`, `sudo config interface ip add PortChannel10 192.0.2.1/31`; `sudo config interface ip add Ethernet2 172.16.2.1/31`.
   - Peers: `192.0.2.0` on `<UL_IF>` and `172.16.2.0` on `Ethernet2`; `ping -c 5 192.0.2.0`, `ping -c 5 172.16.2.0`.
   - Underlay ECMP route to the endpoints `200.0.0.1` and `200.0.0.2`: `vtysh -c "configure terminal" -c "ip route 200.0.0.0/24 192.0.2.0" -c "ip route 200.0.0.0/24 172.16.2.0"`; `show ip route 200.0.0.1` (two nexthops).
3. Create the VXLAN tunnel and the VNET (the JSON of `create_vxlan_tunnel` and `create_vnets`) and bind `Ethernet4` to it:

   ```text
   cat > /tmp/vnet_ecmp.json <<'EOF'
   {"VXLAN_TUNNEL": {"tunnel_v4": {"src_ip": "<LO_IP>"}},
    "VNET": {"Vnet-0": {"vxlan_tunnel": "tunnel_v4", "vni": "10000", "peer_list": "", "advertise_prefix": "false", "overlay_dmac": "<OVERLAY_DMAC>"}}}
   EOF
   sudo config load /tmp/vnet_ecmp.json -y
   redis-cli -n 4 HSET "INTERFACE|Ethernet4" vnet_name Vnet-0
   sudo config interface ip add Ethernet4 172.16.4.1/31
   redis-cli -n 4 HSET "NEIGH|Ethernet4|172.16.4.0" family IPv4
   show vnet brief
   ```

4. Create the tunnel route with two endpoints in the SWSS container (JSON of `create_single_route`; add `"endpoint_monitor": "200.0.0.1,200.0.0.2"` for the BFD variant):

   ```text
   cat > /tmp/vnet_route.json <<'EOF'
   [{"VNET_ROUTE_TUNNEL_TABLE:Vnet-0:100.1.1.1/32": {"endpoint": "200.0.0.1,200.0.0.2"}, "OP": "SET"}]
   EOF
   docker exec -i swss swssconfig /dev/stdin < /tmp/vnet_route.json
   show vnet routes all
   redis-cli -n 0 KEYS "VNET_ROUTE_TUNNEL_TABLE:*"
   ```

5. Send overlay traffic with different source ports (`test_vxlan_random_hash`, `test_vxlan_varying_src_ip`) and capture the VXLAN packets on both underlay paths: on the peer of `Ethernet0` and the peer of `Ethernet2` `sudo tcpdump -nn -i <PEER_IF> -c 20 udp port 4789`; on the peer of `Ethernet4`:

   ```text
   sudo python3 -c "from scapy.all import *; [sendp(Ether(dst='<DUT_MAC>')/IP(src='172.16.4.0', dst='100.1.1.1')/UDP(sport=1000+i, dport=2000)/Raw(b'x'*20), iface='<PEER_IF4>') for i in range(100)]"
   ```

   The captured packets have the outer destination `200.0.0.1` or `200.0.0.2`, UDP port `4789`, VNI `10000` and the inner packet to `100.1.1.1`. Both underlay children carry packets (ECMP); `show interfaces counters -i Ethernet0,Ethernet2,Ethernet4`.
6. Underlay child flap (`test_vxlan_underlay_ecmp`, `test_underlay_portchannel_shutdown`, `test_vxlan_ecmp_switchover`): `sudo config interface shutdown Ethernet2`, wait 10 s, `show ip route 200.0.0.1` (one nexthop), repeat step 5 (all packets leave on `<UL_IF>`, no loss to the tunnel route: `show vnet routes all` is unchanged); `sudo config interface startup Ethernet2`, wait 30 s, `ping -c 5 172.16.2.0`, `show ip route 200.0.0.1` (two nexthops), repeat step 5 (both paths again). BFD variant: `show bfd summary` (the endpoint `200.0.0.2` is `Down` while the path is down and `Up` after it) and, for TSA (`test_vxlan_bfd_tsa.py`), `sudo TSA` and `sudo TSB`, `show vnet routes all` (the endpoint is withdrawn in TSA and restored with TSB).
7. Modify the route (`test_vxlan_modify_route_different_endpoint`, `test_vxlan_remove_all_route`): set the route with one endpoint (`"endpoint": "200.0.0.1"`, `OP` `SET`), repeat step 5 (all packets use `200.0.0.1`); remove it (`OP` `DEL`, `show vnet routes all` has no `100.1.1.1/32`, `redis-cli -n 0 KEYS "VNET_ROUTE_TUNNEL_TABLE:*"` is empty), repeat step 5 (no VXLAN packet); create it again.
8. CRM (`test_vxlan_crm.py`): `crm config polling interval 1`; `crm show resources all | grep -E "ipv4_route|nexthop_group|nexthop_group_member"` before and after the creation of 100 routes (a loop of `VNET_ROUTE_TUNNEL_TABLE:Vnet-0:100.1.<i>.1/32` with the endpoints of step 4 loaded with `swssconfig`); the `used` counters increase and return to the first values after the `DEL` of the routes.
9. Route advertisement (`test_vxlan_route_advertisement.py`, `test_vnet_bgp_route_precedence.py`, T1): add `"adv_prefix": "100.1.0.0/24"` and `"profile": "<PROFILE>"` to the route of step 4 (the profile with a BGP community is defined in `BGP_PROFILE_TABLE`); `vtysh -c "show ip bgp 100.1.0.0/24"`; `show ip bgp neighbor <NEIGHBOR> advertised-routes` (the prefix with the community); `sudo config interface shutdown <both underlay children>` (the endpoints are down: the advertised prefix is withdrawn with BFD) and `startup` (it returns).
10. Recreate the underlay child: `sudo config interface ip remove <UL_IF> 192.0.2.1/31` (T0 PortChannel: remove the member `sudo config portchannel member del PortChannel10 Ethernet0` and the PortChannel after the IP removal); `sudo config interface breakout Ethernet0 '2x400G[200G]' -f -y`; `show ip route 200.0.0.1` (one nexthop through `Ethernet2`); `show vnet routes all` (the route has the two endpoints); repeat step 5 (all packets use `Ethernet2`); restore `sudo config interface breakout Ethernet0 '4x200G[100G]' -f -y`, `sudo config interface startup` on the four children, apply the underlay of step 2 again, and repeat step 5 (both paths again).
11. Cleanup: `docker exec -i swss swssconfig /dev/stdin <<< '[{"VNET_ROUTE_TUNNEL_TABLE:Vnet-0:100.1.1.1/32": {}, "OP": "DEL"}]'`; `redis-cli -n 4 DEL "NEIGH|Ethernet4|172.16.4.0"`; `sudo config interface ip remove Ethernet4 172.16.4.1/31`; `redis-cli -n 4 HDEL "INTERFACE|Ethernet4" vnet_name`; `redis-cli -n 4 DEL "VNET|Vnet-0"`; `redis-cli -n 4 DEL "VXLAN_TUNNEL|tunnel_v4"`; `vtysh -c "configure terminal" -c "no ip route 200.0.0.0/24 192.0.2.0" -c "no ip route 200.0.0.0/24 172.16.2.0"`; remove the IPs and the PortChannel (`sudo config interface ip remove <UL_IF> 192.0.2.1/31`, `sudo config interface ip remove Ethernet2 172.16.2.1/31`, `sudo config portchannel member del PortChannel10 Ethernet0`, `sudo config portchannel del PortChannel10`); `sudo config interface breakout Ethernet0 '1x800G[400G]' -f -y`; `sudo config save -y`; `show interfaces breakout current-mode Ethernet0`; `rm -f /tmp/vnet_ecmp.json /tmp/vnet_route.json`; restore the fanout port: `sudo config interface breakout <FANOUT_PORT> '1x800G[400G]' -f -y` (on the fanout, use the original mode of the fanout).

**Expected:** Step 2: `show ip route 200.0.0.1` has two nexthops. Step 4: `show vnet routes all` lists `100.1.1.1/32` with the two endpoints. Step 5: VXLAN packets (UDP 4789, VNI 10000) leave on both underlay children and the sum of the packets on the two children equals the number sent. Step 6: with one underlay child down all the packets use the other child with no loss in the VNET route, and both children are used again after `startup`; with BFD the endpoint state follows the path. Step 7: the traffic follows the endpoint list and stops after the route is removed. Step 8: the CRM counters increase with the routes and return to the first values after the removal. Step 9: the prefix is advertised with the community while an endpoint is up and withdrawn when all endpoints are down. Step 10: while `Ethernet0` is removed all the traffic uses `Ethernet2` and the route is not removed, then ECMP returns after the child is recreated. After cleanup no `VNET`, `VXLAN_TUNNEL` or `VNET_ROUTE_TUNNEL_TABLE` entry remains and the mode is `1x800G[400G]`.

