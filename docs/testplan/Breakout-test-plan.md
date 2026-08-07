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

```md
## Test cases
### Test case # 1 - Verify 2x400G, L3 Interface Creation After Breakout on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT using sudo config interface breakout <InterfaceName> 2x400G[200G] -f
2. Configure IPv4 and IPv6 addresses on breakout interfaces and corresponding peer devices in T1 topology.
3. Verify bgp session, L3 traffic and L3 connectivity by pinging peer IPs from DUT on breakout interfaces
4. Check that all interfaces are operational and routing entries are correctly installed using show ip interface and show ip route.

### Test case # 2 - Breakout 4x200G, L3 Interface Creation After Breakout on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT using sudo config interface breakout <InterfaceName> 4x200G[100G] -f
2. Configure IPv4 and IPv6 addresses on all breakout interfaces.
3. Verify bgp session and L3 connectivity by performing ping from DUT on breakout interfaces.
4. Check that all interfaces are operational and routing entries are correctly installed using show ip interface and show ip route.

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

### Test case # 11 - LLDP Verification on Breakout Interface Random Interface  (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 on L3 interfaces
2. Ensure LLDP service is enabled on DUT
3. Check LLDP neighbors on breakout interfaces using show lldp neighbors
4. Verify breakout interfaces are correctly showing neighbor entries in LLDP output

### Test case # 12 - SNMP verification for breakout interfaces on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv6 and IPv4 to L3 interfaces
2. Ensure SNMP service is enabled on DUT
3. SNMP polling on breakout interfaces (e.g., interface status, speed, counters)
4. Verify breakout interfaces are correctly reflected in SNMP output

### Test case # 13 - gNMI telemetry verification for breakout interfaces on Random Interface (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv6 and IPv4 to L3 interfaces
2. Enable gNMI telemetry on DUT
3. Subscribe to interface state paths (e.g., interface status, counters)
4. Verify breakout interfaces are reported correctly with accurate operational data

### Test case # 14 - Breakout Interface Traffic Forwarding After Reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 15 - Breakout interface traffic forwarding after warm-reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using warm-reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 16 - Breakout interface traffic forwarding after fast-reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using fast-reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 17 - Breakout interface traffic forwarding after soft-reboot (IPv4 and IPv6)
1. Apply breakout configuration on DUT and configure IPv4 and IPv6 addresses on L3 interfaces
2. Verify initial L3 connectivity with peers using ping (IPv4) and ping6 (IPv6) and with L3 traffic.
3. Reboot DUT using soft-reboot
4. Verify breakout configuration, interface state, L3 traffic and L3 connectivity (IPv4 and IPv6) are restored after reboot using ping and ping6

### Test case # 18 - Interface counter validation on breakout ports
1. Apply breakout configuration and configure L3 interfaces
2. Send traffic between DUT and peers
3. Check interface counters using show interface counters
4. Verify packet counters increment correctly on respective breakout interfaces
