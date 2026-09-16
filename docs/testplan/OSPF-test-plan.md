# OSPF Routing


- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
    - [Related DUT CLI Commands](#related-dut-cli-commands)
- [Test Structure](#test-structure)
    - [Setup Configuration](#setup-configuration)
    - [Testbed Setup](#testbed-setup)
        - [Tier 0 (t0)](#tier-0-t0)
        - [Tier 1 (t1)](#tier-1-t1)
- [Test Cases](#test-cases)
    - [Test Case #0 \- Test Neighborship Status](#test-case-0---test-neighborship-status)
        - [Test Objective](#test-objective)
        - [Test Steps](#test-steps)
    - [Test Case #1 \- Test Dynamic Routing Change](#test-case-1---test-dynamic-routing-change)
        - [Test Objective](#test-objective-1)
        - [Test Steps](#test-steps-1)

## Overview
The purpose of this test is to verify the functionality of OSPF routing sessions on a SONiC switch DUT. This test aims to cover the routing functionality of both OSPF and OSPFv3.
The test assumes any default routing configurations (BGP or OSPF) to be pre-configured in the DUT and neighboring systems. It is assumed that neighboring devices are of SONiC or Arista EOS/vEOS/cEOS type.

### Scope
The test is targeting a running SONiC system with any default routing configuration (BGP or OSPF).
The purpose of the test is functional testing of OSPF on a SONiC system, testing OSPF neighborship status and dynamic routing changes in the event of a link failure and a newly learnt route.

### Testbed
The test is available for all variations of **Tier 0** and **Tier 1** topologies available in the **sonic-mgmt** repository comprising a single DUT and where the neighboring devices are of SONiC or Arista EOS/vEOS/cEOS type.

### Related DUT CLI Commands
Existing BGP routing functionality is disabled using the following command inside the configure terminal of SONiC FRR (vtysh) mode.

    sonic(config)# no router bgp

OSPF configurations are made using the following commands inside the configure terminal of SONiC FRR (vtysh) mode.

    #Enter OSPF configuration mode
    sonic(config)# router ospf

    #Configure OSPF neighbor network
    sonic(config-router)# network <IP-Address>/<Netmask> area <Area>


## Test Structure
### Setup Configuration
The test assumes any default routing configurations (BGP or OSPF) to be pre-configured in the DUT and neighboring systems. It is assumed that neighboring devices are SONiC or Arista EOS/vEOS/cEOS devices.

### Testbed Setup

#### Tier 0 (t0)
![Variation t0](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t0.png?raw=true)

- The DUT has 32 ports.
- Requires 4 VMs.
- The first 28 ports are connected to PTF docker simulating servers.
- The last 4 ports are connected to 4 VMs simulating T1 devices. The connection to each of the upstream T1 is configured as a port-channel with single link.

#### Tier 1 (t1)
![Variation t1](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t1.png?raw=true)

- The DUT has 32 ports.
- Requires 32 VMs.
- 16 of the ports are connected to 16 VMs simulating upstream T2 neighbors. The connections to upstream T2s are single link without port channel configured.
- 16 of the ports are connected to another 16 VMs simulating downstream T0 neighbors. No port-channel is configured for the links between DUT and T0 neighbors.

## Test Cases
### Test Case \#0 - Test Neighborship Status
#### Test Objective
Verify whether OSPF neighbors are successfully created and appear with active status.

#### Test Steps
1. Clear existing default routing configurations (if non-OSPF configurations)
2. Establish OSPF sessions and neighbors
3. Verify OSPF neighbors are successfully established with active status
4. Verify OSPF routes received are the same as previously configured routes (eg. BGP)
5. Restore original routing configurations (if non-OSPF configurations) ***[CLEANUP]***

### Test Case \#1 - Test Dynamic Routing Change
#### Test Objective
Verify whether OSPF routes are dynamically adjusted in the case of link failure and a newly learnt route.

#### Test Steps
1. Clear existing default routing configurations (if non-OSPF configurations)
2. Establish OSPF sessions and neighbors
3. Simulate one link failure
4. Verify whether the OSPF route has changed in response to link failure
5. Simulate a newly learnt OSPF route in a neighbor device (via PTF)
6. Verify if the newly learnt OSPF route is received by the DUT
7. Restore original routing configurations (if non-OSPF configurations) ***[CLEANUP]***
