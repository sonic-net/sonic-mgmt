# OSPF Routing


- [Overview](#overview)
    - [Scope](#scope)
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
The purpose of this test is to verify the functionality of OSPF routing sessions on a SONIC switch DUT. This test aims to cover the routing functionality of both OSPF and OSPFv3.
The test assumes all standard topology configurations, such as BGP neighborship, are pre-configured in the DUT and neighboring systems with no OSPF configurations. It is also assumed that neighboring devices are all SONiC devices.

### Scope
The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is functional testing of OSPF on a SONIC system, testing OSPF neighborship status and dynamic routing changes in the event of a link failure.

NOTE: OSPF Routing tests will run on all **Tier 0** and **Tier 1** topologies where neighboring devices are SONiC devices.

### Related DUT CLI Commands
Existing BGP routing functionality is disabled using the following command inside the configure terminal of SONiC FRR (vtysh) mode.

    sonic(config)# no router bgp

OSPF configurations are be made using the following commands inside the configure terminal of SONiC FRR (vtysh) mode.
    
    #Enter OSPF configuration mode
    sonic(config)# router ospf

    #Configure OSPF neighbor network
    sonic(config-router)# network <IP-Address>/<Netmask> area <Area>


## Test Structure
### Setup Configuration
The test assumes all standard configurations, such as BGP neighborship, are pre-configured in the DUT and neighboring systems with no OSPF configurations. It is also assumed that the neighboring devices are of SONiC type.

### Testbed Setup
The test is avilable for all variations of **Tier 0** and **Tier 1** topologies available in the **sonic-mgmt** repository where the neighboring devices are SONiC devices.

#### Tier 0 (t0)
![Variation t0](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t0.png?raw=true)

#### Tier 1 (t1)
![Variation t1](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t1.png?raw=true)

## Test Cases
### Test Case \#0 - Test Neighborship Status
#### Test Objective
Verify whether OSPF neighbors are successfully created and appear with active status.

#### Test Steps
1. Establish OSPF sessions and neighbors
2. Verify OSPF neighbors are successfully established with active status
5. Clear OSPF session configurations ***[CLEANUP]***

### Test Case \#1 - Test Dynamic Routing Change
#### Test Objective
Verify whether OSPF routes are dynamically adjusted in the case of link failure.

#### Test Steps
1. Establish OSPF sessions and neighbors
2. Simuate link failure
4. Verify OSPF route has changed in reposnse to link failure
5. Clear OSPF session configurations ***[CLEANUP]***
