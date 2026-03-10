# Bidirectional Forwarding Detection  (BFD) and OSPF   Interoperability

## Test Plan Revision History

| Rev  | Date       | Author            | Change Description           |
| ---- | ---------- | ----------------- | ---------------------------- |
| 1    | 05/03/2024 | Ghulam Bahoo | Initial Version of test plan |


## Introduction
### Objective
The purpose of this test is to evaluate the functionality of BFD in conjunction with the OSPF protocol on the SONIC switch DUT.
The test assumes all standard topology configurations, such as BGP neighborship, are pre-configured in the DUT and neighboring systems with no OSPF configurations. It is also assumed that neighboring devices are all SONiC devices.

### Scope
- Test BFD functionality in conjunction with OSPF protocol.

NOTE: OSPF Routing tests will run on all **Tier 0** and **Tier 1** topologies where neighboring devices are SONiC devices.

## Definition/Abbreviation
| **Term**   | **Meaning**                              |
| ---------- | ---------------------------------------- |
| BFD       | Bidirectional Forwarding Detection              |
| OSPF        | Open Shortest Path First                      |


### Related DUT CLI Commands
| Commands| Comment |
| ------- | ------- |
|Configuration commands|
| no router bgp | Disable BGP instance on DUT|
| router ospf | Instanciate OSPF instance on DUT|
| network x.x.x.x/x area x | Advertise network |
| bfd| Opens the BFD daemon configuration mode |
| peer x.x.x.x | Configure BFD peer |
|interface Ethernet x |Enters into interface configuration mode|
|ip ospf bfd| Listen for BFD events on peers created on the interface|
|Show commands|
|Show ip ospf|show all information about ospf |
|Show ip ospf neighbors |show all information about OSPF neighbors |
| Show bfd peer | Show all configured BFD peers information and current status |
## Test Structure
### Setup Configuration
The test assumes all standard configurations, such as BGP neighborship, are pre-configured in the DUT and neighboring systems with no OSPF configurations. It is also assumed that the neighboring devices are of SONiC type.

### Testbed Setup
The test will run on the t0 and t1 testbed:

#### Tier 0 (t0)
![Variation t0](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t0.png?raw=true)

#### Tier 1 (t1)
![Variation t1](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t1.png?raw=true)

## Test Cases
### Test Case \#0 - Test OSPF Neighborship Status
#### Test Objective
Verify whether OSPF neighbors are successfully created and appear with active status.

#### Test Steps
1. Clear existing default routing configurations (if non-OSPF configurations)
2. Establish OSPF session between DUT and neighbors
3. Verify OSPF neighbors are successfully established with active status
4. Restore original routing configurations (if non-OSPF configurations)

### Test Case \#1 - Test BFD Neighborship Status
#### Test Objective
Verify whether BFD neighborship is successfully created between DUT and its neighbors and whether they are sharing BFD packets.

#### Test Steps
1. Clear existing default routing configurations (if non-OSPF configurations)
2. Establish BFD session between DUT and neighbors
3. Verify BFD packets are being shared between BFD peers.
4. Restore original routing configurations (if non-OSPF configurations)

### Test Case \#2 - Test Dynamic Switching of Network Traffic
#### Test Objective
Verify whether BFD is reporting a link failure to OSPF and whether it is dynamically switching the network traffic to other available routes in response to a link failure.
#### Test Steps
1. Clear existing default routing configurations (if non-OSPF configurations)
2. Establish BFD session between DUT and neighbors
3. Simulate one link failure
4. Verify whether BFD is dynamically switching the network traffic to other available routes
5. Restore original routing configurations (if non-OSPF configurations)
