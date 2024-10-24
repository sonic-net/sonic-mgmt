# Birirectional Forwarding Detection (BFD)  Echo-Mode

## Test Plan Revision History

| Rev  | Date       | Author            | Change Description           |
| ---- | ---------- | ----------------- | ---------------------------- |
| 1    | 05/03/2024 | Ghulam Bahoo | Initial Version of test plan |

## Definition/Abbreviation

| **Term**   | **Meaning**                              |
| ---------- | ---------------------------------------- |
| BFD       | Bidirectional Forwarding Detection        |

## Introduction

### Objective
The purpose is to test functionality of BFD echo-mode on the SONIC switch DUT, closely resembling production environment. The test assumes all standard topology configurations, such as BGP neighborship, are pre-configured in the DUT and neighboring systems with no BFD configurations. It is also assumed that neighboring devices are all SONiC devices.


### Scope
- Test BFD Echo-Mode on SONiC DUT and neighboring devices

### Related DUT CLI Commands
| Commands| Comment |
| ------- | ------- |
|Configuration commands|
| router bgp | BGP configuration mode |
| neighbor x.x.x.x bfd | Enable bfd on BGP neighbor |
| bfd | Opens the BFD daemon configuration mode |
| peer x.x.x.x | Configure BFD peer |
| echo-mode |Enables or disables the echo transmission mode |
|Show commands|
| show ip bgp summary | Dispaly current BGP neighborship statistics |
| show bfd peer | Show all configured BFD peers information and current status |

## Test structure

### Testbed
The test will run on the following testbeds:
* t0
* t1
## Setup configuration
The test assumes all standard configurations, such as BGP neighborship, are pre-configured in the DUT and neighboring systems with no BFD configurations. It is also assumed that the neighboring devices are of SONiC type.

## Test

#### Test objective
Verify that BFD neighborship is established and BFD peers are sharing BFD peer information to each other.
#### Test steps
* Establish BFD session between BFD Peers.
* Enable BFD protocol on BFD peer interfaces.
* Verify BFD peer information.

### Test case # 2 – BFD Scale

#### Test objective
To validate BFD session establishment, state transitions (Up, Down, AdminDown), suspension, and scale testing with various scenarios including IPv4 and IPv6 addresses, single-hop, and multi-hop configurations, along with queue counter verification for BFD traffic.

#### Test steps

* Setup
   * Identify network interfaces and their respective neighbors.
   * Assign IP addresses to interfaces.
   * Initialize BFD on the testing tool or platform.

* Test Execution
   * Create BFD sessions between DUT and neighboring devices.
   * Validate BFD session states and transitions (e.g., Up, Down, AdminDown).
   * Perform specific state transitions for testing (e.g., suspension, restoration).
   Check and validate BFD queue counters or traffic statistics.
* Cleanup
   * Remove BFD sessions established during testing.
   * Release IP addresses assigned earlier.
   * Stop BFD on the testing tool or platform.


### Test case # 3 – BFD Multihop
#### Test objective
To validate BFD session establishment, state transitions (Up, Down, AdminDown), suspension, and scale testing with various scenarios including IPv4 and IPv6 addresses, single-hop, and multi-hop configurations, along with queue counter verification for BFD traffic.
#### Test steps

* Setup
   * Identify network interfaces and their respective neighbors.
   * Assign IP addresses to interfaces.
   * Initialize BFD on the testing tool or platform.

* Test Execution
   * Create BFD sessions between network devices.
   * Validate BFD session states and transitions (e.g., Up, Down, AdminDown).
   * Perform specific state transitions for testing (e.g., suspension, restoration).
   Check and validate BFD queue counters or traffic statistics.
* Cleanup
   * Remove BFD sessions established during testing.
   * Release IP addresses assigned earlier.
   * Stop BFD on the testing tool or platform.
## New Test cases
### Test case # 4 – BFD Echo Mode

#### Test objective
Verify that BFD neighborship is established and BFD peers are sharing BFD peer information to each other. Also varify the bidirectional reachability of a network path rather than just monitoring the path for faults.
#### Test steps
* Establish BFD session between existing bgp neighbors
* Enable BFD echo mode
* Verify BFD peer information
* Verify that BFD peers are sharing BFD echo packets
