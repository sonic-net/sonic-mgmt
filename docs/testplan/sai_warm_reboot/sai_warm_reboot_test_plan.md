# Warm reboot Test Plan
- [Warm reboot Test Plan](#warm-reboot-test-plan)
  - [Overriew](#overriew)
  - [Scope](#scope)
  - [## Test bed](#-test-bed)
  - [## Test Structure](#-test-structure)
  - [## Test Methodology](#-test-methodology)
    - [Manipulate warm boot process](#manipulate-warm-boot-process)
  - [## Switch configuration Test cases](#-switch-configuration-test-cases)
    - [Case 1 - Sanity test for warm boot - happy path](#case-1---sanity-test-for-warm-boot---happy-path)
      - [Test objective](#test-objective)
      - [Test steps](#test-steps)
    - [Case 2 - Sanity test for warm boot - failed path, error code and restart interval](#case-2---sanity-test-for-warm-boot---failed-path-error-code-and-restart-interval)
      - [Test objective](#test-objective-1)
      - [Test steps](#test-steps-1)
    - [Case 3 - switch OID consistence](#case-3---switch-oid-consistence)
      - [Test objective](#test-objective-2)
      - [Test steps](#test-steps-2)
    - [Case 3 - switch mac learning disable](#case-3---switch-mac-learning-disable)
      - [Test objective](#test-objective-3)
      - [Test steps](#test-steps-3)
    - [Case 4 - IPv4 entry](#case-4---ipv4-entry)
      - [Test objective](#test-objective-4)
      - [Test steps](#test-steps-4)
    - [Case 5 - IPv6 entry](#case-5---ipv6-entry)
      - [Test objective](#test-objective-5)
      - [Test steps](#test-steps-5)
    - [Case 6 - IPv4 Next hop entry](#case-6---ipv4-next-hop-entry)
      - [Test objective](#test-objective-6)
      - [Test steps](#test-steps-6)
    - [Case 7 - IPv6 Next hop entry](#case-7---ipv6-next-hop-entry)
      - [Test objective](#test-objective-7)
      - [Test steps](#test-steps-7)
    - [Case 8 - IPv4 Neighbor entry](#case-8---ipv4-neighbor-entry)
      - [Test objective](#test-objective-8)
      - [Test steps](#test-steps-8)
    - [Case 9 - IPv6 Neighbor entry](#case-9---ipv6-neighbor-entry)
      - [Test objective](#test-objective-9)
      - [Test steps](#test-steps-9)
    - [Case 10 - Next hop group entry](#case-10---next-hop-group-entry)
      - [Test objective](#test-objective-10)
      - [Test steps](#test-steps-10)
    - [Case 11 - Next hop group  member entry](#case-11---next-hop-group--member-entry)
      - [Test objective](#test-objective-11)
      - [Test steps](#test-steps-11)
    - [Case 12 - Fdb entry](#case-12---fdb-entry)
      - [Test objective](#test-objective-12)
      - [Test steps](#test-steps-12)
    - [Case 13 - ACL table](#case-13---acl-table)
      - [Test objective](#test-objective-13)
      - [Test steps](#test-steps-13)
    - [Case 14 - SNAT entry](#case-14---snat-entry)
      - [Test steps](#test-steps-14)
    - [Case 15 - DNAT entry](#case-15---dnat-entry)
      - [Test steps](#test-steps-15)
    - [Case 16 - Read only attribute midifications with the default value](#case-16---read-only-attribute-midifications-with-the-default-value)
      - [Test objective](#test-objective-14)
      - [Test steps](#test-steps-16)
    - [Case 17 - Vlan state counter](#case-17---vlan-state-counter)
      - [Test objective](#test-objective-15)
      - [Test steps](#test-steps-17)
    - [Case 18 - RIF status counter](#case-18---rif-status-counter)
      - [Test objective](#test-objective-16)
      - [Test steps](#test-steps-18)
    - [Case 19 - VXLAN](#case-19---vxlan)
      - [Test objective](#test-objective-17)
      - [Test steps](#test-steps-19)
  - [Features Test cases in warm reboot scenarios](#features-test-cases-in-warm-reboot-scenarios)
    - [L3 Next hop](#l3-next-hop)
    - [L3 route](#l3-route)

## Overriew
The purpose of those tests is to verify the functionality of the warm reboot scenarios from SAI layer. Including the behavior verification, switch attribute and configuration, and packet transfer during warm boot.

## Scope
Those tests are targeted on verify the warm reboot from sai layer. With this purpose, those tests will focus on the SAI interface and the switch data which can be manipulate and check from SAI interfaces.

Sai tests will not independent from SONiC components, this will ensure the quality from fundmental layer, and shift tests to the left side of the spectrum.

## Test bed
---
Those test will be run on the test bed structure as below, the components are:
* PTF - running in a server which can connect to the target DUT
* SAI server - running on a dut
   ![Device_topology](img/Device_topology.jpg)
*p.s. cause the sai testing will not depends on any sonic components, then there will be no specifical topology(T0 T1 T2) for testing.*

## Test Structure
---
![Components](img/Component_topology.jpg)
Test structure the chart above, components are:
*PTF container - run test cases, and use a RPC client to invoke the SAI interfaces on DUT
*SAI Server container - run inside DUT/switch, which exposes the SAI SDK APIs from the libsai
*SAI-Qualify - Test controller, which is used to deploy and control the test running, meanwhile, manipulate the DUT on warm reboot.

## Test Methodology
---
Cause the warm reboot testing needs to reboot the dut, we need some approach to control and make differnt verification in the whole reboot process the

* For warmboot functionality verification, needs to control the dut with RPC APIs to make different configuration for shutdown and startup
* For switch behivor during warmboot, manipulate the Reboot stage by invoke the sai interface manually but not depends on the system services.
* Contol the warmboot process for checking the data/packet/status/attribute in different stage of the reboot, including before/in-middle/after of the warm reboot.
*  Validation will be devided into two kinds, switch status check (attribute and configurations), and switch behivor check(packet delivering). The packet delivering verification will be seperated into different features' tests.

### Manipulate warm boot process

1. Removal the system services during reboot, like swss, syncd, lldp, teamd etc. Then there will be no sonic components in the testing environment.
2. Start sai server docker, use saiserver to setup the shutdown mode and configuration trigger a restart.
   ```
   SAI_START_TYPE_WARM_BOOT
   SAI_WARM_BOOT_WRITE_FILE=/var/warmboot/sai-warmboot.bin
   ```
3. Stimulate a system restart
   ```
   kexec
   ```
4. Start sai server docker, use saiserver to setup the startup mode
   ```
   SAI_START_TYPE_WARM_BOOT
   SAI_WARM_BOOT_READ_FILE: /var/warmboot/sai-warmboot.bin
   ```

## Switch configuration Test cases
---
### Case 1 - Sanity test for warm boot - happy path
#### Test objective
Test the basic warm boot function, read and write file from the configured dump file.
#### Test steps
1. Start saiserver and switch
2. Config vlan port and fib
3. Packet forwarding check
4. Shutdown switch in warm mode
5. Packet forwarding check, result same as step 3
6. Start switch in warm mode
7. Packet forwarding check, result same as step 3

### Case 2 - Sanity test for warm boot - failed path, error code and restart interval
#### Test objective
Test the basic warm boot function, error happened when cannot read configured dump file.

#### Test steps
1. Start saiserver and switch
2. Config vlan port and fib
3. Packet forwarding check
4. Shutdown switch in warm mode
5. start saiserver with warm mode after kernel start
6. check the error code and SAI_SWITCH_ATTR_MIN_PLANNED_RESTART_INTERVAL

### Case 3 - switch OID consistence
#### Test objective
Check switch OID and basic switch attribtues keep the same during warmboot
#### Test steps
1. init switch, record the switch oid and atrts
2. warm reboot
3. check the oid and attr are the same

### Case 3 - switch mac learning disable
#### Test objective
Check switch mac learning disable 
#### Test steps
1. start switch
2. config vlan, flooding and mac learning confguration
3. warm reboot and disable the mac learning, simulate syncd restart process 
4. send packet on differernt port
5. check the fib after warmboot


### Case 4 - IPv4 entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported
**Memory threshold exceed might happen**
 (need different condition on can or cannot add when exceed the threshold before warm boot, max number might not be the actual amount memory can take)
#### Test steps
1. start switch check available_ipv4_route_entry
2. add max number of available_ipv4_route_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 5 - IPv6 entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **memory threshold exceed might happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number might not be the actual amount memory can take)
#### Test steps
1. start switch check available_ipv6_route_entry
2. add max number of available_ipv6_route_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check
### Case 6 - IPv4 Next hop entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen**(need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_ipv4_nexthop_entry
2. add max number of available_ipv4_nexthop_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 7 - IPv6 Next hop entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_ipv6_nexthop_entry
2. add max number of available_ipv6_nexthop_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 8 - IPv4 Neighbor entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_ipv4_neighbor_entry
2. add max number of available_ipv4_neighbor_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 9 - IPv6 Neighbor entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_ipv6_neighbor_entry
2. add max number of available_ipv6_neighbor_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check


### Case 10 - Next hop group entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_next_hop_group_entry
2. add max number of available_next_hop_group_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 11 - Next hop group  member entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_next_hop_group_member_entry
2. add max number of available_next_hop_group_member_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check


### Case 12 - Fdb entry
#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_fdb_entry
2. add max number of available_fdb_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 13 - ACL table

#### Test objective
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_acl_table
2. add max number of available_acl_table
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check


### Case 14 - SNAT entry
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_snat_entry
2. add max number of available_snat_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 15 - DNAT entry
Check the squence, content and the amount of the entry are the same.
Check maximum number supported, **table threshold exceed should not happen** (need different condition on can or cannot add when exceed the threshold before warm boot, max number should be the actual number in table)
#### Test steps
1. start switch check available_dnat_entry
2. add max number of available_dnat_entry
3. restart and check the status same as before
4. exceed max number, if can add success check status after restart, if cannot add, skip the check

### Case 16 - Read only attribute midifications with the default value
#### Test objective
Check the read_only_attribute keep the same
#### Test steps
Check the default value of those read_only attributes
1. SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS
2. SAI_SWITCH_ATTR_MAX_NUMBER_OF_SUPPORTED_PORTS
3. SAI_SWITCH_ATTR_PORT_LIST
4. SAI_SWITCH_ATTR_PORT_MAX_MTU
5. SAI_SWITCH_ATTR_CPU_PORT
6. SAI_SWITCH_ATTR_MAX_VIRTUAL_ROUTERS
7. SAI_SWITCH_ATTR_FDB_TABLE_SIZE
8. SAI_SWITCH_ATTR_L3_NEIGHBOR_TABLE_SIZE
9. SAI_SWITCH_ATTR_L3_ROUTE_TABLE_SIZE
10. SAI_SWITCH_ATTR_LAG_MEMBERS
11. SAI_SWITCH_ATTR_NUMBER_OF_LAGS
12. SAI_SWITCH_ATTR_ECMP_MEMBERS
13. SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS
14. SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES
15. SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES
16. SAI_SWITCH_ATTR_NUMBER_OF_QUEUES
17. SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES
18. SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY
19. SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY
20. SAI_SWITCH_ATTR_DEFAULT_VLAN_ID
21. SAI_SWITCH_ATTR_DEFAULT_STP_INST_ID
22. SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID
23. SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID
24. SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_TRAFFIC_CLASSES
25. qos_max_number_of_scheduler_group_hierarchy_levels
26. SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_SCHEDULER_GROUPS_
27. qos_max_number_of_scheduler_groups_per_hierarchy_level
28. SAI_SWITCH_ATTR_QOS_MAX_NUMBER_OF_CHILDS_
29. SAI_SWITCH_ATTR_TOTAL_BUFFER_SIZE
30. qos_max_number_of_childs_per_scheduler_group
31. SAI_SWITCH_ATTR_INGRESS_BUFFER_POOL_NUM
32. SAI_SWITCH_ATTR_EGRESS_BUFFER_POOL_NUM
33. SAI_SWITCH_ATTR_LAG_HASH
34. SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT
35. SAI_SWITCH_ATTR_MAX_ACL_RANGE_COUNT
36. SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP
37. SAI_SWITCH_ATTR_ACL_STAGE_INGRESS
38. SAI_SWITCH_ATTR_ACL_STAGE_EGRESS
    
### Case 17 - Vlan state counter
#### Test objective
Check vlan state counter configured as expected in warmboot and the counter is working during warmboot
#### Test steps
1. start switch set interval counter_refresh_interval
2. send packet before/mid/after warmboot
3. check the counter and the vlan stat (need add interval base on the interval)
   
### Case 18 - RIF status counter
#### Test objective
Check RIF state counter configured as expected in warmboot and the counter is working during warmboot
#### Test steps
1. start switch set interval counter_refresh_interval
2. send packet before/mid/after warmboot
3. check the counter and the vlan stat (need add interval base on the interval)

### Case 19 - VXLAN 
#### Test objective
Test the vxlan port and mac settings
#### Test steps
1. setup vxlan with overlay and underlay tunnel
2. setup encap and decap
3. create tunnel and other route
4. send packet on vxlan port and route mac
5. warm boot
6. check the behivor

## Features Test cases in warm reboot scenarios
For switch features tests, they will be sperated into test suite for each feature respectively.
The genertic approach to add the warm reboot test within existing features test is
- Setup the configuration and attribute as normal
- Run checks before shutdown
- Reboot and skip the setup process
- Run checks before start (Skip if the related setting need to be disabled in warmboot)
- Start switch with warm mode and skip the setup process
- Run checks after start 

Warmboot test suite/case will be added after feature suite/case available, the most recent features will be
### L3 Next hop
### L3 route