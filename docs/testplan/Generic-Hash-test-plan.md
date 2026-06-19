# Generic Hash Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| SONiC Generic Hash | [[https://github.com/sonic-net/SONiC/doc/hash/hash-design.md](https://github.com/sonic-net/SONiC/blob/master/doc/hash/hash-design.md)]|


## 1. Overview
The hashing algorithm is used to make traffic-forwarding decisions for traffic exiting the switch.
It makes hashing decisions based on values in various packet fields, as well as on the hash seed value.
The packet fields used by the hashing algorithm varies by the configuration on the switch.

For ECMP, the hashing algorithm determines how incoming traffic is forwarded to the next-hop device.
For LAG, the hashing algorithm determines how traffic is placed onto the LAG member links to manage
bandwidth by evenly load-balancing traffic across the outgoing links.

Generic Hash is a feature which allows user to configure which hash fields suppose to be used by hashing algorithm by providing global switch hash configuration for ECMP and LAG.

The sonic-mgmt generic hash tests validate whether the hash configurations can be applied successfully and the hash behaviour is as expected.

## 2. Requirements

### 2.1 The Generic Hash feature supports the following functionality:
1. Ethernet packet hashing configuration with inner/outer IP frames
2. Global switch hash configuration for ECMP and LAG
3. Warm/Fast reboot

### 2.2 This feature will support the following commands:

1. config: set switch hash global configuration
2. show: display switch hash global configuration or capabilities

### 2.3 This feature will provide error handling for the next situations:

#### 2.3.1 Frontend
**This feature will provide error handling for the next situations:**
1. Invalid parameter value
#### 2.3.2 Backend
**This feature will provide error handling for the next situations:**
1. Missing parameters
2. Invalid parameter value
3. Parameter removal
4. Configuration removal

## 3. Scope

The test is to verify the hash configuration can be added/updated by the generic hash, and the ECMP and lag hash behavior will change according to the generic hash configurations.

### 3.1 Scale / Performance

No scale or performance test related

### 3.2 CLI commands

#### 3.2.1 Config
The following command can be used to configure generic hash:
```
config
|--- switch-hash
     |--- global
          |--- ecmp-hash ARGS
          |--- lag-hash ARGS
          |--- ecmp-hash-algorithm ARG
          |--- lag-hash-algorithm ARG
```

Examples:
The following command updates switch hash global:
```
config switch-hash global ecmp-hash \
'DST_MAC' \
'SRC_MAC' \
'ETHERTYPE' \
'IP_PROTOCOL' \
'DST_IP' \
'SRC_IP' \
'L4_DST_PORT' \
'L4_SRC_PORT' \
'INNER_DST_MAC' \
'INNER_SRC_MAC' \
'INNER_ETHERTYPE' \
'INNER_IP_PROTOCOL' \
'INNER_DST_IP' \
'INNER_SRC_IP' \
'INNER_L4_DST_PORT' \
'INNER_L4_SRC_PORT'
```
```
config switch-hash global lag-hash \
'DST_MAC' \
'SRC_MAC' \
'ETHERTYPE' \
'IP_PROTOCOL' \
'DST_IP' \
'SRC_IP' \
'L4_DST_PORT' \
'L4_SRC_PORT' \
'INNER_DST_MAC' \
'INNER_SRC_MAC' \
'INNER_ETHERTYPE' \
'INNER_IP_PROTOCOL' \
'INNER_DST_IP' \
'INNER_SRC_IP' \
'INNER_L4_DST_PORT' \
'INNER_L4_SRC_PORT'
```

#### 3.2.2 Show
The following command shows switch hash global configuration:
```
show
|--- switch-hash
     |--- global
     |--- capabilities
```

Example:
**The following command shows switch hash global configuration:**
```bash
root@sonic:/home/admin# show switch-hash global
+--------+-------------------------------------+
| Hash   | Configuration                       |
+========+=====================================+
| ECMP   | +--------------+-------------+      |
|        | | Hash Field   | Algorithm   |      |
|        | |--------------+-------------|      |
|        | | IP_PROTOCOL  | CRC_CCITT   |      |
|        | +--------------+-------------+      |
+--------+-------------------------------------+
| LAG    | +-------------------+-------------+ |
|        | | Hash Field        | Algorithm   | |
|        | |-------------------+-------------| |
|        | | INNER_IP_PROTOCOL | CRC         | |
|        | +-------------------+-------------+ |
+--------+-------------------------------------+
```

**The following command shows switch hash capabilities:**
```bash
root@sonic:/home/admin# show switch-hash capabilities
+--------+-------------------------------------+
| Hash   | Capabilities                        |
+========+=====================================+
| ECMP   | +-------------------+-------------+ |
|        | | Hash Field        | Algorithm   | |
|        | |-------------------+-------------| |
|        | | SRC_IP            | CRC         | |
|        | | DST_IP            | XOR         | |
|        | | INNER_SRC_IP      | RANDOM      | |
|        | | INNER_DST_IP      | CRC_CCITT   | |
|        | | VLAN_ID           |             | |
|        | | IP_PROTOCOL       |             | |
|        | | ETHERTYPE         |             | |
|        | | L4_SRC_PORT       |             | |
|        | | L4_DST_PORT       |             | |
|        | | SRC_MAC           |             | |
|        | | DST_MAC           |             | |
|        | | IN_PORT           |             | |
|        | | INNER_IP_PROTOCOL |             | |
|        | | INNER_ETHERTYPE   |             | |
|        | | INNER_L4_SRC_PORT |             | |
|        | | INNER_L4_DST_PORT |             | |
|        | | INNER_SRC_MAC     |             | |
|        | | INNER_DST_MAC     |             | |
|        | +-------------------+-------------+ |
+--------+-------------------------------------+
| LAG    | +-------------------+-------------+ |
|        | | Hash Field        | Algorithm   | |
|        | |-------------------+-------------| |
|        | | SRC_IP            | CRC         | |
|        | | DST_IP            | XOR         | |
|        | | INNER_SRC_IP      | RANDOM      | |
|        | | INNER_DST_IP      | CRC_CCITT   | |
|        | | VLAN_ID           |             | |
|        | | IP_PROTOCOL       |             | |
|        | | ETHERTYPE         |             | |
|        | | L4_SRC_PORT       |             | |
|        | | L4_DST_PORT       |             | |
|        | | SRC_MAC           |             | |
|        | | DST_MAC           |             | |
|        | | IN_PORT           |             | |
|        | | INNER_IP_PROTOCOL |             | |
|        | | INNER_ETHERTYPE   |             | |
|        | | INNER_L4_SRC_PORT |             | |
|        | | INNER_L4_DST_PORT |             | |
|        | | INNER_SRC_MAC     |             | |
|        | | INNER_DST_MAC     |             | |
|        | +-------------------+-------------+ |
+--------+-------------------------------------+
```

### 3.3 DUT related configuration in config_db

```
    "SWITCH_HASH": {
        "GLOBAL": {
            "ecmp_hash": [
                "IP_PROTOCOL"
            ],
            "ecmp_hash_algorithm": "CRC_CCITT",
            "lag_hash": [
                "INNER_IP_PROTOCOL"
            ],
            "lag_hash_algorithm": "CRC"
        }
    }
```
### 3.4 Supported topology
The test should support t0 and t1 topologies.

## 4. Test cases

| **No.** | **Test Case** | **Test Purpose** |
|----------|-------------------|----------|
| 1 | test_hash_capability | Verify the “show switch-hash capabilities” gets the supported hash fields.|
| 2 | test_ecmp_hash | Verify the basic functionality of ecmp hash with a single hash field|
| 3 | test_lag_hash | Verify the basic functionality of lag hash with a single hash field|
| 4 | test_ecmp_and_lag_hash | Verify the hash functionality with all ecmp and lag hash fields configured|
| 5 | test_nexthop_flap | Verify the ecmp hash functionality when there is nexthop flap|
| 6 | test_lag_member_flap | Verify the lag hash functionality when there is lag member flap|
| 7 | test_lag_member_remove_add| Verify the lag hash functionality after a lag member is removed and added back to a portchannel|
| 8 | test_reboot | Verify there is no hash configuration inconsistence before and after reload/reboot|
| 9 | test_backend_error_messages | Verify there are backend errors in syslog when the hash config is removed or updated with invalid values via redis cli|
| 10 | test_algorithm_config | Verify algorithm show and configuration via cli|

### Notes:
  1. The tested hash field in each test case is randomly selected from a pre-defined field list per asic type. Currently these fields are tested as default: 'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP'; In the test enhancement, there are 6 fields added: 'INNER_L4_SRC_PORT', 'INNER_L4_DST_PORT', 'INNER_IP_PROTOCOL', 'INNER_ETHERTYPE', 'INNER_SRC_MAC', 'INNER_DST_MAC', those fields would be updated into all the necessary test cases.
  2. The tested algorithm in each test case is randomly selected from 'CRC' and 'CRC_CCITT' for Mellanox switches, otherwise randomly selected from all the supported algorithms. For the other algorithms that Mellanox switches not fully supported, there would be cli test to cover them.
  3. All the test cases should be integrated to dualtor setup.
  4. DST_MAC, ETHERTYPE, VLAN_ID fields are only tested in lag hash test cases, because L2 traffic is needed to test these fields, and there is no ecmp hash when the traffic is fowarded in L2.
  5. IPv4 and IPv6 are covered in the test, but the versions(including the inner version when testing the inner fields) are randomly selected in the test cases.
  6. For the inner fields, three types of encapsulations are covered: IPinIP, VxLAN and NVGRE. For the VxLAN packet, the default port 4789 and a custom port 13330 are covered in the test.
  7. For the reboot test, reboot type is randomly selected from config reload, cold, warm and fast reboot.
  8. The random selections of algorithms, hash fields, ip versions, encapsulation types and reboot types can be controlled by pytest options. The user is able to set each of the option as 'random', 'all', or a specific value. Furthermore, for algorithms and hash fields option, the user is able to set a list of values separated by comma, such as CRC,CRC_CCITT.

### Test cases #1 - test_hash_capability
1. Get the supported hash fields via cli "show switch-hash capabilities"
2. Check the fields are as expected.

### Test cases #2 - test_ecmp_hash
1. The test is using the default links and routes in a t0/t1 testbed.
2. Randomly select a hash field and configure it to the ecmp hash list via cli "config switch-hash global ecmp-hash".
3. Randomly select an algorithm and configure it to the ecmp hash list via cli "config switch-hash global ecmp-hash-algorithm".
4. Configure the lag hash list to exclude the selected field to verify the lag hash configuration does not affect the hash result.
5. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination via multiple nexthops.
6. Check the traffic is balanced over the nexthops.
7. If the uplinks are portchannels with multiple members, check the traffic is not balanced over the members.

### Test cases #3 - test_lag_hash
1. The test is using the default links and routes in a t0/t1 testbed, and only runs on setups which have multi-member portchannel uplinks.
2. Randomly select a hash field and configure it to the lag hash list via cli "config switch-hash global lag-hash".
3. Randomly select an algorithm and configure it to the lag hash list via cli "config switch-hash global lag-hash-algorithm".
4. Configure the ecmp hash list to exclude the selected field to verify the ecmp hash configuration does not affect the hash result.
5. If the hash field is DST_MAC, ETHERTYPE or VLAN_ID, take the steps 5-7, otherwise skip them.
6. Choose one downlink interface and one uplink interface, remove all ip/ipv6 addresses on them.
7. Remove the downlink interface from the existing vlan if it is t0 topology.
8. For the DST_MAC, ETHERTYPE fields, add the chosen interfaces to a same vlan; For VLAN_ID field, add the interfaces to multiple vlans.
9. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination via the portchannels.
10. Check the traffic is forwarded through only one portchannel and is balanced over the members.

### Test cases #4 - test_ecmp_and_lag_hash
1. The test is using the default links and routes in a t0/t1 testbed.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field and algorithm to test.
4. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
5. Check the traffc is balanced over all the uplink physical ports.

### Test cases #5 - test_nexthop_flap
1. The test is using the default links and routes in a t0/t1 testbed.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field and algorithm to test.
4. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
5. Check the traffic is balanced over all the uplink ports.
6. Randomly shutdown 1 nexthop interface.
7. Send the traffic again.
8. Check the traffic is balanced over all remaining uplink ports with no packet loss.
9. Recover the interface and do shutdown/startup on the interface 3 more times.
10. Send the traffic again.
11. Check the traffic is balanced over all uplink ports with no packet loss.

### Test cases #6 - test_lag_member_flap
1. The test is using the default links and routes in a t0/t1 testbed, and only runs on setups which have multi-member portchannel uplinks.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field and algorithm to test.
4. If the hash field is DST_MAC, ETHERTYPE or VLAN_ID, take the steps 5-7, otherwise skip them.
5. Choose one downlink interface and one uplink interface, remove all ip/ipv6 addresses on them.
6. Remove the downlink interface from the existing vlan if it is t0 topology.
7. For the DST_MAC, ETHERTYPE fields, add the chosen interfaces to a same vlan; For VLAN_ID field, add the interfaces to multiple vlans.
8. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
9. Check the traffic is balanced over all the uplink ports.
10. Randomly shutdown 1 member port in all uplink portchannels.
11. Send the traffic again.
12. Check the traffic is balanced over all remaining uplink ports with no packet loss.
13. Recover the members and do shutdown/startup on them 3 more times.
14. Send the traffic again.
15. Check the traffic is balanced over all uplink ports with no packet loss.

### Test cases #7 - test_lag_member_remove_add
1. The test is using the default links and routes in a t0/t1 testbed, and only runs on setups which have multi-member portchannel uplinks.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field and algorithm to test.
4. If the hash field is DST_MAC, ETHERTYPE or VLAN_ID, take the steps 5-7, otherwise skip them.
5. Choose one downlink interface and one uplink interface, remove all ip/ipv6 addresses on them.
6. Remove the downlink interface from the existing vlan if it is t0 topology.
7. For the DST_MAC, ETHERTYPE fields, add the chosen interfaces to a same vlan; For VLAN_ID field, add the interfaces to multiple vlans.
8. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
9. Check the traffic is balanced over all the uplink ports.
10. Randomly remove 1 member port from each uplink portchannels.
11. Add the member ports back to the portchannels.
12. Send the traffic again.
13. Check the traffic is balanced over all uplink ports with no packet loss.

### Test cases #8 - test_reboot
1. The test is using the default links and routes in a t0/t1 testbed.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field and algorithm to test.
4. Randomly select a reboot type from reload or fast/warm/cold reboot, if reload or cold reboot, save the configuration before the reload/reboot.
5. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
6. Check the traffic is balanced over all the uplink ports.
7. Do the reload/reboot.
8. After the reload/reboot, check the generic hash config via cli, it should keep the same as it was before the reload/reboot.
9. Send traffic again.
10. Check the traffic is balanced over all the uplink ports.

### Test cases #9 - test_backend_error_messages
1. Config ecmp and lag hash via cli.
2. Remove the ecmp hash key via redis cli.
3. Check there is a warning printed in the syslog.
4. Remove the ecmp hash algorithm via redis cli.
5. Check there is a warning printed in the syslog.
6. Remove the lag hash key via redis cli.
7. Check there is a warning printed in the syslog.
8. Remove the lag hash algorithm via redis cli.
9. Check there is a warning printed in the syslog.
10. Re-config the ecmp and lag hash via cli.
11. Update the ecmp hash fields with an invalid value via redis cli.
12. Check there is a warning printed in the syslog.
13. Update the ecmp hash algorithm with an invalid value via redis cli.
14. Check there is a warning printed in the syslog.
15. Update the lag hash fields with an invalid value via redis cli.
16. Check there is a warning printed in the syslog.
17. Update the lag hash algorithm with an invalid value via redis cli.
18. Check there is a warning printed in the syslog.
19. Re-config the ecmp and lag hash via cli.
20. Remove the generic hash key via redis cli.
21. Check there is a warning printed in the syslog.

### Test cases #10 - test_algorithm_config
1. Config ecmp and lag hash via cli.
2. Config ecmp and lag hash algorithm via cli.
3. Check configuration correct via show hash capabilities cli
4. Cover all the algorithms which switch supports
