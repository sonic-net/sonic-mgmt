# Generic Hash Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| SONiC Generic Hash | [https://github.com/sonic-net/SONiC/doc/hash/hash-design.md]|


## 1. Overview
The hashing algorithm is used to make traffic-forwarding decisions for traffic exiting the switch.
It makes hashing decisions based on values in various packet fields, as well as on the hash seed value.
The packet fields used by the hashing algorithm varies by the configuration on the switch.

For ECMP, the hashing algorithm determines how incoming traffic is forwarded to the next-hop device.
For LAG, the hashing algorithm determines how traffic is placed onto the LAG member links to manage
bandwidth by evenly load-balancing traffic across the outgoing links.

GH is a feature which allows user to configure which hash fields suppose to be used by hashing algorithm.
GH provides global switch hash configuration for ECMP and LAG.


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
ECMP HASH          LAG HASH
-----------------  -----------------
DST_MAC            DST_MAC
SRC_MAC            SRC_MAC
ETHERTYPE          ETHERTYPE
IP_PROTOCOL        IP_PROTOCOL
DST_IP             DST_IP
SRC_IP             SRC_IP
L4_DST_PORT        L4_DST_PORT
L4_SRC_PORT        L4_SRC_PORT
INNER_DST_MAC      INNER_DST_MAC
INNER_SRC_MAC      INNER_SRC_MAC
INNER_ETHERTYPE    INNER_ETHERTYPE
INNER_IP_PROTOCOL  INNER_IP_PROTOCOL
INNER_DST_IP       INNER_DST_IP
INNER_SRC_IP       INNER_SRC_IP
INNER_L4_DST_PORT  INNER_L4_DST_PORT
INNER_L4_SRC_PORT  INNER_L4_SRC_PORT
```

**The following command shows switch hash capabilities:**
```bash
root@sonic:/home/admin# show switch-hash capabilities
ECMP HASH          LAG HASH
-----------------  -----------------
IN_PORT            IN_PORT
DST_MAC            DST_MAC
SRC_MAC            SRC_MAC
ETHERTYPE          ETHERTYPE
VLAN_ID            VLAN_ID
IP_PROTOCOL        IP_PROTOCOL
DST_IP             DST_IP
SRC_IP             SRC_IP
L4_DST_PORT        L4_DST_PORT
L4_SRC_PORT        L4_SRC_PORT
INNER_DST_MAC      INNER_DST_MAC
INNER_SRC_MAC      INNER_SRC_MAC
INNER_ETHERTYPE    INNER_ETHERTYPE
INNER_IP_PROTOCOL  INNER_IP_PROTOCOL
INNER_DST_IP       INNER_DST_IP
INNER_SRC_IP       INNER_SRC_IP
INNER_L4_DST_PORT  INNER_L4_DST_PORT
INNER_L4_SRC_PORT  INNER_L4_SRC_PORT
```

### 3.3 DUT related configuration in config_db

```
{
    "SWITCH_HASH": {
        "GLOBAL": {
            "ecmp_hash": [
                "DST_MAC",
                "SRC_MAC",
                "ETHERTYPE",
                "IP_PROTOCOL",
                "DST_IP",
                "SRC_IP",
                "L4_DST_PORT",
                "L4_SRC_PORT",
                "INNER_DST_MAC",
                "INNER_SRC_MAC",
                "INNER_ETHERTYPE",
                "INNER_IP_PROTOCOL",
                "INNER_DST_IP",
                "INNER_SRC_IP",
                "INNER_L4_DST_PORT",
                "INNER_L4_SRC_PORT"
            ],
            "lag_hash": [
                "DST_MAC",
                "SRC_MAC",
                "ETHERTYPE",
                "IP_PROTOCOL",
                "DST_IP",
                "SRC_IP",
                "L4_DST_PORT",
                "L4_SRC_PORT",
                "INNER_DST_MAC",
                "INNER_SRC_MAC",
                "INNER_ETHERTYPE",
                "INNER_IP_PROTOCOL",
                "INNER_DST_IP",
                "INNER_SRC_IP",
                "INNER_L4_DST_PORT",
                "INNER_L4_SRC_PORT"
            ]
        }
    }
}
```
### 3.4 Supported topology
The test supports t0 and t1 topologies, not supports dualtor topology.


## 4. Test cases

Notes: 
  1. The hash field is randomly selected in the test cases. Currently these fields are tested: 'IN_PORT', 'SRC_MAC', 'DST_MAC', 'ETHERTYPE', 'VLAN_ID', 'IP_PROTOCOL', 'SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT', 'INNER_SRC_IP', 'INNER_DST_IP'.
  2. DST_MAC, ETHERTYPE, VLAN_ID fields are only tested in lag hash test cases, because L2 traffic is needed to test these fields, and there is no ecmp hash when switching in L2.
  3. IPv4 and IPv6 are covered in the test, but the versions(including the inner version when testing the inner fields) are randomly selected in the test cases.
  4. For the inner fields, three types of encapsulations are covered: IPinIP, VxLAN and NVGRE. For the VxLAN packet, the default port 4789 and a custom port 13330 are covered in the test.

### Test cases #1 - Verify the “show switch-hash capabilities” gets the supported hash fields.
1. Get the supported hash fields via cli "show switch-hash capabilities"
2. Check the fields are as expected.

### Test cases #2 - Verify when generic ecmp hash is configured, the traffic can be balanced accordingly.
1. The test is using the default links and routes in a t0/t1 testbed.
2. Randomly select a hash field and configure it to the ecmp hash list via cli "config switch-hash global ecmp-hash".
3. Configure the lag hash list to exclude the selected field to verify the lag hash configuration does not affect the hash result.
4. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination via multiple nexthops.
5. Check the traffic is balanced over the nexthops.
6. If the uplinks are portchannels with multiple members, check the traffic is not balanced over the members.

### Test cases #3 - Verify when generic lag hash is configured, the traffic can be balanced accordingly.
1. The test is using the default links and routes in a t0/t1 testbed, and only runs on setups which have multi-member portchannel uplinks.
2. Randomly select a hash field and configure it to the lag hash list via cli "config switch-hash global lag-hash".
3. Configure the ecmp hash list to exclude the selected field to verify the ecmp hash configuration does not affect the hash result.
4. If the hash field is DST_MAC, ETHERTYPE or VLAN_ID, change the topology to allow L2 switching and send L2 traffic in the next step.
5. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination via the portchannels.
6. Check the traffic is forwarded through only one portchannel and is balanced over the members.

### Test cases #4 - Verify when both generic ecmp and lag hash are configured with all the valid fields, the traffic can be balanced accordingly.
1. The test is using the default links and routes in a t0/t1 testbed.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field to test.
4. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
5. Check the traffc is balanced over all the uplink physical ports.

### Test cases #5 - Verify generic hash works properly when there are nexthop flaps.
1. The test is using the default links and routes in a t0/t1 testbed.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field to test.
4. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
5. Check the traffic is balanced over all the uplink ports.
6. Randomly shutdown 1 nexthop interface.
7. Send the traffic again.
8. Check the traffic is balanced over all remaining uplink ports with no packet loss.
9. Recover the interface and do shutdown/startup on the interface 3 more times.
10. Send the traffic again.
11. Check the traffic is balanced over all uplink ports with no packet loss.

### Test cases #6 - Verify generic hash works properly when there are lag member flaps.
1. The test is using the default links and routes in a t0/t1 testbed, and only runs on setups which have multi-member portchannel uplinks
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field to test.
4. If the hash field is DST_MAC, ETHERTYPE or VLAN_ID, change the topology to allow L2 switching and send L2 traffic in the next step.
5. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
6. Check the traffic is balanced over all the uplink ports.
7. Randomly shutdown 1 member port in all uplink portchannels.
8. Send the traffic again.
9. Check the traffic is balance over all remaining uplink ports with no packet loss.
10. Recover the members and do shutdown/startup on them 3 more times.
11. Send the traffic again.
12. Check the traffic is balance over all uplink ports with no packet loss.

### Test cases #7 - Verify generic hash running configuration persists after fast/warm reboot, and the saved configuration persists after cold reboot.
1. The test is using the default links and routes in a t0/t1 testbed.
2. Configure all the supported hash fields for the ecmp and lag hash.
3. Randomly select one hash field to test.
4. Randomly select a reboot type from fast/warm/cold reboot, if cold reboot, save the configuration before the reboot.
5. Send traffic with changing values of the field under test from a downlink ptf port to uplink destination.
6. Check the traffic is balance over all the uplink ports.
7. Randomly do fast/warm/cold reboot.
8. After the reboot, check the generic hash config via cli, it should keep the same as it was before the reboot.
9. Send traffic again.
10. Check the traffic is balance over all the uplink ports.

### Test cases #8 - Verify the generic hash cannot be configured successfully with invalid parameters.
1. Configure the ecmp/lag hash with invalid fields parameter.
2. Check there is a cli error that notifies the user the parameter is invalid.
3. Check the running config is not changed.
4. The invalid parameters to test:
  a. empty parameter
  b. single invalid field
  c. invalid fields combined with valid fields
  d. duplicated valid fields

### Test cases #9 - Verify when a generic hash config key is removed, or updated with invalid values from config_DB via redis cli, there will be warnings printed in the syslog.
1. Config ecmp and lag hash via cli.
2. Remove the ecmp hash key via redis cli.
3. Check there is a warning printed in the syslog.
4. Remove the lag hash key via redis cli.
5. Check there is a warning printed in the syslog.
6. Re-config the ecmp and lag hash via cli.
7. Update the ecmp hash fields with an invalid value via redis cli.
8. Check there is a warning printed in the syslog.
9. Update the lag hash fields with an invalid value via redis cli.
10. Check there is a warning printed in the syslog.
11. Re-config the ecmp and lag hash via cli.
12. Remove the generic hash key via redis cli.
13. Check there is a warning printed in the syslog.
