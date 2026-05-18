# Management Interface Configuration Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| Management Interface Configuration HLD |
[https://github.com/chrisy97/SONiC-Doc/blob/dev-mgmt-interface/doc/mgmt-interface/mgmt-interface-config.md]|


## Overview

This design focuses on the backend configuration settings for management interfaces.
The settings are speed, duplex and auto-negotiation in the document.
And it can be easily extended to more settings.
The document does not include the front-end CLI for the related settings.

### Scope

The test is to verify Management Interface configuration

### Scale / Performance

No scale/performance test involved in this test plan

### Supported topology
The tests will be supported on any topo.


### Test cases #1 -  Configure mgmt port:
1. Configure Management port autoneg on like below:
```
sonic-db-cli CONFIG_DB HSET 'MGMT_PORT|{{ mgmt_intf }}' 'autoneg' 'on'
```
2. Verify changes by ethtool command
3. Configure Management port autoneg off like below:
```
sonic-db-cli CONFIG_DB HSET 'MGMT_PORT|{{ mgmt_intf }}' 'autoneg' 'off'
```
4. Verify changes by ethtool command
5. Configure Management port full duplex on like below:
```
sonic-db-cli CONFIG_DB HSET 'MGMT_PORT|{{ mgmt_intf }}' 'duplex' 'full'
```
6. Verify changes by ethtool command
7. Configure Management port half duplex on like below:
```
sonic-db-cli CONFIG_DB HSET 'MGMT_PORT|{{ mgmt_intf }}' 'duplex' 'half'
```
8. Verify changes by ethtool command
9. Configure Management port speed  like below:
```
sonic-db-cli CONFIG_DB HSET 'MGMT_PORT|{{ mgmt_intf }}' 'speed' '10000'
```
10. Verify changes by ethtool command
11. Unset configuration
