# DHCP DOS Mitigation

## Test Plan Revision History

| Rev  | Date       | Author            | Change Description           |
| ---- | ---------- | ----------------- | ---------------------------- |
| 1    | 16/05/2024 | Ghulam Bahoo | Initial Version of test plan |


## Introduction
### Objective
This test plan validates the effectiveness of the DHCP rate limiting feature on a specific interface on the DUT which is a SONiC device.

### Scope
- Test DHCP rate limiting feature in response to a DHCP DOS attack on a specific interface.


## Definition/Abbreviation
| **Term**   | **Meaning**                              |
| ---------- | ---------------------------------------- |
| DoS       | Deniel of Service  |
| DHCP       | Dynamic Host Configuration Protocol |


### Related DUT CLI Commands
#### Config
The following command can be used to configure DHCP rate limit on an interface:
```
config interface dhcp-mitigation-rate add [port] [packet-rate]
config interface dhcp-mitigation-rate delete [port] [packet-rate]
```

Examples:
```
config interface dhcp-mitigation-rate add Ethernet0 1
config interface dhcp-mitigation-rate delete Ethernet0 1
```

#### Show
The following command can be used to show dhcp rate limit on an interface:
```
show interface dhcp-mitigation-rate
```
### Related DUT configuration file
#### Before Migration PORT TABLE Schema in Config_DB
```
"PORT":
  {
    "Ethernet0": {
        "admin_status": "up",
        "alias": "fortyGigE0/0",
        "index": "0",
        "lanes": "25,26,27,28",
        "mtu": "9100",
        "speed": "40000",
    }
  }
```
#### After Migration PORT TABLE Schema in Config_DB
```
"PORT":
  {
    "Ethernet0": {
        "admin_status": "up",
        "alias": "fortyGigE0/0",
        "index": "0",
        "lanes": "25,26,27,28",
        "mtu": "9100",
        "speed": "40000",
        "dhcp_rate_limit" : "300"
    }
  }
```

### Supported topology
The test will be supported on any topology


## Test Cases
### Test Case  - Test DHCP Rate Limit on an Inteface.
#### Test Objective
Verify whether DHCP rate limit is applied to a specified interface.

#### Test Steps
1. Apply a dhcp rate limit on an interface.
2. Verify that the specified dhcp rate limit is applied to the specified interface.
3. Delete the dhcp rate limit from an interface.
4. Verify that the specified dhcp rate limit is removed from the specified interface.
