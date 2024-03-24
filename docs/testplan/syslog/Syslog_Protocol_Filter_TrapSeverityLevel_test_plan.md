# Syslog Protocol Filter Trap severity level Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| Syslog new functionality HLD | [https://github.com/sonic-net/SONiC/pull/1218]|


## Overview

Extended following functionality in syslog:

Configure remote syslog servers: protocol, filter, trap severity level
Update global syslog configuration: trap severity level, message format

### Scope

The test is to verify syslog new functionality

### Scale / Performance

No scale/performance test involved in this test plan

### Related **DUT** CLI commands

```
User interface:

config
|--- syslog
     |--- add <server_ip> OPTIONS
     |--- del <server_ip>

Options:

config syslog add server_ip

-s|--source - source ip address
-p|--port - server udp port
-r|--vrf - vrf device


show
|--- syslog
```

### Supported topology
The tests will be supported on any topo.

### Test cases #1 -  Configure syslog server with source:unset/unset
1. Configure syslog server with source:unset/unset like below:
```
config syslog add 2.2.2.2
```
2. Check syslog config by show syslog, the result should like below:
    ```
    # show syslog
    SERVER      SOURCE      PORT    VRF
    ----------  ----------  ------  --------
    2.2.2.2     N/A         514     default
    ```
3. Check the corresponding interface will send syslog message with port 514 on dut
```
# show syslog
SERVER      SOURCE      PORT    VRF
----------  ----------  ------  --------
2.2.2.2     N/A         514     default
```
4. Change syslog protocol to tcp
```
sonic-db-cli CONFIG_DB HSET 'SYSLOG_SERVER|2.2.2.2' 'protocol' 'tcp'
```
5. Send message with tcp protocol and verify packet sent
6. Send message with udp and verify it did not send
7. Configure include filter with filter regex
```
sonic-db-cli CONFIG_DB hset 'SYSLOG_SERVER|2.2.2.2' 'filter_type' 'include' 'filter_regex' 'sonic'
```
8. Send message with include filter and verify packet sent
9. Send message without include filter and verify packet did not send
10. Configure exclude filter
```
sonic-db-cli CONFIG_DB hset 'SYSLOG_SERVER|2.2.2.2' 'filter_type' 'exclude' 'filter_regex' 'aa'
```
11. Send message with exclude regex and verify packet not sent
12. Send message without exclude regex and verify packet sent
13. Remove exclude filter
```
sonic-db-cli CONFIG_DB hdel 'SYSLOG_SERVER|2.2.2.2' 'filter_type' 'exclude' 'filter_regex' 'aa'
```
14. Send messages with different severities and make sure they will be filtered according to default severity
15. Change global severity and make sure it works according to messages you sent
16. Remove syslog config
```
config syslog del 2.2.2.2
```

14. Send messages with different severities and make sure they will be filtered according to default severity
15. Change global severity and make sure it works according to messages you sent
16. Remove syslog config
```
config syslog del 2.2.2.2
```
