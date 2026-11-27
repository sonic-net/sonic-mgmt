# CLI Sessions Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| CLI Sessions HLD | [https://github.com/sonic-net/SONiC/pull/1367]|


## Overview

Allow configuring ssh server and serial-connection global settings.

Implement next commands for CLI-sessions feature:
- config serial-console inactivity-timeout
- config serial-console sysrq-capabilities
- show serial-console
- config ssh max-sessions
- config ssh inactivity-timeout
- show ssh

### Scope

The test is to verify CLI Sessions feature

### Scale / Performance

No scale/performance test involved in this test plan

### Related **DUT** CLI commands
```
User interface:

config
|--- ssh
     |--- max-sessions
     |--- inactivity-timeout
|--- serial-console
     |--- inactivity-timeout
     |--- sysrq-capabilities

show
|--- ssh
|--- serial-console
```

### Supported topology
The tests will be supported on any topo.


### Test cases #1 -  Configure ssh max-sessions: set/unset
1. Check default max-sessions value by show ssh command, should be 3
2. Configure max-sessions to 2 and verify changes by show command
3. Create 3 ssh connection and verify only 2 connected
4. Del max-sessions and verify it returned to 3


### Test cases #2 -  Configure ssh, serial-connection inactivity timeout: set/unset
1. Check default inactivity timeout value by show ssh command, should be 15
2. Configure inactivity timeout for ssh to 1 min and verify changes by show ssh command
3. Make new ssh connection to switch and wait for disconnect after 1 min
4. Del inactivity timeout and verify it returned to 15
5. Configure inactivity timeout for serial-connection to 1 min and verify changes by show serial-console command
6. Make new serial connection to switch and wait for disconnect after 1 min
7. Del serial inactivity timeout and verify it returned to 15


### Test cases #3 -  Configure serial sysrq-capabilities: set/unset
1. Check default sysrq-capabilities show serial-console command, should be disabled
2. Configure sysrq-capabilities enabled and verify changes by serial-console ssh command
3. Del sysrq-capabilities and verify it returned to disabled
