# System Banner Messages Test Plan


- [Overview](#overview)
    - [Scope](#scope)
    - [Scale/Performance](#scale--performance)
    - [Related DUT CLI commands](#related-dut-cli-commands)
    - [Supported Topology](#supported-topology)
- [Test cases](#test-cases)
    - [Test case \#1](#test-case-1----configure-login-banner-messageset)
    - [Test case \#2](#test-case-2----configure-motd-banner-messageset)
    - [Test case \#3](#test-case-3----configure-logout-banner-messageset)
- [Open Questions](#open-questions)

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| Banner Messages HLD | [https://github.com/sonic-net/SONiC/blob/master/doc/banner/banner_hld.md]|


## Overview

The OS maintains several messages for communication with users. These messages associate with login and logout processes.

| **Type** | **Description** |
|-------------------|----------|
| login  | Display a banner to the users connected locally or remotely before login prompt |
| motd   | Display a banner to the users after login prompt |
| logout | Display a logout banner to the users connected locally or remotely |

The motivation of this feature is to provide the ability to user to configure banner  messages from CLI and show existing configuration.

### Scope

The test is to verify the System Banner Messages functionality

### Scale / Performance

No scale/performance test involved in this test plan

### Related DUT CLI commands
```
User interface:

config
\-- banner
    |-- state <enabled|disabled>
    |-- login <message>
    |-- logout <message>
    |-- motd <message>

show
\-- banner
```

### Supported topology
The tests will be supported on any topology.

## Test Cases

### Test case \#1 -  Configure login banner message:set

#### Test Objective

Verify the set command for system login banner message which comes with the login prompt

#### Test steps

1. Configure 'login' message:set/unset like below:
```
config banner login "Welcome to Sonic CLI"
```

2. Check banner config by show, the result should like below:
 ```
 # show banner
 STATE       LOGIN                  MOTD      LOGOUT
 ----------  --------------------   --------  --------
 enabled     Welcome to Sonic CLI   Sonic
 ```

3. Attempt to login via ssh and check the login message
```
# ssh admin@10.7.144.28
Welcome to Sonic CLI
admin@10.7.144.30's password:
```

### Test case \#2 -  Configure motd banner message:set

#### Test Objective

Verify the set command for system 'message of the day banner' message which comes after
the login prompt

#### Test steps

1. Configure 'motd' message:set like below:
```
config banner motd "Your are on SONIC"
```

2. Check banner config by show, the result should like below:
 ```
 # show banner
 STATE       LOGIN                  MOTD                LOGOUT
 ----------  --------------------   ------------------  --------
 enabled     Welcome to Sonic CLI   Your are on SONIC
 ```

3. Login and check the login message
```
# ssh admin@10.7.144.28
Welcome to Sonic CLI
admin@10.7.144.30's password:
You are on SONIC
```

### Test case \#3 -  Configure logout banner message:set

#### Test Objective

Verify the command for set of system logout banner message which comes after logout

#### Test steps

1. Configure 'logout' message:set like below:
```
config banner logout "Good Bye"
```

2. Check banner config by show, the result should like below:
 ```
 # show banner
 STATE       LOGIN                  MOTD      LOGOUT
 ----------  --------------------   --------  --------
 enabled     Welcome to Sonic CLI   Sonic     Good Bye
 ```

3. Logout and check the logout message
```
# exit
Good Bye
Connection to 10.7.144.28 closed.
```

## Open Questions

