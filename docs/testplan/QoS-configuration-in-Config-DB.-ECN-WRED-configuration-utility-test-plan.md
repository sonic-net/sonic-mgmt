## Overview
The purpose is to test the functionality of ECN Configuration on the SONIC Switch.
The test does not require any links on the Switch.

Test cases cover initial ECN WRED configuration and 

## Related tools and CLI utilities
Utility to be used for QoS configuration (including ECN WRED) validation: `sonic-cfggen`.  

    sonic-cfggen -j qos.json --print-config
Utility to test ECN WRED configuration update: `ecnconfig`.

    ecnconfig -p AZURE_LOSSY -gmax 516096

Utility to explore DB: `redis-cli`.

    redis-cli -n 4 keys *

## Manual tests
To be performed after changes touching QoS ECN components:

- Orchagent: qosorch.cpp, qosorch.h, orchdaemon.cpp
- sonic-cfggen utility
- Common table classes: ProducerTable, ConsumerTable
- sonic-py-swsssdk library
- first-time init script rc.load
- manipulations with hwsku
- adding configuration for new platforms/hwskus
- ecnconfig utility

## Automated tests
To be performed on testbed or stand-alone switch in scope of regression tests.

### Test cases
Test cases marked with (M) - manual - recommended for manual testing and (A) if it makes sense to automate the test and run it in regression. (MA) - suitable for both.

#### Test case #1(M): Check configuration file(s) available on Switch
Build SONiC, install to Switch, boot and check if `qos.json` files in folders

    /usr/share/sonic/device/<platform>/<hwsku>/
Check for related or updated platforms.

#### Test case #2(M): Check QoS configuration reaches DB

Ssh to Switch and check whether QoS configuration was added to the Config DB.

    redis-cli -n 4 keys \* | grep QUEUE

Expected records like:

    43) "QUEUE|Ethernet0,Ethernet4....

#### Test case #3(MA): Check configuration applied

Ssh to Switch and check whether QoS configuration applied.

    redis-cli -n 1 keys \* | grep QUEUE

Expected records like:

    1034) "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:oid:0x150000000003bf"

#### Test case #4(M): Ecnconfig utility test. List mode
Ssh to Switch and execute:

    ecnconfig -l

Expected output:

	Profile: AZURE_LOSSLESS
	--------------------  -------
	red_max_threshold     516096
	wred_green_enable     true
	ecn                   ecn_all
	green_min_threshold   184320
	red_min_threshold     516096
	wred_yellow_enable    true
	yellow_min_threshold  516096
	green_max_threshold   184320
	yellow_max_threshold  516096
	--------------------  -------
	...

Compare to values in init_cfg.json:

    sonic-cfggen -j /etc/sonic/init_cfg.json --print-data | grep -A20 \"AZURE_LOSSLESS\"

#### Test case #5(M): Ecnconfig utility test. Set mode
Ssh to Switch and execute:

    ecnconfig -p AZURE_LOSSY -gmax 184320 -rmax 516096

No error messages expected.

#### Test case #6(MA): Ecnconfig utility test. Set function
Ssh to Switch and execute:

    ecnconfig -p AZURE_LOSSY -rmin 491520

Check ASIC DB records.

    redis-cli -n 1 keys \* | grep "ASIC_STATE:SAI_OBJECT_TYPE_WRED"

Expected output example:

    root@arc-switch1028:/home/admin# redis-cli -n 1 hgetall "ASIC_STATE:SAI_OBJECT_TYPE_WRED:oid:0x130000000005cc"
    ...
    13) "SAI_WRED_ATTR_RED_MIN_THRESHOLD"
    14) "491520"
    ...

#### Test case #7(M): Ecnconfig utility test. Integration with `show` and `config`
Ssh to Switch and run the following commands:

    show ecn

Expected output: like in test case #4

    config ecn --help

Expected output: utility usage help screen

    config ecn -profile AZURE_LOSSY -rmin 430080

Check value applied like in test case #6

#### Test case #8(M): Ecnconfig utility test. Negative tests
Ssh to Switch and run the following commands:

    ecnconfig -l -p
    ecnconfig -l -p LOSS
    ecnconfig -p LOSS
    ecnconfig -p LOSS -gmax
    config ecn -gmax 45
    show ecn -p

All should fail with the appropriate error messages.
