# Purpose of SER test

SER test is a test designed to validate Broadcom ASIC memory parity error protection mechanism.

There are certain registers that are cached and protected by ECC. When injecting a single big error on these cached memory, the expectation is that they will be corrected and a syslog entry will be generated to state the correction.

There are a few things making this test complicated:

- Some cached memory locations don't support SER test.
- Some cached memory locations generate correction syslog with an unrecognized memory address. Which making mapping it to the tested location impossible.
- Some cached memory locations take really long time to inject error (more than a minute), which slows down test quite a bit.
- Some cached memory locations has alias, this is not really an issue. The test groups these memory locations together and check them off with one hit.

# How the test work

## General test strategy

The test strategy is as following:
1. Collect the cached memory locations from either ASIC, or from the cached file after first test.
2. Choose a test set according to the completeness level. Depending on the level, some memory locations might be excluded from the full test set.
3. Injecting errors in batches. Batch size is controlled by parameter --batch_size (-b). Default is 10 entries.
4. During error injection, if any location takes more than --injection_slow_sec (-i) seconds, the location is marked as slow injection. Default limit is 5 seconds.
5. Watch the syslog up to batch timeout seconds, controlled by paramter --test_batch_timeout (-t). The default is 60 seconds.
6. Any matched memory will be removed from test set. If test set is empty, then the test is done successfully.
7. If some match happened, and test set is not empty when timed out, set stall count back to 0, go back to step 3.
8. If no match happened, and test set is not empty when timed out, increase stall count. At the same time, increase the batch size by default bach size.
9. If the stall count is less than --stall_limit (-s), go back to step 3. Otherwise, fail the test.

## Different test completeness levels

### Different sets of memory locations:
- Full list: all cached memory locations.
- Unsupported: error injection clearly indicated the location doesn't support SER test.
- timeout: memory locations failed test at thorough level.
- timeout_basic: memory locations randomly failed during basic level tests.
- slow_injection: memory locations takes extremely long time to inject error.

### debug
Randomly pick 1 memory location to test, the location is from (full list - unsupported - timeout - timeout_basic - slow_injection)

The purpose of this level is more to test the test procedure itself.

### basic
Randomly pick 6 batch_size(s) of locations to run the test. This is the default test mode.

### confident
Test memory locations of (full list - unsupported - timeout - slow_injection).

### thorough
Test all memory locations. Except when --skip_slow_injections (-e) parameter is provided, exclude the slow_injection locations.

### Diagnose
Test all 'bad' memory locations: (timeout + timeout_basic + slow_injection + unsupported)

# How to program the initial parameters for an new ASIC

## Following steps are recommended when learning the characteristics of an new ASIC:

1. Add a section for the new asic in SKIP_MEMORY_PER_ASIC with empty lists (remove existing entries when re-calibrating an ASIC):
```
    'foo' : {
        'timeout' : [
        ],
        'timeout_basic' : [
        ],
        'slow_injection' : [
        ],
        'unsupported' : [
        ]
     }
```

2. Add new ASIC lspci signature in function get_asic_name(), skip this step when recalibrating an ASIC.

3. Copy ser_injector.py to target device and chmod +x ser_injector.py.

4. Note that the test could last for hours. Please disable ssh timeout from DUT by commented out ClientAliveInterval and ClientAliveCountMax config in /etc/ssh/sshd_config, and restart ssh daemon. Logout and login just to be sure.

5. Run ser_injector.py -c thorough once. Add the failed list and timed out list to 'timeout' list in the diction created in step 1. Add unsupported list to 'unsupported'. Add slow injection list to 'slow_injection'. This test would last for longest. Would be better to start this test from a tmux session on a jumpbox, then ssh to dut, at the same time pipe output to a file for record.
```
    SER Test failed for memories (*): {...} [...]
    SER Test timed out for memories (*): [...]
    SER Test is not supported for memories (*): [...]
    SER Test memory error injection too slow (*): {...} [...]
```

6. Run several times of confident level test, add newly found entries as in step 5. The goal is to have at lest 3 confident level test succeeded.

7. Run several times of basic level test, add newly found timeout/failed entries to 'timeout_basic' list. The goal is to have at least 10 basic level test succeeded. At this step, we don't really expect to see unsupported or slow injection. But if we do, add them accordingly.


## The script I used to run confident and basic level tests:
```
	#!/bin/bash

	test='confident'
	for i in $(seq 4); do
		echo "==== iteration $i ===="
		time ./ser_injector.py -c ${test} -b 20 -s 5 -v -e | tee test-${test}-$(date "+%Y%m%d-%H%M").log
	done

	test='basic'
	for i in $(seq 20); do
		echo "==== iteration $i ===="
		time ./ser_injector.py -c ${test} -s 10 -v | tee test-${test}-$(date "+%Y%m%d-%H%M").log
	done
```
