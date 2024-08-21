# Storage Monitoring Daemon Test Plan

## 1. Test Plan Revision History

| Version | Date       | Author      | Changes Made        |
|---------|------------|-------------|---------------------|
| 1.0     | 2024-08-20 | Ashwin Srinivasan    | Initial Document    |

## 2. Objective

The objective of this test suite is to validate the functionality, performance, and reliability of the [Storage Monitoring Daemon](https://github.com/sonic-net/SONiC/blob/master/doc/storagemond/storagemond-hld.md), a platform monitoring daemon that continuously monitors and reports various attributes of storage disks to the `STATE_DB`. The tests will ensure that the daemon operates as expected under different scenarios, including normal operation, reboots, and crashes.

## 3. Scope

The scope of this test plan includes the following:

- Verification of daemon initialization and proper logging of disk attributes.
- Validation of the daemon's ability to report accurate data to `STATE_DB`.
- Testing the daemon's behavior during various system reboot scenarios (cold, warm, and soft reboots).
- Assessment of the daemon's recovery process after unexpected crashes.

## 4. Tests

### 4.1 Daemon Initialization
Objective: Verify that the Storage Monitoring Daemon initializes correctly and logs the appropriate messages:

```
2024 May 28 17:50:54.327712 sonic-device INFO pmon#supervisord 2024-05-28 17:50:54,326 INFO spawned: 'stormond' with pid 96
2024 May 28 17:50:55.695842 sonic-device INFO pmon#stormond[96]: /usr/share/stormond/fsio-rw-stats.json not present.
2024 May 28 17:50:55.696967 sonic-device INFO pmon#stormond[96]: Starting Storage Monitoring Daemon
2024 May 28 17:50:55.697958 sonic-device INFO pmon#stormond[96]: Storage Device: sda, Device Model: InnoDisk Corp. - mSATA 3IE3, Serial: BCA12310040200027
2024 May 28 17:50:55.701215 sonic-device INFO pmon#stormond[96]: Polling Interval set to 3600 seconds
2024 May 28 17:50:55.702037 sonic-device INFO pmon#stormond[96]: FSIO JSON file Interval set to 86400 seconds
2024 May 28 17:50:56.068452 sonic-device INFO pmon#stormond[96]: Storage Device: sda, Firmware: S16425cG, health: 99%, Temp: 30C, FS IO Reads: 36708, FS IO Writes: 68792
2024 May 28 17:50:56.068602 sonic-device INFO pmon#stormond[96]: Latest FSIO Reads: 13854, Latest FSIO Writes: 6386
2024 May 28 17:50:56.068671 sonic-device INFO pmon#stormond[96]: Disk IO Reads: 26092, Disk IO Writes: 16047, Reserved Blocks: 63
2024 May 28 17:51:04.821947 sonic-device INFO pmon#supervisord 2024-05-28 17:51:04,820 INFO success: stormond entered RUNNING state, process has stayed up for > than 10 seconds (startsecs)
``` 

#### Test Case 4.1.1: Initialize stormond and verify the following:
  1. Stormond is spawned with a valid process ID.
  2. The daemon starts without errors and logs the start-up message.
  3. The polling interval and FSIO JSON file interval are set correctly.
  4. `STATE_DB` Status: Empty
  5. JSON File: Empty
  6. PROCFS Status: Initial Values
  7. JSON File Synced With `STATE_DB`?: Yes
  8. `stormond` Restarted: Yes

#### Test Case 4.1.2: Verify the running state of stormond:
  1. The daemon logs the storage device attributes: health, temperature, FS IO Reads/Writes, Disk IO Reads/Writes and Reserved Blocks to `STATE_DB`.
  2. Ensure the latest FSIO Reads and Writes are updated correctly.
  3. `STATE_DB` Status: Initial values
  4. JSON File: Empty
  5. PROCFS Status: Initial Values
  6. JSON File Synced With `STATE_DB`?: No

### 4.2 Bind Mount Operations

**Objective**: Confirm that the bind mount operations work correctly for the daemon’s files.

**Test Case 4.2.1**: Verify bind mount in the container and host:
  1. Ensure that the `/host/pmon/stormond/` directory on the host reflects the correct bind mount from the container.
  2. Check that the `/usr/share/stormond/` directory on the container contains the expected file(s).
  3. Verify the file permissions, ownership and inode number are identical in the bind-mounted directories in container and host.

    **Container:**
    ```
    root@sonic-device:/# ls -il /usr/share/stormond/
    total 4
    527873 -rw-r--r-- 1 root root 9 May 28 17:53 bindmnt.txt
    root@sonic-device:/#
    ```

    **Host**
    ```
    admin@sonic-device:~$ ls -il /host/pmon/stormond/
    total 4
    527873 -rw-r--r-- 1 root root 9 May 28 17:53 bindmnt.txt
    ```

### 4.3 Planned Reboots

**Objective**: Validate the daemon’s behavior during and after different types of planned reboots.

#### 4.3.1 Cold Reboot
**Test Case 4.3.1.1**: Perform a cold reboot and verify:
  1. The daemon receives the SIGTERM signal and shuts down gracefully.

```
2024 May 28 17:54:41.250139 sonic-device INFO pmon#stormond[96]: Caught signal 'SIGTERM'
2024 May 28 17:54:41.250591 sonic-device INFO pmon#stormond[96]: Syncing latest procfs reads and writes to disk
2024 May 28 17:54:41.250857 sonic-device INFO pmon#stormond[96]: Syncing total and latest procfs reads and writes from STATE_DB to JSON file
2024 May 28 17:54:41.252355 sonic-device INFO pmon#stormond[96]: Exiting with SIGTERM
2024 May 28 17:54:41.252671 sonic-device INFO pmon#stormond[96]: Shutting down Storage Monitoring Daemon
```

  2. Storage device attributes are synced to the JSON file before shutdown.
  3. The daemon restarts automatically after the reboot and logs the correct storage device attributes.

```
2024 May 28 17:59:11.137282 sonic-device INFO pmon#stormond[39]: Starting Storage Monitoring Daemon
2024 May 28 17:59:11.138012 sonic-device INFO pmon#stormond[39]: Storage Device: sda, Device Model: InnoDisk Corp. - mSATA 3IE3, Serial: BCA12310040200027
2024 May 28 17:59:11.140763 sonic-device INFO pmon#stormond[39]: Polling Interval set to 3600 seconds
2024 May 28 17:59:11.141522 sonic-device INFO pmon#stormond[39]: FSIO JSON file Interval set to 86400 seconds
2024 May 28 17:59:11.484554 sonic-device INFO pmon#stormond[39]: Storage Device: sda, Firmware: S16425cG, health: 99%, Temp: 30C, FS IO Reads: 56806, FS IO Writes: 71943
2024 May 28 17:59:11.484654 sonic-device INFO pmon#stormond[39]: Latest FSIO Reads: 20098, Latest FSIO Writes: 3151
2024 May 28 17:59:11.484654 sonic-device INFO pmon#stormond[39]: Disk IO Reads: 26122, Disk IO Writes: 16049, Reserved Blocks: 63
```

  4. `STATE_DB` Status: Cleared
  5. JSON File: Persisted
  6. PROCFS Status: RESET, Initial Values
  7. JSON File Synced With `STATE_DB`?: Yes
  8. `stormond` Restarted: Yes

#### 4.3.2 Soft Reboot
**Test Case 4.3.2.1**: Perform a soft reboot and verify:
  1. The daemon handles the SIGTERM signal appropriately.

```
2024 May 28 18:53:58.670677 sonic-device INFO systemd[1]: Stopping pmon.service - Platform monitor container...
2024 May 28 18:53:59.634032 sonic-device DEBUG container: read_data: config:True feature:pmon fields:[('set_owner', 'local'), ('no_fallback_to_local', False), ('state', 'disabled')] val:['local', False, 'enabled']
2024 May 28 18:53:59.635955 sonic-device DEBUG container: read_data: config:False feature:pmon fields:[('current_owner', 'none'), ('remote_state', 'none'), ('container_id', '')] val:['none', 'none', '']
2024 May 28 18:53:59.638080 sonic-device DEBUG container: container_stop: pmon: set_owner:local current_owner:none remote_state:none docker_id:pmon
2024 May 28 18:53:59.740204 sonic-device INFO pmon#supervisord 2024-05-28 18:53:59,738 WARN received SIGTERM indicating exit request
2024 May 28 18:53:59.740204 sonic-device INFO pmon#pcied[42]: message repeated 13 times: [ PCIe device status check : PASSED]
2024 May 28 18:53:59.740204 sonic-device INFO pmon#pcied[42]: Caught signal 'SIGTERM' - exiting...
2024 May 28 18:53:59.740380 sonic-device INFO pmon#pcied[42]: Shutting down...
2024 May 28 18:53:59.740428 sonic-device INFO pmon#supervisord 2024-05-28 18:53:59,739 INFO waiting for supervisor-proc-exit-listener, rsyslogd, xcvrd, psud, syseepromd, stormond, thermalctld, pcied to die
2024 May 28 18:53:59.926286 sonic-device INFO pmon#supervisord 2024-05-28 18:53:59,925 WARN stopped: pcied (exit status 143)
2024 May 28 18:53:59.928786 sonic-device INFO pmon#thermalctld[41]: Caught signal 'SIGTERM' - exiting...
2024 May 28 18:53:59.928786 sonic-device INFO pmon#thermalctld: Stop thermal monitoring loop
2024 May 28 18:53:59.933764 sonic-device INFO pmon#thermalctld[41]: Shutting down with exit code 143...
2024 May 28 18:54:01.139907 sonic-device INFO pmon#supervisord 2024-05-28 18:54:01,139 WARN stopped: thermalctld (exit status 143)
2024 May 28 18:54:01.141292 sonic-device INFO pmon#stormond[40]: Caught signal 'SIGTERM'
2024 May 28 18:54:01.141292 sonic-device INFO pmon#stormond[40]: Syncing latest procfs reads and writes to disk
2024 May 28 18:54:01.141342 sonic-device INFO pmon#stormond[40]: Syncing total and latest procfs reads and writes from STATE_DB to JSON file
2024 May 28 18:54:01.142815 sonic-device INFO pmon#stormond[40]: Exiting with SIGTERM
2024 May 28 18:54:01.143046 sonic-device INFO pmon#stormond[40]: Shutting down Storage Monitoring Daemon
2024 May 28 18:54:02.289815 sonic-device INFO pmon#supervisord 2024-05-28 18:54:02,288 WARN stopped: stormond (exit status 143)
```

  2. The daemon shuts down and restarts after the reboot without errors.

```
2024 May 28 18:57:44.313318 sonic-device INFO pmon#stormond[39]: Starting Storage Monitoring Daemon
2024 May 28 18:57:44.313318 sonic-device INFO pmon#stormond[39]: Storage Device: sda, Device Model: InnoDisk Corp. - mSATA 3IE3, Serial: BCA12310040200027
2024 May 28 18:57:44.315186 sonic-device INFO pmon#stormond[39]: Polling Interval set to 3600 seconds
2024 May 28 18:57:44.315277 sonic-device INFO pmon#stormond[39]: FSIO JSON file Interval set to 86400 seconds
```

  3. Storage device attributes are consistent after the reboot.

```
2024 May 28 18:57:44.714516 sonic-device INFO pmon#stormond[39]: Storage Device: sda, Firmware: S16425cG, health: 99%, Temp: 30C, FS IO Reads: 97865, FS IO Writes: 93334
2024 May 28 18:57:44.714695 sonic-device INFO pmon#stormond[39]: Latest FSIO Reads: 20099, Latest FSIO Writes: 3559
2024 May 28 18:57:44.714760 sonic-device INFO pmon#stormond[39]: Disk IO Reads: 26153, Disk IO Writes: 16060, Reserved Blocks: 63
```

  4. `STATE_DB` Status: Cleared
  5. JSON File: Persisted
  6. PROCFS Status: RESET, Initial Values
  7. JSON File Synced With `STATE_DB`?: Yes
  8. `stormond` Restarted: Yes

#### 4.3.3 Warm Reboot

**Test Case 4.3.3.1**: Perform a warm reboot and verify the following:

  1. Ensure the daemon syncs storage attributes to the `STATE_DB` before reboot.

```
2024 May 28 19:17:29.258327 sonic-device INFO pmon#stormond[39]: Caught signal 'SIGTERM'
2024 May 28 19:17:29.258688 sonic-device INFO pmon#stormond[39]: Syncing latest procfs reads and writes to disk
2024 May 28 19:17:29.258914 sonic-device INFO pmon#stormond[39]: Syncing total and latest procfs reads and writes from STATE_DB to JSON file
2024 May 28 19:17:29.260681 sonic-device INFO pmon#stormond[39]: Exiting with SIGTERM
2024 May 28 19:17:29.260967 sonic-device INFO pmon#stormond[39]: Shutting down Storage Monitoring Daemon

admin@sonic-device:~$ docker ps | grep pmon
admin@sonic-device:~$ 
admin@sonic-device:~$ redis-cli -n 6 hgetall "STORAGE_INFO|sda"
1) "device_model"
2) "InnoDisk Corp. - mSATA 3IE3"
3) "serial"
4) "BCA12310040200027"
5) "firmware"
6) "S16425cG"
7) "health"
8) "99"
9) "temperature"
10) "30"
11) "latest_fsio_reads"
12) "20099"
13) "latest_fsio_writes"
14) "3559"
15) "disk_io_reads"
16) "26153"
17) "disk_io_writes"
18) "16060"
19) "reserved_blocks"
20) "63"
21) "total_fsio_reads"
22) "97865"
23) "total_fsio_writes"
24) "93334"
admin@sonic-device:~$ 
```

  2. Verify that the daemon restarts correctly and the storage attributes are consistent with the pre-reboot state.

```
2024 May 28 19:22:06.079932 sonic-device INFO pmon#supervisord 2024-05-28 19:22:06,078 INFO success: stormond entered RUNNING state, process has stayed up for > than 10 seconds (startsecs)
2024 May 28 19:22:01.479249 sonic-device INFO pmon#stormond[39]: Polling Interval set to 3600 seconds
2024 May 28 19:22:01.483975 sonic-device INFO pmon#stormond[39]: FSIO JSON file Interval set to 86400 seconds
2024 May 28 19:22:01.684967 sonic-device INFO systemd[1]: Starting snmp.service - SNMP container...
2024 May 28 19:22:01.878598 sonic-device INFO pmon#stormond[39]: Storage Device: sda, Firmware: S16425cG, health: 99%, Temp: 30C, FS IO Reads: 118815, FS IO Writes: 96834
2024 May 28 19:22:01.878824 sonic-device INFO pmon#stormond[39]: Latest FSIO Reads: 20950, Latest FSIO Writes: 3500
2024 May 28 19:22:01.878917 sonic-device INFO pmon#stormond[39]: Disk IO Reads: 26184, Disk IO Writes: 16070, Reserved Blocks: 63
```

  3. `STATE_DB` Status: Persisted
  4. JSON File: Persisted
  5. PROCFS Status: RESET, Initial Values
  6. JSON File Synced With `STATE_DB`?: Yes
  7. `stormond` Restarted: Yes


### 4.4 Crash Scenarios

**Objective**: Test the daemon’s resilience and recovery mechanisms in the event of unexpected crashes.

#### 4.4.1 Daemon Crash Before Planned Reboot

**Test Case 4.4.1.1**: Simulate a crash of stormond before a planned reboot:
  1. Kill the daemon process and verify that it restarts automatically.
  2. Ensure the daemon logs the crash and subsequent recovery.
  3. Verify that:
     - if the `/usr/share/stormond/fsio-rw-stats.json` file is present: FSIO Reads and Writes are greater than values observed before the daemon crashed.
     - else, since it is essentially a fresh initialization of the daemon, the Reserved blocks, Disk Reads and Writes values are >= the values prior to crash.

  4. `STATE_DB` Status: Persisted
  5. JSON File: Persisted
  6. PROCFS Status: Persisted
  7. `stormond` Restarted: Yes

#### 4.4.2 Daemon Crash After Planned Reboot
**Test Case 4.4.2.1**: Simulate a crash of stormond after a planned reboot:
  1. Kill the daemon process and verify recovery.
  2. Check the logs for accurate reporting of storage attributes post-recovery, i.e., FSIO Reads and Writes are greater than values observed before the daemon crashed.

    ```
    admin@sonic-device:~$ docker exec -it pmon bash
    root@sonic-device:/# kill -9 39
    root@sonic-device:/# 

    logs:

    2024 May 28 19:25:04.363976 sonic-device INFO pmon#supervisord 2024-05-28 19:25:04,362 WARN exited: stormond (terminated by SIGKILL; not expected)
    2024 May 28 19:25:05.368716 sonic-device INFO pmon#supervisord 2024-05-28 19:25:05,367 INFO spawned: 'stormond' with pid 93
    2024 May 28 19:25:06.653840 sonic-device INFO pmon#stormond[93]: Starting Storage Monitoring Daemon
    2024 May 28 19:25:06.653840 sonic-device INFO pmon#stormond[93]: Storage Device: sda, Device Model: InnoDisk Corp. - mSATA 3IE3, Serial: BCA12310040200027
    2024 May 28 19:25:06.655318 sonic-device INFO pmon#stormond[93]: Polling Interval set to 3600 seconds
    2024 May 28 19:25:06.655318 sonic-device INFO pmon#stormond[93]: FSIO JSON file Interval set to 86400 seconds
    2024 May 28 19:25:06.933503 sonic-device INFO pmon#stormond[93]: Storage Device: sda, Firmware: S16425cG, health: 99%, Temp: 30C, FS IO Reads: 119725, FS IO Writes: 97367
    2024 May 28 19:25:06.933752 sonic-device INFO pmon#stormond[93]: Latest FSIO Reads: 21860, Latest FSIO Writes: 4033
    2024 May 28 19:25:06.934238 sonic-device INFO pmon#stormond[93]: Disk IO Reads: 26185, Disk IO Writes: 16070, Reserved Blocks: 63
    ```

  3. `STATE_DB` Status: Cleared
  4. JSON File: Persisted
  5. PROCFS Status: RESET, Initial Values
  6. JSON File Synced With `STATE_DB`?: UNSURE, DON'T CARE
  7. `stormond` Restarted: Yes