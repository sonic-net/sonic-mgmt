# Overview

This document describes the test plan for exercising the following system related Openconfig paths with the headings:
- /system/logging
- /system/memory
- /system/ntp
- /system/state
- /system/cpus

End to end tests may only access the device using the gNMI interface.  

State paths are read-only paths.  They are used to reflect the state of the system.  For end to end tests, state paths cannot be directly modified unless there is a corresponding config path.

Config paths can be read or written.  Writing a config path indicates a desired system change.  There is a corresponding state path that is updated once the change takes effect.  Most of the gNMI config path tests verify both the gNMI get (read) path is operating as expected and that the gNMI set (write) path updates the system state as expected.

## Full List of Paths Covered

<table>
  <tbody>
    <tr>
      <td>/system/logging/remote-servers/remote-server[host=syslog-ip-address]/state/host</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/counters/correctable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/counters/uncorrectable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
      <td>/system/memory/state/free</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/physical</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/used</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/state/enabled</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/address</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/stratum</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/root-delay</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/offset</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/poll-interval</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/root-dispersion</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/reach</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/refid</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/state/boot-time</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/state/hostname</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/config/config-meta-data</td>
      <td>Config</td>
    </tr>
    <tr>
      <td>/system/state/config-meta-data</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/cpus/cpu[index=<>]/state/index</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/cpus/cpu[index=<>]/state/total/avg</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/cpus/cpu[index=<>]/state/total/interval</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/state/current-datetime</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/memory-usage</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/pid</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/name</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/cpu-utilization</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/cpu-usage-user</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/cpu-usage-system</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/start-time</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>



# Logging Paths

<table>
  <tbody>
    <tr>
      <td>/system/logging/remote-servers/remote-server[host=syslog-ip-address]/state/host</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>

## Tests
### Test

Perform wildcard gNMI get to fetch the syslog server IP addresses:
* /system/logging/remote-servers/remote-server[host=*]/state/host.

### Validations
 * List of IP addresses returned by the switch match the expected syslog servers IP addresses.
 * Number of IP addresses match the expected number of syslog servers.
 * IP addresses are valid IPv4/IPv6 addresses and are not repeated.
 * IP address matches the key ([host=syslog-ip-address]).


# Memory Paths

<table>
  <tbody>
    <tr>
      <td>/system/memory/state/free</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/physical</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/used</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/counters/correctable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/counters/uncorrectable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>

## Tests
### Test
Perform a gNMI get on the following openconfig paths:
* /system/memory/state/physical
* /system/memory/state/free
* /system/memory/state/used

### Validations
Set expected thresholds for *free* and *used* memories.

* Physical memory is within the expected physical memory range for the switch.
* 0 <= free <= physical && free <= defined threshold.
* 0 <= used <= physical && used <= defined threshold.

### Test
Perform a gNMI get on the following openconfig paths:
* /system/memory/state/counters/correctable-ecc-errors
* /system/memory/state/counters/uncorrectable-ecc-errors

### Validations
Set expected thresholds for both of these errors.

* 0 <= correctable-ecc-errors <= defined threshold.
* 0 <= uncorrectable-ecc-errors <= defined threshold.


# NTP Paths

<table>
  <tbody>
    <tr>
      <td>/system/ntp/state/enabled</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/address</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/stratum</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/root-delay</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/offset</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/poll-interval</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/root-dispersion</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/reach</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/refid</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>

OpenConfig Definition: 

    enabled 	boolean

    stratum 	uint8

    root_delay 	uint32		milliseconds

    offset		uint64		milliseconds

    poll-interval	uint32		seconds

    root-disperson uint64		milliseconds

    refid is not defined in openconfig-system.yang: but reference ids are defined in RFC5905 as 4 byte ascii strings and are commonly handled as a uint32.

    reach is not defined in openconfig-system.yang, but reach is defined as an 8 bit integer shift register in RF5905. (note that “ntpq -p” returns ‘reach’ in octal).

## Tests
### Test
Enable NTP on the switch.

Perform a gNMI get on:
* ntp/state/enabled

### Validations
* Value is True.

### Test
Perform a wildcard gNMI get to get the list of NTP servers:
* /system/ntp/servers/server[address=*]/state

For each returned server address, fetch the value of:
* /system/ntp/servers/server[address=<ntp_address>]/state/address

For each returned server address, fetch the value of:
* /system/ntp/servers/server[address=<ntp_address>]/state/stratum
* /system/ntp/servers/server[address=<ntp_address>]/state/root-delay
* /system/ntp/servers/server[address=<ntp_address>]/state/offset
* /system/ntp/servers/server[address=<ntp_address>]/state/poll-interval
* /system/ntp/servers/server[address=<ntp_address>]/state/root-dispersion
* /system/ntp/servers/server[address=<ntp_address>]/state/reach
* /system/ntp/servers/server[address=<ntp_address>]/state/refid

### Validations
* The number of IP addresses returned by the switch is equal to the expected number of NTP servers.
* *address* leaf matches the NTP address key *[address=<ntp_address>]*.
* All expected IP addresses (IPv4 and IPv6) are returned by the switch.

For each NTP server, fetch the value of *reach* leaf. Perform the following validations if the NTP server is reachable i.e. reach > 0:
* 0 <= stratum <= defined threshold.
* root-delay > 0.
* root-dispersion != 0.

For each unreachable NTP server i.e reach == 0, perform the following validations:
* offset == 0 (switch shouldn't be synchronized with an unreachable NTP server).

For each NTP server, perform the following validations irrespective of NTP server reachability:
* refid is not empty.
* poll-interval != 0.


# State Paths

<table>
  <tbody>
    <tr>
      <td>/system/state/boot-time </td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/state/hostname</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/config/config-meta-data</td>
      <td>Config</td>
    </tr>
    <tr>
      <td>/system/state/config-meta-data</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>


## Tests
### Test
* gNMI get /system/state/boot-time: time1.
* Reboot the switch.
* gNMI get /system/state/boot-time: time2.
* Perform gNMI get on /system/state/boot-time multiple times.

### Validations
* time2 > time1.
* boot-time == time2 each time it is fetched from the switch after reboot.

### Test
Perform a gNMI get on /system/state/hostname.

### Validations
* Value matches the expected hostname of the switch.

### Test
* Perform gNMI set on /system/config/config-meta-data.
* Perform gNMI get on /system/config/config-meta-data and /system/state/config-meta-data.

Repeat the above steps multiple times with different metadata values.

### Validations
* gNMI get in step 2 should match the value configured in step 1.


# CPU Paths

<table>
  <tbody>
    <tr>
      <td>/system/cpus/cpu[index=<>]/state/index</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/cpus/cpu[index=<>]/state/total/avg</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/cpus/cpu[index=<>]/state/total/interval</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>


## Tests

### Test 
Perform a wildcard gNMI get to get the list of CPU indexes:
* /system/cpus/cpu[index=*]/state

For each of the above CPU, perform gNMI get to fetch the average utilization for a period of time:
* /system/cpus/cpu[index=<>]/state/total/avg

For each of the above CPU, perform gNMI get to fetch the CPU interval:
* /system/cpus/cpu[index=<>]/state/total/interval

### Validations
* Number of CPU indexes returned by the switch match the expected number of indexes.
* The list of indexes returned by the switch matches the expected indexes.
* All indexes returned by the switch must be unique. 

For each CPU, define a threshold for the average usage.
* 0 <= avg <= defined threshold for that CPU.
* Cumulate average usage of all CPUs > 0.
* interval > 0.


# DateTime Path

<table>
  <tbody>
    <tr>
      <td>/system/state/current-datetime</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>

## Tests

### Test
* Fetch current time: time1.
* Perform gNMI get on /system/state/current-datetime: time2.
* Fetch current time: time3.

### Validations
* time1 < time2 < time3.

# Process Paths

<table>
  <tbody>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/memory-usage</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/pid</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/name</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/cpu-utilization</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/cpu-usage-user</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/cpu-usage-system</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/processes/process[pid=<process_id>]/state/start-time</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>


## Tests

### Test
Perform wildcard gNMI get to fetch information of all the processes running on the switch: 
* /system/processes/process[pid=*]/state

For each process in the process information subtree, fetch the following paths:
* /system/processes/process[pid=]/state/memory-usage
* /system/processes/process[pid=]/state/pid
* /system/processes/process[pid=]/state/name
* /system/processes/process[pid=]/state/cpu-utilization
* /system/processes/process[pid=]/state/cpu-usage-user
* /system/processes/process[pid=]/state/cpu-usage-system
* /system/processes/process[pid=]/state/start-time

Perfrom gNMI get on the following paths:
* /system/state/boot-time
* /system/memory/state/physical

### Validations
For each process returned in the process information subtree:
* pid != 0 and matches [pid=<process_id] key.
* name is not empty.
* 0 <= cpu-utilization < 100.
* 0 <= memory-usage < physical (memory usage cannot be more than the system memory).
* memory-limit != 0. Define memory limits for each process and verify that memory-limt matches the expected value.
* 0 < start-time < boot-time (process start time cannot be before the system boot-time).
* cpu-usage-user => 0.
* cpu-usage-system => 0.
