# Overview

This document describes the test plan for exercising 18 active gNMI platform-related paths with the headings:

-   `/system/logging` (1 path)
-   `/system/memory` (8 paths)
-   `/system/ntp` (10 paths)
-   `/system/state` (5 paths)
-   `/system/cpus` (2 path)

End to end tests may only access the device using the gNMI interface.

State paths are read-only paths.  They are used to reflect the state of the system.  For end to end tests, state paths cannot be directly modified unless there is a corresponding config path.

Config paths can be read or written.  Writing a config path indicates a desired system change.  There is a corresponding state path that is updated once the change takes effect.  Most of the gNMI config path tests verify both the gNMI get (read) path is operating as expected and that the gNMI set (write) path updates the system state as expected.

# Full List of Paths Covered

<table>
  <thead>
    <tr>
      <th>/system/logging/remote-servers/remote-server[host=syslog-ip-address]/state/host</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/system/memory/state/counters/correctable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/counters/uncorrectable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/active</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/buffers</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/cached</td>
      <td>Telemetry</td>
    </tr>
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
      <td>/system/ntp/state/enabled</td>
      <td>Telemetry*</td>
    </tr>
    <tr>
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/address</td>
      <td>Telemetry*</td>
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
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/peertype</td>
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
      <td>/system/cpus/cpu[index=<i>]/state/total/avg</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/cpus/cpu[index=<i>]/state/total/interval</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/state/current-datetime</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>

*Config paths for these two variables are not being supported. Discussed [here](https://docs.google.com/spreadsheets/d/1LjV1bVwlVuvPmCqCJlX9tpk8XFA2b6U6aI3UQpM8Kes/edit?disco=AAAAH3l26Xw) and [here](https://docs.google.com/document/d/1vgRpJfCSwvy_ZV6u9uyjolyInofPaukpxWN6xajsyzg/edit?disco=AAAAIUE7aG4).

/system/alarms paths are covered by: go/gpins-gnmi-alarms-e2e-test-plan  
/system/grpc-server: test plan ownership TBD depending on design.  
/system/ssh-server: test plan ownership TBD depending on design.  
/system/aaa: test plan ownership TBD depending on design.

# Logging Paths

<table>
  <thead>
    <tr>
      <th>/system/logging/remote-servers/remote-server[host=syslog-ip-address]/state/host</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>



## Tests

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Verify we can read two syslog ip addresses via gNMI get.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>One of the sylog ip addresses should be:</li>
</ul>
<ul>
<li>"172.20.0.192": for ipv4</li>
</ol>
</li>
</ul>
<ul>
<li>"[2001:4860:f802::c0]": for ipv4free installs</li>
</ol>
</li>
</ul>
<ul>
<li>The other syslog ip address should be:</li>
</ul>
<ul>
<li>"172.20.0.191": for ipv4</li>
</ol>
</li>
</ul>
<ul>
<li>"[2001:4860:f802::bf]": for ipv4free installs</li>
</ol>
</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

# Memory Paths

<table>
  <thead>
    <tr>
      <th>/system/memory/state/counters/correctable-ecc-errors</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/system/memory/state/counters/uncorrectable-ecc-errors</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/active</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/buffer</td>
      <td>Telemetry</td>
    </tr>
    <tr>
      <td>/system/memory/state/cached</td>
      <td>Telemetry</td>
    </tr>
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
  </tbody>
</table>


## Tests

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th>
Perform a gNMI get on the following 6 openconfig paths:
<li>/system/memory/state/active</li>
<li>/system/memory/state/buffer</li>
<li>/system/memory/state/cached</li>
<li>/system/memory/state/free</li>
<li>/system/memory/state/physical</li>
<li>/system/memory/state/used</li></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm:</li>
</ul>
<ul>
<li>active: 0 <= active <= physical</li>
</ol>
</li>
</ul>
<ul>
<li>additionally at time of test creation look at reported value and set a threshold we wouldn't expect to exceed (perhaps half of physical) 		</li>
</ol>
</li>
</ol>
</li>
</ul>
<ul>
<li>buffer: 0 <= buffer <= physical</li>
</ol>
</li>
</ul>
<ul>
<li>additionally at time of test creation look at reported value and set a threshold we wouldn't expect to exceed </li>
</ol>
</li>
</ol>
</li>
</ul>
<ul>
<li>cached: 0 <= cached <= physical</li>
</ol>
</li>
</ul>
<ul>
<li>additionally at time of test creation look at reported value and set a threshold we wouldn't expect to exceed (perhaps half of physical)</li>
</ol>
</li>
</ol>
</li>
</ul>
<ul>
<li>free: greater than half physical</li>
</ol>
</li>
</ul>
<ul>
<li>physical: (based on platform)</li>
</ol>
</li>
</ul>
<ul>
<li>16GB for Taygeta</li>
</ol>
</li>
</ol>
</li>
</ul>
<ul>
<li>32GB for Brixia</li>
</ol>
</li>
</ol>
</li>
</ul>
<ul>
<li>used: 0 <= used <= physical</li>
</ol>
</li>
</ul>
<ul>
<li>additionally at time of test creation look at reported value and set a threshold we wouldn't expect to exceed (perhaps half of physical)</li>
</ol>
</li>
</ol>
</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><br>
<ul>
<li>Perform a gNMI get on:</li>
</ul>
/system/memory/state/counters/correctable-ecc-errors<br>
/system/memory/state/counters/uncorrectable-ecc-errors<br>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm:</li>
</ul>
<ul>
<li>0 = uncorrectable-ecc-errors</li>
</ol>
</li>
</ul>
<ul>
<li>0 = correctable-ecc-errors*</li>
</ol>
</li>
</ul>
*Add a note/comment during test creation that correctable-ecc-errors greater than 0 is ok and the thresholds can be adjusted over time as issues are observed that don't indicate bad hardware.</td>
    </tr>
  </tbody>
</table>

# NTP Paths

<table>
  <thead>
    <tr>
      <th>/system/ntp/state/enabled</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
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
      <td>/system/ntp/servers/server[address=<ntp_address>]/state/peertype</td>
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

 
enabled 	boolean  
stratum 	uint8  
root_delay 	uint32		milliseconds  
offset		uint64		milliseconds  
poll-interval	uint32		seconds  
root-disperson uint64		milliseconds

> refid is not defined in openconfig-system.yang: but reference ids are defined in RFC5905 as 4 byte ascii strings and are commonly handled as a uint32.

> reach is not defined in openconfig-system.yang, but reach is defined as an 8 bit integer shift register in RF5905. (note that "ntpq -p" returns ‘reach' in octal)

> peertype is not defined in openconfig-system.yang. ntpq lists peer type as one of (local, unicast, multicast or broadcast) and display the type as a single char (lumb). I presume this will be defined as a string.
>
> ## Google Time Servers

> The four google time servers used by ntp are:  
# time1.google.com  
server 216.239.35.0 iburst minpoll 4  
server 2001:4860:4806:: iburst minpoll 4  
# time2.google.com  
server 216.239.35.4 iburst minpoll 4  
server 2001:4860:4806:4:: iburst minpoll 4  
# time3.google.com  
server 216.239.35.8 iburst minpoll 4  
server 2001:4860:4806:8:: iburst minpoll 4  
# time4.google.com  
server 216.239.35.12 iburst minpoll 4  
server 2001:4860:4806:c:: iburst minpoll 4

> 	These are not configurable on the switch.
## Tests

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI get on the ntp/state/enabled path.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm a return value of True.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI read on /system/ntp/servers to get the list of server address keys.</li>
</ul>
<ul>
<li>For each returned address key read:</li>
</ul>
<br>
/system/ntp/servers/server[address=<ntp_address>]/state/address</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Verify config/address values are in the above <a href="#heading=h.tck6pvlzhymw">list</a>.</li>
</ul>
<ul>
<li>Verify state/address values are in the above <a href="#bookmark=id.fabv4u6p4hkz">list</a>.</li>
</ul>
<ul>
<li>Verify all 4 google time servers listed above are present.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI read on /system/ntp/servers to get the list of server address keys.</li>
</ul>
<ul>
<li>For each address key perform a gNMI read of: </li>
</ul>
/system/ntp/servers/server[address=<ntp_address>]/state/stratum<br>
/system/ntp/servers/server[address=<ntp_address>]/state/root-delay<br>
/system/ntp/servers/server[address=<ntp_address>]/state/offset<br>
/system/ntp/servers/server[address=<ntp_address>]/state/poll-interval<br>
/system/ntp/servers/server[address=<ntp_address>]/state/root-dispersion<br>
/system/ntp/servers/server[address=<ntp_address>]/state/peertype<br>
/system/ntp/servers/server[address=<ntp_address>]/state/reach<br>
/system/ntp/servers/server[address=<ntp_address>]/state/refid</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm no error reading stratum, root-delay, offset, poll_interval, root_dispersion, refid, reach and peertype.</li>
</ul>
<ul>
<li>stratum < 3.</li>
</ul>
<ul>
<li>peertype = ‘u'</li>
</ul>
<ul>
<li>For each address key, if reach is not zero:</li>
</ul>
<ul>
<li>Confirm following are non-zero: root-delay, offset, poll_interval, root_dispersion. (intentionally skip refid)</li>
</ul>
<br>
Stratum is probably always 1.<br>
Reach should be non-zero if we can communicate with the server.<br>
Refid is generally 4 byte ascii error code, it could be a 4 octet, left justified, zero-padded ASCII string identifying a reference clock.<br>
All others are probably greater than 0.<br>
<br>
</td>
    </tr>
  </tbody>
</table>

State Paths

<table>
  <thead>
    <tr>
      <th><br>
/system/state/boot-time</th>
      <th><br>
Telemetry</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><br>
/system/state/hostname</td>
      <td><br>
Telemetry</td>
    </tr>
    <tr>
      <td><br>
/system/config/config-meta-data</td>
      <td><br>
Config</td>
    </tr>
    <tr>
      <td><br>
/system/state/config-meta-data</td>
      <td><br>
Telemetry</td>
    </tr>
  </tbody>
</table>

boot-time is of type uint64 in units of seconds since Unix Epoch.  
hostname (cardData.hostname in cmal) is of type string with max length of 253 bytes conforming to a regex pattern defined in [openconfig-inet-types.yang]

config-meta-data is defined as a string in [google-pins-system.yang](https://source.corp.google.com/gpins/third_party/sonic-buildimage/src/sonic-mgmt-common/models/yang/google-pins-system.yang):

```
     description
       "SMA generates a new config metadata for every new version
       of config that is pushed to the switch. The switch stores
       the meta data. When SMA wants to check if there is a need
       to re-push the configuration to the switch, it does a gNMI
       GET on the metadata from the switch and compares it with
       the meta data for the configuration returned by the config
       generator and if there is mismatch it initiates a new
       config push to the switch.";
     reference
       "TextProto representation of ConfigVersionMeta defined
       in config_meta.proto file:
         message ConfigVersionMeta {
           // The ModelSetId used to generate the config.
           optional platforms_model.ModelSetId msid = 1;
           // The config generator mpm version used to generate the config.
           optional GeneratorMpmVersion generator_mpm_version = 2;
         }";
```

## Tests

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Read boot-time: time1.</li>
</ul>
<ul>
<li>Delay three seconds.</li>
</ul>
<ul>
<li>Read boot-time: time2.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm: time2 > time1.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI get on hostname.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm no errors and return type is a string between 1 and 253 characters conforming to regex pattern for domain-name defined in openconfig-inet-types.yang.</li>
</ul>
<ul>
<li>Confirm value matches dhcp assigned hostname.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI get on state/config-meta-data and store result as string1.</li>
</ul>
<ul>
<li>Perform a gNMI set on config/config-meta-data with string "test1" or "test2" that isn't equal to string1. This is string 2.</li>
</ul>
<ul>
<li>Perform a gNMI get on config/config-meta-data and state/config-meta-data as string3 and string 4 respectively.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm no errors when calling gNMI get and set.</li>
</ul>
<ul>
<li>Confirm string1 has length greater than 0.</li>
</ul>
<ul>
<li>Confirm string1 is not equal to string2, string3 and string 4.</li>
</ul>
<ul>
<li>Confirm equality of string2, string3 and string4.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

# CPU Paths

<table>
  <thead>
    <tr>
      <th>/system/cpus/cpu[index=<i>]/state/total/avg</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>/system/cpus/cpu[index=<i>]/state/total/interval</td>
      <td>Telemetry</td>
    </tr>
  </tbody>
</table>

avg is a uint8 between 0 <= avg <= 100.  
interval is a uint64 in units of nanoseconds.
## Tests

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI read on /system/cpus/cpu to get the list of cpu index keys.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm 8 (verify at time of test creation) index keys are returned in range [0-7] inclusive with no duplicates.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>For cpu's 0 -> 7: read average cpu usage.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>For each cpu confirm:</li>
</ul>
0 <= avg <= 30</td>
    </tr>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>For cpu's 0 -> 7: read interval.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>For each cpu confirm: interval > 0.</li>
</ul>
<ul>
<li>(The default value for top is 3).</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

# DateTime Path

<table>
  <thead>
    <tr>
      <th>/system/state/current-datetime</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
  </tbody>
</table>

#### 

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform a gNMI get on current-datetime.</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Confirm date is within range yesterday/today/tomorrow.</li>
</ul>
<ul>
<li>Confirm time is with 6 hours of current time on test system.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

# Process Paths

<table>
  <thead>
    <tr>
      <th>/system/processes/process[pid=<process_id>]/state/memory-usage</th>
      <th>Telemetry</th>
    </tr>
  </thead>
  <tbody>
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

OpenConfig Definition here: [openconfig-procmon.yang](google3/third_party/openconfig/public/release/models/system/openconfig-procmon.yang).

## Tests

<table>
  <thead>
    <tr>
      <th><strong>Test</strong></th>
      <th><ul>
<li>Perform gNMI read on /system/processes/process[pid=*] to fetch the list of processes running on the switch. For each process, perform a gNMI read on the following paths:</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/memory-usage</li>
</ol>
</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/pid</li>
</ol>
</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/name</li>
</ol>
</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/cpu-utilization</li>
</ol>
</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/cpu-usage-user</li>
</ol>
</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/cpu-usage-system</li>
</ol>
</li>
</ul>
<ul>
<li>/system/processes/process[pid=<process_id>]/state/start-time</li>
</ol>
</li>
</ul>
</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Validations</strong></td>
      <td><ul>
<li>Verify that at least 1 PID exists on the switch.</li>
</ul>
<ul>
<li>Verify that the <code>memory-usage</code> of a process is less than the total memory available which can be fetched from /system/memory/state/ paths.</li>
</ul>
<ul>
<li>Verify that <code>pid</code> of a process matches <code>pid=<process_id></code> key of /system/processes/process[pid=<process_id>].</li>
</ul>
<ul>
<li>Verify that <code>name</code> is not empty.</li>
</ul>
<ul>
<li>Verify that <code>cpu-utilization</code> is <= 100%.</li>
</ul>
<ul>
<li>Verify that <code>cpu-usage-user</code> > 0 and <code>cpu-usage-system</code> => 0. (maybe none of them > system boot time?)</li>
</ul>
<ul>
<li>Verify that <code>start-time</code> is less than the boot time of the switch which can be fetched from /system/state/boot-time path.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>
