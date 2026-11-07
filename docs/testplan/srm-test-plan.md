SONiC System Resource Monitoring — Test Plan

Feature Name: System Resource Monitoring (SRM)
Version: 1.1
Date: 2026-05-19

Overview

This test plan validates the System Resource Monitoring (SRM) feature in SONiC, covering CPU, memory (RAM), and storage monitoring with threshold-based alarming and syslog notifications.
Scope


CPU utilization monitoring (per core — current snapshot and historical)
Memory (RAM) utilization monitoring (current snapshot and historical)
Storage partition monitoring and utilization (current snapshot only)
Threshold configuration and alarm generation for CPU, RAM, and storage
Syslog notification for threshold violations
CLI configuration and show command validation

Out of Scope


Temperature monitoring
Fan tray / fan monitoring and management
SNMP trap notifications
Removable storage device monitoring
Container-level CPU utilization
Aggregate CPU utilization across all logical CPUs
Per CPU socket utilization (multi-socket systems)
History data persistence across system restarts
Storage utilization history


Test Objectives


Verify CPU utilization retrieval per logical core (current snapshot)
Validate CPU utilization history collection, configuration, and display
Verify memory (RAM) utilization retrieval (current snapshot)
Validate RAM utilization history collection, configuration, and display
Verify storage partition information and utilization reporting
Test threshold configuration for CPU, RAM, and storage
Validate alarm generation and automatic clearing for threshold violations
Verify syslog notification for all threshold events
Validate CLI config and show command behavior including edge cases


Testbed Setup

Topology


[Test Server] <--SSH--> [SONiC DUT with SRM Feature]
                              |
                        [Monitoring Tools]
Insert at cursor

Requirements


SONiC device with SRM feature enabled (SONiC VS supported)
Multiple CPU cores for per-core testing
Sufficient RAM for threshold testing
Multiple storage partitions (permanently attached)
Syslog collection mechanism
Load generation tools (stress-ng, sysbench, dd)


Test Cases


Section 1 — CPU Utilization Monitoring (RF-01)

TC-1.1: Current CPU Utilization Per Core — Basic Retrieval

Objective: Verify show platform cpu returns current utilization per logical core
Reference: SONiC_SRM/RF-01
Priority: P0
Steps:

Run show platform cpu

Verify output contains columns: Cpu Index, Core Index, Utilization, Alarm Status, Threshold, Timestamp

Verify a row exists for each logical CPU core
Verify utilization values are in the format X% and within 0–100%
Verify Timestamp is in format YYYYMMDD HH:MM:SSZ

Compare utilization values with mpstat or top output

Expected Result:

All logical cores listed with individual utilization values
Values within ±5% of Linux tool readings
Output format matches specification


TC-1.2: CPU Utilization — Threshold Displayed as NA When Not Configured

Objective: Verify Threshold column shows NA when no threshold is configured in Config DB
Reference: SONiC_SRM/RF-01, RF-06
Priority: P0
Steps:

Ensure no CPU threshold entry exists in Config DB (fresh state)
Run show platform cpu

Verify Threshold column shows N/A for all cores
Verify Alarm Status shows Cleared


Expected Result:


Threshold column displays N/A


Alarm Status displays Cleared



TC-1.3: CPU Utilization — Threshold Displayed as NA When Set to 0

Objective: Verify threshold value of 0 is treated as disabled (NA)
Reference: SONiC_SRM/RF-06
Priority: P0
Steps:

Run sudo config platform cpu utilization-threshold 0

Run show platform cpu

Verify Threshold column shows NA for all cores

Expected Result:


Threshold column displays NA when threshold is set to 0


TC-1.4: CPU Utilization Under Load

Objective: Verify CPU monitoring reflects actual load conditions
Reference: SONiC_SRM/RF-01
Priority: P1
Steps:

Record baseline CPU utilization via show platform cpu

Generate ~50% CPU load using stress-ng

Run show platform cpu, verify per-core utilization increases
Generate ~100% CPU load
Run show platform cpu, verify near-100% utilization
Stop load, verify utilization returns to baseline

Expected Result:

Per-core utilization accurately reflects load
Values consistent with mpstat readings


Section 2 — CPU Utilization History (RF-02)

TC-2.1: CPU History — Default Status is Disabled

Objective: Verify CPU history collection is disabled by default
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

On a fresh system, run show platform cpu-history-status

Verify output shows Status : Disabled


Expected Result:

Default status is Disabled



TC-2.2: CPU History — Enable and Verify Status

Objective: Verify enabling CPU history collection
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

Run sudo config platform cpu-history status enable

Run show platform cpu-history-status

Verify output shows Status : Enabled


Expected Result:

Status changes to Enabled after command


TC-2.3: CPU History — Disable and Verify Status

Objective: Verify disabling CPU history collection
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

Enable history: sudo config platform cpu-history status enable

Disable history: sudo config platform cpu-history status disable

Run show platform cpu-history-status

Verify output shows Status : Disabled


Expected Result:

Status changes to Disabled



TC-2.4: CPU History — Configure Measurement Interval When Disabled

Objective: Verify measurement interval can only be configured when status is disabled
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

Ensure history status is Disabled

Run sudo config platform cpu-history measurement-interval 3

Verify command succeeds
Run show platform cpu-history and verify Interval : 3 minutes


Expected Result:

Configuration accepted when status is disabled
Interval reflected in show output


TC-2.5: CPU History — Configure Duration When Disabled

Objective: Verify duration can only be configured when status is disabled
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

Ensure history status is Disabled

Run sudo config platform cpu-history duration 30

Verify command succeeds
Run show platform cpu-history and verify Duration : 30 minutes


Expected Result:

Configuration accepted when status is disabled
Duration reflected in show output


TC-2.6: CPU History — Configuration Rejected When Status is Enabled

Objective: Verify measurement-interval and duration cannot be changed while history is enabled
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

Enable history: sudo config platform cpu-history status enable

Attempt: sudo config platform cpu-history measurement-interval 5

Verify command fails with an error
Attempt: sudo config platform cpu-history duration 60

Verify command fails with an error

Expected Result:

Both commands rejected with appropriate error message
Existing configuration unchanged


TC-2.7: CPU History — Default Duration and Interval Values

Objective: Verify default history duration (60 min) and interval (5 min)
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

On a fresh system (no custom config), enable history
Run show platform cpu-history

Verify Duration : 60 minutes and Interval : 5 minutes


Expected Result:

Default duration: 60 minutes
Default interval: 5 minutes


TC-2.8: CPU History — Data Collection and Display When Enabled

Objective: Verify history data is collected and displayed per core
Reference: SONiC_SRM/RF-02
Priority: P0
Steps:

Configure: sudo config platform cpu-history measurement-interval 1 (while disabled)
Configure: sudo config platform cpu-history duration 30 (while disabled)
Enable: sudo config platform cpu-history status enable

Wait for at least 3 intervals (3 minutes)
Run show platform cpu-history

Verify output contains:

Status : Enabled
Duration : 30 minutes
Interval : 1 minutes
Table with columns: Cpu Index, Core Index, Timestamp, Utilization

Separate rows per core per timestamp


Verify timestamps are spaced ~1 minute apart

Expected Result:

History data displayed per core with correct timestamps
Each row represents one measurement interval per core


TC-2.9: CPU History — Show Behavior When Status is Disabled (No Data)

Objective: Verify no table is shown when status is disabled and no data exists
Reference: SONiC_SRM/RF-02
Priority: P1
Steps:

Ensure history is disabled and no history data exists in Redis
Run show platform cpu-history

Verify no history table is displayed

Expected Result:

No table output when status is disabled and no data in Redis


TC-2.10: CPU History — Show Behavior When Status is Disabled (Data Present in Redis)

Objective: Verify history table is shown when status is disabled but data exists in Redis
Reference: SONiC_SRM/RF-02
Priority: P1
Steps:

Enable history, wait for data to accumulate
Disable history: sudo config platform cpu-history status disable

Run show platform cpu-history

Verify output shows Status : Disabled and the existing history table

Expected Result:

Status shows Disabled

Existing Redis data is still displayed


TC-2.11: CPU History — Data Not Retained Across Reboot

Objective: Verify history data is cleared after system reboot
Reference: SONiC_SRM/RF-02
Priority: P1
Steps:

Enable history, wait for data to accumulate
Verify history data present via show platform cpu-history

Reboot the system
After reboot, run show platform cpu-history

Verify history table is empty

Expected Result:

History data cleared after reboot
Configuration (duration/interval/status) preserved


TC-2.12: CPU History — Invalid Interval Range Rejected

Objective: Verify out-of-range interval values are rejected
Reference: SONiC_SRM/RF-02
Priority: P1
Steps:

Ensure history is disabled
Attempt: sudo config platform cpu-history measurement-interval 0

Verify error thrown
Attempt: sudo config platform cpu-history measurement-interval 11

Verify error thrown
Attempt: sudo config platform cpu-history measurement-interval -1

Verify error thrown

Expected Result:

Values outside range 1–10 rejected with error message
Valid range: 1–10


TC-2.13: CPU History — Invalid Duration Range Rejected

Objective: Verify out-of-range duration values are rejected
Reference: SONiC_SRM/RF-02
Priority: P1
Steps:

Ensure history is disabled
Attempt: sudo config platform cpu-history duration 29

Verify error thrown
Attempt: sudo config platform cpu-history duration 181

Verify error thrown

Expected Result:

Values outside range 30–180 rejected with error message
Valid range: 30–180


TC-2.14: CPU History — Buffer FIFO Behavior

Objective: Verify oldest entries are removed when buffer is full
Reference: SONiC_SRM/RF-02
Priority: P1
Steps:

Configure: duration=30, interval=1 (30 entries max), enable history
Wait for buffer to fill (30+ minutes)
Verify exactly 30 entries in history
Wait for one more interval
Verify still 30 entries, oldest timestamp removed, newest added

Expected Result:

FIFO behavior: oldest entry removed when buffer full
Entry count stays at duration/interval maximum


Section 3 — Memory (RAM) Utilization Monitoring (RF-03)

TC-3.1: Current RAM Utilization — Basic Retrieval

Objective: Verify show platform ram returns current memory utilization
Reference: SONiC_SRM/RF-03
Priority: P0
Steps:

Run show platform ram

Verify output contains columns: Total Memory, Used Memory, Available, Utilization, Alarm Status, Threshold, Timestamp

Verify values are in KB units
Verify: Total Memory ≈ Used Memory + Available
Verify utilization percentage is consistent with used/total ratio
Compare with free command output

Expected Result:

All fields populated correctly
Values accurate within ±2% of free command
Arithmetic consistency: Total ≈ Used + Available


TC-3.2: RAM Utilization — Threshold Displayed as NA When Not Configured

Objective: Verify Threshold shows N/A when no threshold configured
Reference: SONiC_SRM/RF-03, RF-07
Priority: P0
Steps:

Ensure no RAM threshold in Config DB
Run show platform ram

Verify Threshold column shows N/A


Expected Result:


Threshold displays N/A



TC-3.3: RAM Utilization Under Load

Objective: Verify RAM monitoring reflects actual memory allocation
Reference: SONiC_SRM/RF-03
Priority: P1
Steps:

Record baseline via show platform ram

Allocate memory to increase usage by ~20%
Run show platform ram, verify Used Memory and Utilization increase
Release memory, verify values return to baseline

Expected Result:

RAM utilization accurately reflects allocation changes


Section 4 — Memory (RAM) Utilization History (RF-04)

TC-4.1: RAM History — Default Status is Disabled

Objective: Verify RAM history is disabled by default
Reference: SONiC_SRM/RF-04
Priority: P0
Steps:

On a fresh system, run show platform ram-history

Verify no table displayed (status disabled, no data)

Expected Result:

No history table shown by default


TC-4.2: RAM History — Enable and Collect Data

Objective: Verify RAM history data is collected and displayed when enabled
Reference: SONiC_SRM/RF-04
Priority: P0
Steps:

Ensure history is disabled
Configure: sudo config platform ram-history measurement-interval 1

Configure: sudo config platform ram-history duration 30

Enable: sudo config platform ram-history status enable

Wait for at least 3 intervals
Run show platform ram-history

Verify output contains:

Status : Enabled
Duration : 30 minutes
Interval : 1 minutes
Table with columns: Timestamp, Total Memory, Used Memory, Available, Utilization



Verify timestamps spaced ~1 minute apart

Expected Result:

History data displayed with correct format and timing


TC-4.3: RAM History — Configuration Rejected When Enabled

Objective: Verify interval and duration cannot be changed while history is enabled
Reference: SONiC_SRM/RF-04
Priority: P0
Steps:

Enable RAM history
Attempt: sudo config platform ram-history measurement-interval 5

Verify error
Attempt: sudo config platform ram-history duration 60

Verify error

Expected Result:

Both commands rejected with error when status is enabled


TC-4.4: RAM History — Default Duration and Interval

Objective: Verify default history duration (60 min) and interval (5 min)
Reference: SONiC_SRM/RF-04
Priority: P0
Steps:

On fresh system, enable RAM history
Run show platform ram-history

Verify Duration : 60 minutes and Interval : 5 minutes


Expected Result:

Default duration: 60 minutes, default interval: 5 minutes


TC-4.5: RAM History — Show Behavior When Disabled (No Data)

Objective: Verify no table shown when disabled and no Redis data
Reference: SONiC_SRM/RF-04
Priority: P1
Steps:

Ensure RAM history disabled and no data in Redis
Run show platform ram-history

Verify no table displayed

Expected Result:

No output table when disabled with no data


TC-4.6: RAM History — Show Behavior When Disabled (Data in Redis)

Objective: Verify history table shown when disabled but data exists in Redis
Reference: SONiC_SRM/RF-04
Priority: P1
Steps:

Enable RAM history, wait for data
Disable: sudo config platform ram-history status disable

Run show platform ram-history

Verify Status : Disabled and history table displayed

Expected Result:

Status shows Disabled, existing data still displayed


TC-4.7: RAM History — Data Not Retained Across Reboot

Objective: Verify RAM history cleared after reboot
Reference: SONiC_SRM/RF-04
Priority: P1
Steps:

Enable RAM history, accumulate data
Reboot system
Run show platform ram-history

Verify history table is empty

Expected Result:

History cleared after reboot; configuration preserved


TC-4.8: RAM History — Invalid Range Values Rejected

Objective: Verify out-of-range values rejected for interval and duration
Reference: SONiC_SRM/RF-04
Priority: P1
Steps:

Ensure RAM history disabled
Attempt interval=0, interval=11 — verify errors
Attempt duration=29, duration=181 — verify errors

Expected Result:

Interval valid range: 1–10; Duration valid range: 30–180
Out-of-range values rejected with error


TC-4.9: RAM History — Independent Configuration from CPU History

Objective: Verify RAM history settings are independent of CPU history settings
Reference: SONiC_SRM/RF-04
Priority: P1
Steps:

Configure CPU history: duration=60, interval=5
Configure RAM history: duration=30, interval=2
Enable both
Run show platform cpu-history — verify duration=60, interval=5
Run show platform ram-history — verify duration=30, interval=2

Expected Result:

CPU and RAM history configurations are fully independent


Section 5 — Storage Monitoring (RF-05)

TC-5.1: Storage — Partition Information and Utilization

Objective: Verify show platform storage reports all mounted permanently attached partitions
Reference: SONiC_SRM/RF-05
Priority: P0
Steps:

Run show platform storage

Verify output contains columns: Device, Partition, Total, Used, Available, Utilization, Alarm Status, Threshold, Timestamp

Verify all mounted partitions of permanently attached devices are listed
Compare partition list with df -h output
Verify removable devices (USB) are excluded
Verify utilization percentage is consistent with used/total

Expected Result:

All mounted permanently attached partitions listed
Utilization values match df -h within ±1%
Removable devices excluded


TC-5.2: Storage — Only Mounted Partitions Reported

Objective: Verify unmounted partitions are excluded
Reference: SONiC_SRM/RF-05
Priority: P1
Steps:

Identify an unmounted partition on the device
Run show platform storage

Verify unmounted partition is not listed

Expected Result:

Only currently mounted partitions appear in output


TC-5.3: Storage — Utilization Changes Reflected

Objective: Verify storage monitoring reflects file system changes
Reference: SONiC_SRM/RF-05
Priority: P1
Steps:

Record initial utilization via show platform storage

Create large files to increase usage by ~10%
Run show platform storage, verify utilization increased
Delete files, verify utilization decreases

Expected Result:

Utilization accurately reflects file system state

TC-5.4: Storage — Threshold Displayed as NA When Not Configured

Objective: Verify Threshold shows N/A when no threshold configured
Reference: SONiC_SRM/RF-05, RF-08
Priority: P0
Steps:

Ensure no storage threshold in Config DB
Run show platform storage

Verify Threshold column shows N/A for all partitions
Verify Alarm Status shows Cleared


Expected Result:


Threshold displays N/A


Alarm Status displays Cleared



Section 6 — CPU Threshold and Alarm (RF-06)

TC-6.1: CPU Threshold — Configure Valid Threshold

Objective: Verify CPU utilization threshold can be configured
Reference: SONiC_SRM/RF-06
Priority: P0
Steps:

Run sudo config platform cpu utilization-threshold 90

Run show platform cpu

Verify Threshold column shows 90% for all cores

Expected Result:

Threshold value reflected in show output for all cores


TC-6.2: CPU Threshold — Default Value (85%)

Objective: Verify default CPU threshold is 85%
Reference: SONiC_SRM/RF-06
Priority: P0
Steps:

On a fresh system with no threshold configured, apply default
Verify default threshold is 85%
Run show platform cpu and confirm Threshold shows 85%


Expected Result:

Default CPU threshold: 85%


TC-6.3: CPU Threshold — Alarm Generated When Threshold Exceeded

Objective: Verify alarm is generated when CPU utilization exceeds threshold
Reference: SONiC_SRM/RF-06
Priority: P0
Steps:

Configure threshold to a value below current load (e.g., 10%)
Run show platform cpu

Verify Alarm Status shows Active for affected cores
Verify syslog contains threshold violation entry

Expected Result:


Alarm Status shows Active when utilization > threshold
Syslog entry generated for the violation


TC-6.4: CPU Threshold — Alarm Cleared When Utilization Returns Below Threshold

Objective: Verify alarm auto-clears when utilization drops below threshold
Reference: SONiC_SRM/RF-06
Priority: P0
Steps:

Trigger CPU alarm (utilization > threshold)
Verify Alarm Status shows Active

Reduce CPU load below threshold
Run show platform cpu

Verify Alarm Status returns to Cleared

Verify syslog contains alarm cleared entry

Expected Result:

Alarm auto-clears when utilization drops below threshold
Syslog entry generated for alarm clearance


TC-6.5: CPU Threshold — Invalid Range Rejected

Objective: Verify out-of-range threshold values are rejected
Reference: SONiC_SRM/RF-06
Priority: P1
Steps:

Attempt: sudo config platform cpu utilization-threshold 101

Verify error thrown
Attempt: sudo config platform cpu utilization-threshold -1

Verify error thrown

Expected Result:

Values outside range 0–100 rejected with error message


TC-6.6: CPU Threshold — Threshold Set to 0 Displays NA

Objective: Verify threshold=0 disables alarming and shows NA
Reference: SONiC_SRM/RF-06
Priority: P0
Steps:

Run sudo config platform cpu utilization-threshold 0

Run show platform cpu

Verify Threshold column shows NA

Verify no alarm generated regardless of CPU load

Expected Result:


Threshold displays NA

No alarm generated when threshold is 0


Section 7 — RAM Threshold and Alarm (RF-07)

TC-7.1: RAM Threshold — Configure Valid Threshold

Objective: Verify RAM utilization threshold can be configured
Reference: SONiC_SRM/RF-07
Priority: P0
Steps:

Run sudo config platform ram utilization-threshold 90

Run show platform ram

Verify Threshold column shows 90%


Expected Result:

Threshold value reflected in show output


TC-7.2: RAM Threshold — Default Value (80%)

Objective: Verify default RAM threshold is 80%
Reference: SONiC_SRM/RF-07
Priority: P0
Steps:

On a fresh system, verify default RAM threshold is 80%
Run show platform ram and confirm Threshold shows 80%


Expected Result:

Default RAM threshold: 80%


TC-7.3: RAM Threshold — Alarm Generated When Threshold Exceeded

Objective: Verify alarm generated when RAM utilization exceeds threshold
Reference: SONiC_SRM/RF-07
Priority: P0
Steps:

Configure threshold below current RAM utilization (e.g., 10%)
Run show platform ram

Verify Alarm Status shows Active

Verify syslog contains threshold violation entry

Expected Result:


Alarm Status shows Active

Syslog entry generated


TC-7.4: RAM Threshold — Alarm Cleared Automatically

Objective: Verify alarm auto-clears when RAM utilization drops below threshold
Reference: SONiC_SRM/RF-07
Priority: P0
Steps:

Trigger RAM alarm (utilization > threshold)
Verify Alarm Status shows Active

Release memory to drop utilization below threshold
Run show platform ram

Verify Alarm Status returns to Cleared

Verify syslog contains alarm cleared entry

Expected Result:

Alarm auto-clears
Syslog entry for clearance generated


TC-7.5: RAM Threshold — Invalid Range Rejected

Objective: Verify out-of-range threshold values are rejected
Reference: SONiC_SRM/RF-07
Priority: P1
Steps:

Attempt: sudo config platform ram utilization-threshold 101

Verify error thrown
Attempt: sudo config platform ram utilization-threshold -1

Verify error thrown

Expected Result:

Values outside 0–100 rejected with error


TC-7.6: RAM Threshold — Threshold Set to 0 Displays NA

Objective: Verify threshold=0 disables alarming and shows NA
Reference: SONiC_SRM/RF-07
Priority: P0
Steps:

Run sudo config platform ram utilization-threshold 0

Run show platform ram

Verify Threshold column shows NA

Verify no alarm generated

Expected Result:


Threshold displays NA

No alarm generated


Section 8 — Storage Threshold and Alarm (RF-08)

TC-8.1: Storage Threshold — Configure Valid Threshold

Objective: Verify storage utilization threshold can be configured
Reference: SONiC_SRM/RF-08
Priority: P0
Steps:

Run sudo config platform storage utilization-threshold 90

Run show platform storage

Verify Threshold column shows 90% for all partitions

Expected Result:

Threshold value reflected in show output


TC-8.2: Storage Threshold — Default Value (75%)

Objective: Verify default storage threshold is 75%
Reference: SONiC_SRM/RF-08
Priority: P0
Steps:

On a fresh system, verify default storage threshold is 75%
Run show platform storage and confirm Threshold shows 75%


Expected Result:

Default storage threshold: 75%


TC-8.3: Storage Threshold — Alarm Generated When Threshold Exceeded

Objective: Verify alarm generated when storage utilization exceeds threshold
Reference: SONiC_SRM/RF-08
Priority: P0
Steps:

Configure threshold below current partition utilization
Run show platform storage

Verify Alarm Status shows Active for affected partitions
Verify syslog contains threshold violation entry

Expected Result:


Alarm Status shows Active

Syslog entry generated


TC-8.4: Storage Threshold — Alarm Cleared Automatically

Objective: Verify alarm auto-clears when storage utilization drops below threshold
Reference: SONiC_SRM/RF-08
Priority: P0
Steps:

Trigger storage alarm (utilization > threshold)
Verify Alarm Status shows Active

Delete files to reduce utilization below threshold
Run show platform storage

Verify Alarm Status returns to Cleared

Verify syslog contains alarm cleared entry

Expected Result:

Alarm auto-clears
Syslog clearance entry generated


TC-8.5: Storage Threshold — Invalid Range Rejected

Objective: Verify out-of-range threshold values are rejected
Reference: SONiC_SRM/RF-08
Priority: P1
Steps:

Attempt: sudo config platform storage utilization-threshold 101

Verify error thrown
Attempt: sudo config platform storage utilization-threshold -1

Verify error thrown

Expected Result:

Values outside 0–100 rejected with error


TC-8.6: Storage Threshold — Threshold Set to 0 Displays NA

Objective: Verify threshold=0 disables alarming and shows NA
Reference: SONiC_SRM/RF-08
Priority: P0
Steps:

Run sudo config platform storage utilization-threshold 0

Run show platform storage

Verify Threshold column shows NA

Verify no alarm generated

Expected Result:


Threshold displays NA

No alarm generated


Section 9 — Syslog Notifications (RF-09)

TC-9.1: Syslog — CPU Threshold Violation Logged

Objective: Verify syslog entry generated when CPU threshold exceeded
Reference: SONiC_SRM/RF-09
Priority: P0
Steps:

Configure CPU threshold below current utilization
Monitor syslog (tail -f /var/log/syslog)
Verify syslog entry appears indicating CPU threshold violation
Verify log contains: resource type (CPU), core index, utilization value, threshold value

Expected Result:

Syslog entry generated with relevant details on threshold breach


TC-9.2: Syslog — CPU Alarm Cleared Logged

Objective: Verify syslog entry generated when CPU alarm clears
Reference: SONiC_SRM/RF-09
Priority: P0
Steps:

Trigger CPU alarm
Reduce CPU load below threshold
Verify syslog entry appears indicating alarm cleared

Expected Result:

Syslog entry generated on alarm clearance


TC-9.3: Syslog — RAM Threshold Violation Logged

Objective: Verify syslog entry generated when RAM threshold exceeded
Reference: SONiC_SRM/RF-09
Priority: P0
Steps:

Configure RAM threshold below current utilization
Monitor syslog
Verify syslog entry appears with RAM threshold violation details

Expected Result:

Syslog entry generated with resource type (RAM), utilization, threshold


TC-9.4: Syslog — RAM Alarm Cleared Logged

Objective: Verify syslog entry generated when RAM alarm clears
Reference: SONiC_SRM/RF-09
Priority: P0
Steps:

Trigger RAM alarm
Release memory below threshold
Verify syslog entry for alarm clearance

Expected Result:

Syslog clearance entry generated


TC-9.5: Syslog — Storage Threshold Violation Logged

Objective: Verify syslog entry generated when storage threshold exceeded
Reference: SONiC_SRM/RF-09
Priority: P0
Steps:

Configure storage threshold below current utilization
Monitor syslog
Verify syslog entry with storage threshold violation details (partition, utilization, threshold)

Expected Result:

Syslog entry generated with partition details


TC-9.6: Syslog — Storage Alarm Cleared Logged

Objective: Verify syslog entry generated when storage alarm clears
Reference: SONiC_SRM/RF-09
Priority: P0
Steps:

Trigger storage alarm
Reduce storage utilization below threshold
Verify syslog clearance entry

Expected Result:

Syslog clearance entry generated


Section 10 — Negative and Edge Case Tests

TC-10.1: All Resources — Config DB Missing Entries Show N/A

Objective: Verify all configurable fields show N/A when Config DB entries are absent
Reference: SONiC_SRM/RF-01, RF-03, RF-05
Priority: P0
Steps:

Clear all SRM-related Config DB entries
Run show platform cpu — verify Threshold shows N/A

Run show platform ram — verify Threshold shows N/A

Run show platform storage — verify Threshold shows N/A


Expected Result:

All threshold fields display N/A when Config DB entries absent


TC-10.2: Boundary Values — Valid Range Boundaries Accepted

Objective: Verify boundary values within valid range are accepted
Reference: SONiC_SRM/RF-06, RF-07, RF-08
Priority: P1
Steps:

Configure CPU threshold to 1 — verify accepted
Configure CPU threshold to 100 — verify accepted
Configure RAM threshold to 1 — verify accepted
Configure RAM threshold to 100 — verify accepted
Configure storage threshold to 1 — verify accepted
Configure storage threshold to 100 — verify accepted
Configure cpu-history interval to 1 — verify accepted
Configure cpu-history interval to 10 — verify accepted
Configure cpu-history duration to 30 — verify accepted
Configure cpu-history duration to 180 — verify accepted

Expected Result:

All boundary values within valid range accepted without error


TC-10.3: Concurrent Alarms — Multiple Resources in Alarm Simultaneously

Objective: Verify system handles simultaneous alarms for CPU, RAM, and storage
Reference: SONiC_SRM/RF-06, RF-07, RF-08, RF-09
Priority: P1
Steps:

Configure low thresholds for CPU, RAM, and storage
Trigger utilization above threshold for all three
Verify all three show Alarm Status: Active

Verify syslog contains entries for all three violations
Resolve all three conditions
Verify all alarms clear and syslog reflects clearances

Expected Result:

Independent alarm tracking per resource
All syslog entries generated correctly


Test Summary Table

TC ID	Test Case Description						Requirement						Priority
TC-1.1	Current CPU utilization per core				RF-01							P0
TC-1.2	CPU threshold NA when not configured			RF-01, RF-06					P0
TC-1.3	CPU threshold NA when set to 0					RF-06							P0
TC-1.4	CPU utilization under load						RF-01							P1
TC-2.1	CPU history default status disabled				RF-02							P0
TC-2.2	CPU history enable and verify					RF-02							P0
TC-2.3	CPU history disable and verify					RF-02							P0
TC-2.4	CPU history interval config when disabled		RF-02							P0
TC-2.5	CPU history duration config when disabled		RF-02							P0
TC-2.6	CPU history config rejected when enabled		RF-02							P0
TC-2.7	CPU history default duration and interval		RF-02							P0
TC-2.8	CPU history data collection and display			RF-02							P0
TC-2.9	CPU history show when disabled, no data			RF-02							P1
TC-2.10	CPU history show when disabled, data in Redis	RF-02							P1
TC-2.11	CPU history not retained across reboot			RF-02							P1
TC-2.12	CPU history invalid interval rejected			RF-02							P1
TC-2.13	CPU history invalid duration rejected			RF-02							P1
TC-2.14	CPU history FIFO buffer behavior				RF-02							P1
TC-3.1	Current RAM utilization retrieval				RF-03							P0
TC-3.2	RAM threshold NA when not configured			RF-03, RF-07					P0
TC-3.3	RAM utilization under load						RF-03							P1
TC-4.1	RAM history default status disabled				RF-04							P0
TC-4.2	RAM history enable and collect data				RF-04							P0
TC-4.3	RAM history config rejected when enabled		RF-04							P0
TC-4.4	RAM history default duration and interval		RF-04							P0
TC-4.5	RAM history show when disabled, no data			RF-04							P1
TC-4.6	RAM history show when disabled, data in Redis	RF-04							P1
TC-4.7	RAM history not retained across reboot			RF-04							P1
TC-4.8	RAM history invalid range rejected				RF-04							P1
TC-4.9	RAM history independent from CPU history		RF-04							P1
TC-5.1	Storage partition info and utilization			RF-05							P0
TC-5.2	Only mounted partitions reported				RF-05							P1
TC-5.3	Storage utilization changes reflected			RF-05							P1
TC-5.4	Storage threshold NA when not configured		RF-05, RF-08					P0
TC-6.1	CPU threshold configure valid value				RF-06							P0
TC-6.2	CPU threshold default 85%						RF-06							P0
TC-6.3	CPU alarm generated on threshold breach			RF-06							P0
TC-6.4	CPU alarm auto-cleared							RF-06							P0
TC-6.5	CPU threshold invalid range rejected			RF-06							P1
TC-6.6	CPU threshold 0 shows NA						RF-06							P0
TC-7.1	RAM threshold configure valid value				RF-07							P0
TC-7.2	RAM threshold default 80%						RF-07							P0
TC-7.3	RAM alarm generated on threshold breach			RF-07							P0
TC-7.4	RAM alarm auto-cleared							RF-07							P0
TC-7.5	RAM threshold invalid range rejected			RF-07							P1
TC-7.6	RAM threshold 0 shows NA						RF-07							P0
TC-8.1	Storage threshold configure valid value			RF-08							P0
TC-8.2	Storage threshold default 75%					RF-08							P0
TC-8.3	Storage alarm generated on threshold breach		RF-08							P0
TC-8.4	Storage alarm auto-cleared						RF-08							P0
TC-8.5	Storage threshold invalid range rejected		RF-08							P1
TC-8.6	Storage threshold 0 shows NA					RF-08							P0
TC-9.1	Syslog CPU threshold violation logged			RF-09							P0
TC-9.2	Syslog CPU alarm cleared logged					RF-09							P0
TC-9.3	Syslog RAM threshold violation logged			RF-09							P0
TC-9.4	Syslog RAM alarm cleared logged					RF-09							P0
TC-9.5	Syslog storage threshold violation logged		RF-09							P0
TC-9.6	Syslog storage alarm cleared logged				RF-09							P0
TC-10.1	Config DB missing entries show N/A				RF-01, RF-03, RF-05				P0
TC-10.2	Boundary values accepted						RF-06, RF-07, RF-08				P1
TC-10.3	Concurrent alarms multiple resources			RF-06, RF-07, RF-08, RF-09		P1
