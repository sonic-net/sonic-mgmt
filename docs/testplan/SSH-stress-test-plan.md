- [Overview](#overview)
    - [Scope](#scope)
- [Test Procedure](#test-procedure)

## Overview
This test verifies that concurrent configuration tasks do not overtax DUT CPU or memory and records how many SSH sessions the DUT supports. It also requires resource usage and control-plane state to recover after the workload.

### Scope
The conditional marks run this test only on VPP `t0` and `t1-lag` topologies. The workload requires configured PortChannels and IPv4 BGP neighbors.

## Test Procedure
Part 1:

1. Pre-establish five workload SSH connections, one cancellation-control connection per worker, and one observer connection. Start the cancellation helpers and a persistent `vmstat` stream before calibration.
2. On each workload connection, collect five serial samples in both directions of its command pair and use each direction's median as its baseline. Restore each pair after calibration and allow up to 180 seconds per calibration command.
3. Require temporary configuration to remain absent and teamd/BGP health to remain recovered across two checks ten seconds apart. Use the median of three current one-second `vmstat` samples as the pre-stress CPU and memory baseline, excluding calibration load from stress peaks.
4. Over the five connections, simultaneously and repeatedly perform the following actions:
    - Start BGP connections, then shut them down
    - Shut down an operating interface, then start it back up
    - Configure an ACL, then remove it
    - Add a route, then remove it
    - Add a PortChannel, then remove it
5. During the five-minute stress phase, derive a host-normalized requirement of 3–20 restored cycles from the mixed workload's serial medians; discount the initial no-op BGP startup and do not count an unmatched final command. Use one relative p95/watchdog budget based on every pair's slower direction, with a 60-second floor and 180-second ceiling; commands dispatched before the shared deadline keep that watchdog, while late completions are excluded and safely rolled back. Fail on command, fencing, rollback, p95, or progress violations, and log each command's baseline, sample count, p95, maximum, slowdown, and budget.
6. Monitor memory and CPU throughout the stress phase through the persistent `vmstat` stream.
7. After stress, require one CPU and memory sample within 30 percentage points of the pre-stress baselines. Poll every five seconds for up to 180 seconds.

Part 2:

1. Use the median of three current `vmstat` samples as the resource baseline, then attempt 20 workload SSH connections while one observer connection monitors CPU and memory.
2. Run `show mac` after each workload session starts to confirm DUT responsiveness.
3. If a session does not respond, report the number of workload sessions reached.
4. After closing the sessions, apply the same single-sample, 180-second resource-recovery check used in Part 1.

Teardown fences every command token before restoring the configuration workloads and waiting for teamd and BGP recovery. On VPP, it also requires `route_check.py` and monit `routeCheck` to recover within the bounded wait.
