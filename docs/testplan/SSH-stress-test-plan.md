- [Overview](#overview)
    - [Scope](#scope)
- [Test Procedure](#test-procedure)

## Overview
The purpose for this test is to make sure many configuration tasks can be run simultaneously on the DUT without overtaxing the memory or the CPU. In addition, we want to keep track of how many concurrent SSH connections we can have with the DUT. This test also makes sure that memory and cpu usage return to pre-test levels after the configuration tasks are complete.

### Scope
The current conditional-mark scope runs this test on VPP `t0` and `t1-lag`
topologies. The workload requires configured PortChannels and IPv4 BGP neighbors.

## Test Procedure
Part 1:

1. Pre-establish five workload SSH connections and one observer connection to
   the DUT, then start the observer's persistent `vmstat` stream.
2. On each workload connection that will later run stress, generate its command
   baseline from the median of five serial alternating executions of its command
   pair. The other workload connections and observer remain established, but no
   stress workers are released during calibration. Each pair restores its
   original state afterwards.
3. Before releasing the synchronized workers, require temporary configuration
   to remain absent and teamd/BGP health to remain recovered across two checks
   ten seconds apart. Then use the median of three current one-second `vmstat`
   samples as the pre-stress CPU and memory baseline. Calibration load is
   excluded from the stress peak measurements.
4. Over the five connections, simultaneously and repeatedly perform the following actions
    - Startup BGP connections, then shut them down
    - Shutdown an operating interface and start it back up
    - Configure an acl and then remove it
    - Add a route to the routemap and remove it
    - Add a port channel and remove it
5. Record every completed command duration during the five-minute stress phase.
   Each worker must complete at least 20 full alternating command-pair cycles,
   an average of at least one cycle every 15 seconds over the stress phase. A
   final unmatched command does not count as an additional cycle. A command
   timeout, nonzero exit status, rollback failure, or insufficient cycle count
   fails the test. Each command's nearest-rank p95, maximum, serial baseline
   median, and p95 slowdown are logged as diagnostics; they are not treated as a
   queueing bound for the heterogeneous five-worker workload.
6. Monitor memory and CPU usage over the following 5 minutes through one
   persistent `vmstat` process rather than repeatedly creating monitoring sessions.
7. After the stress workers stop, require CPU and memory to remain within 20
   percentage points of their respective pre-test baselines for three consecutive
   readings. Poll every five seconds, stop as soon as recovery is stable, and
   allow at most the existing 180-second health-recovery window.

Part 2:

1. Attempt to start 20 workload SSH connections while monitoring CPU and memory
   through one additional observer connection, which is excluded from the reported
   workload-session count. Before opening the workload sessions, use the median
   of three current one-second `vmstat` samples as the CPU and memory baseline.
2. After each SSH session is started, "show mac" is run to ensure the DUT is responding
3. If there is no response the test reports the number of SSH sessions reached
4. After the workload sessions close, apply the same consecutive-reading,
   180-second CPU and memory recovery check used in Part 1.

Teardown restores the configuration workloads and waits for teamd and BGP
recovery. On VPP, it also requires a successful `route_check.py` execution and
a healthy monit `routeCheck` status before returning. Monit's periodic result
can lag behind route convergence after intentional churn; the bounded recovery
wait does not disable the checker or accept persistent route mismatches.
