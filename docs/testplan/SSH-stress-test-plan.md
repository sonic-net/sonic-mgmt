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

1. Pre-establish five workload SSH connections, one dormant cancellation-control
   connection per worker, and one observer connection to the DUT. Start the
   observer's persistent `vmstat` stream and each worker's cancellation helper
   before calibration.
2. On each workload connection that will later run stress, generate its command
   baseline from the median of five serial alternating executions of its command
   pair. The other workload connections and observer remain established, but no
   stress workers are released during calibration. Each pair restores its
   original state afterwards. Calibration uses a bounded 180-second watchdog so
   a slower host can provide a baseline instead of failing the historical
   60-second stress-command floor before comparison begins.
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
   Normalize each pair's required restored-cycle count to that DUT's serial
   medians. For each command, budget five times its serial median plus one second
   for the five concurrent workers; add the normal settle delays to form the
   pair's contention budget. Require the number of full cycles that fit in 300
   seconds under that budget, capped at the existing 20-cycle maximum. A host
   whose serial baselines predict fewer than three meaningful cycles is reported
   as `INFRASTRUCTURE_LIMITED` so the run can be rescheduled rather than recorded
   as a product failure. A final unmatched command does not count as an additional
   cycle.
   Command watchdogs scale from the same baseline-derived budgets, with a
   60-second floor and 180-second hard ceiling. Nonzero exit status, rollback
   failure, a deadline violation, or insufficient baseline-normalized progress
   remains a strict failure. A uniquely owned remote helper terminates and
   fences a timed-out process group before rollback can begin. Each command's
   nearest-rank p95, maximum, serial baseline median, p95 slowdown, and relative
   budget are logged as diagnostics; the hard performance gate is restored-cycle
   throughput rather than a per-command queueing assertion.
6. Monitor memory and CPU usage over the following 5 minutes through one
   persistent `vmstat` process rather than repeatedly creating monitoring sessions.
7. After the stress workers stop, require one current CPU and memory sample to
   return within the test's long-standing 20-percentage-point guardrail relative
   to the pre-test baselines. Poll every five seconds, stop at the first qualifying
   sample, and allow at most the existing 180-second health-recovery window.

Part 2:

1. Attempt to start 20 workload SSH connections while monitoring CPU and memory
   through one additional observer connection, which is excluded from the reported
   workload-session count. Before opening the workload sessions, use the median
   of three current one-second `vmstat` samples as the CPU and memory baseline.
2. After each SSH session is started, "show mac" is run to ensure the DUT is responding
3. If there is no response the test reports the number of SSH sessions reached
4. After the workload sessions close, apply the same single-qualifying-sample,
   180-second CPU and memory recovery check used in Part 1.

Teardown first fences every command token owned by this test, then restores the
configuration workloads and waits for teamd and BGP recovery. On VPP, it also
requires a successful `route_check.py` execution and
a healthy monit `routeCheck` status before returning. Monit's periodic result
can lag behind route convergence after intentional churn; the bounded recovery
wait does not disable the checker or accept persistent route mismatches.
