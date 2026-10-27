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

1. For each command, a baseline is generated from the median of five serial
   alternating executions of its command pair. Each pair restores its original
   state afterwards. Before the stress phase, the test requires temporary
   configuration to remain absent and teamd/BGP health to remain recovered
   across two checks ten seconds apart.
2. Pre-establish five workload SSH connections and one observer connection to
   the DUT. Start one worker per command pair and release all workers together
   after the observer's persistent `vmstat` stream produces its first live sample.
3. Over the five connections, simultaneously and repeatedly perform the following actions
    - Startup BGP connections, then shut them down
    - Shutdown an operating interface and start it back up
    - Configure an acl and then remove it
    - Add a route to the routemap and remove it
    - Add a port channel and remove it
4. Record every completed command duration during the five-minute stress phase.
   For each command direction with at least 20 samples, compare the nearest-rank
   p95 with five times that command's own serial baseline median. This allows one
   command no more time than five serial executions of that command. A p95 at or
   above the limit, a timeout, or a nonzero command exit status fails the test.
   The maximum and sample count are logged for diagnosis.
5. Monitor memory and CPU usage over the following 5 minutes through one
   persistent `vmstat` process rather than repeatedly creating monitoring sessions.
6. After the stress workers stop, require CPU and memory to return within 20
   percentage points of their respective pre-test baselines.

Part 2:

1. Attempt to start 20 workload SSH connections while monitoring CPU and memory
   through one additional observer connection, which is excluded from the reported
   workload-session count.
2. After each SSH session is started, "show mac" is run to ensure the DUT is responding
3. If there is no response the test reports the number of SSH sessions reached
4. After the workload sessions close, require CPU and memory to return within
   20 percentage points of their respective pre-test baselines.

Teardown restores the configuration workloads and waits for teamd and BGP
recovery. On VPP, it also requires a successful `route_check.py` execution and
a healthy monit `routeCheck` status before returning. Monit's periodic result
can lag behind route convergence after intentional churn; the bounded recovery
wait does not disable the checker or accept persistent route mismatches.
