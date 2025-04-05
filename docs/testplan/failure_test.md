# SONiC Switch Failure Test

- [SONiC Switch Failure Test](#sonic-switch-failure-test)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Test Cases for Network Resilience and Recovery](#test-cases-for-network-resilience-and-recovery)
    - [Single Link Failure Test](#single-link-failure-test)
    - [All Links Failure Test](#all-links-failure-test)
    - [Container Failure Test](#container-failure-test)
    - [DUT Reboot Test](#dut-reboot-test)
    - [Neighboring Device Reboot Test](#neighboring-device-reboot-test)
    - [Route Withdrawal and Re-advertisement Test](#route-withdrawal-and-re-advertisement-test)

## Test Objective

The objective of this test is to evaluate the traffic recovery time in response to a failure event.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle full traffic loads under stress. Plus all traffic generators in the testbed must be time synchronized.

## Test Cases for Network Resilience and Recovery

Execute "SONiC Switch Scaling IPv6 Routes Test" till step 6, then proceed with the following test cases.

### Single Link Failure Test

Objective: Evaluate the network's ability to recover from a single link failure without impacting traffic flow.

Test Steps:

- Select a redundant link on the DUT and administratively take it down.
- Monitor all traffic flows to confirm that no flow experiences total packet loss.
- Bring the link back up and measure the time taken for traffic to fully recover.

Expected Outcome:

- No traffic flow should experience total loss due to redundancy.
- All traffic flows should be restored to their original state within 15 seconds.

### All Links Failure Test

Objective: Assess network recovery time when all links are lost and then restored.

Test Steps:

- Administratively take down all ports on the DUT.
- Verify that all traffic flows experience 100% packet loss.
- Bring the ports back up and monitor traffic recovery.

Expected Outcome:

- All traffic flows should restore to their original state within approximately 3 minutes.

### Container Failure Test

Objective: Verify the automatic recovery of traffic when individual containers fail.

Test Steps:

- Iterate through the list of critical containers running on the DUT.
- Stop one container at a time and observe the impact on network traffic.
- Ensure the container restarts automatically and check if traffic recovers.

Expected Outcome:

- Each stopped container should restart successfully.
- All traffic should recover automatically without manual intervention.

### DUT Reboot Test

Objective: Measure the network’s ability to restore traffic after a complete device reboot.

Test Steps:

- Reboot the DUT and monitor network behavior.
- Observe the time taken for all traffic flows to be restored.

Expected Outcome:

- All traffic flows should return to their original state after the reboot.

### Neighboring Device Reboot Test

Objective: Test the impact of a neighboring device failure on traffic recovery.

Test Steps:

- Reboot one neighboring device connected to the DUT.
- Monitor network traffic and measure the recovery time.

Expected Outcome:

- Traffic should reroute if alternative paths exist.
- Once the neighboring device is back online, all traffic should return to its original state.

### Route Withdrawal and Re-advertisement Test

Objective: Test how the network responds to route withdrawals and re-advertisements.

Test Steps:

- On a neighboring router, withdraw a set of advertised routes and monitor the impact on traffic.
- Re-advertise the withdrawn routes and measure the recovery time.

Expected Outcome:

- Traffic should reroute if alternative paths exist.
- Once routes are re-advertised, traffic should recover without persistent packet loss.
