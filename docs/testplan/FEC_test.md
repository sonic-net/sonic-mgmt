# SONiC Switch FEC Sanity Test: Automatic Port Operational Status Down with FEC Error Injection

- [SONiC Switch FEC Sanity Test: Automatic Port Operational Status Down with FEC Error Injection](#sonic-switch-fec-sanity-test-automatic-port-operational-status-down-with-fec-error-injection)
  - [Test Objective](#test-objective)
  - [Test Setup](#test-setup)
  - [Background](#background)
  - [Test Steps](#test-steps)
  - [Implementation](#implementation)

## Test Objective

This test aims to verify that SONiC switch links properly respond to severe FEC errors by shutting down the operational status of affected ports.

## Test Setup

The test is designed to be topology-agnostic, meaning it does not assume or impose a specific network connection. The only requirement is that the DUT is fully connected to handle traffic loads. Plus all traffic generators in the testbed must be time synchronized.

## Background

Forward Error Correction (FEC) is an error control technique in data transmission where the transmitter sends redundant data, allowing the receiver to detect and correct a limited number of errors. If the number of erroneous packets exceeds the tolerance threshold, the optical module of the SONiC switch's ports will shut down the link. This test evaluates the FEC mechanism's ability to trigger a link-down event under severe error conditions.

## Test Steps

1. Retrieve the hardware SKU setting from CONFIG_DB to determine the DUT's port breakout mode and obtain the number of logical ports per physical port. Assume the DUT has X physical ports, each breaking out into Y logical ports.

2. Identify the traffic generator and its corresponding port connected to the first logical port of physical port #1. This port will serve as the Rx port for the test traffic. Then, select a port on a separate traffic generator (not connected to the port under test) to act as the Tx port. Define a traffic item which must pass through the DUT and run the traffic for 10 seconds. Validate that the number of Rx packets matches the number of Tx packets. Increase the FEC error rate significantly and check whether the link is brought down as expected.

3. Repeat step 2 for the first logical port of every physical port, running all traffic items simultaneously to verify FEC functionality across multiple ports.

4. Iterate steps 2 and 3 for each logical port of every physical port, ensuring all Y logical ports are tested. In each iteration, a different logical port across all physical ports is tested, ensuring complete FEC functionality verification for all logical ports.

## Implementation

<https://github.com/sonic-net/sonic-mgmt/pull/16692/files>
