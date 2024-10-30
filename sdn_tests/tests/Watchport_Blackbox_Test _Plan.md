# Objective

This document captures the tests that are intended to be covered in the blackbox test environment for Watchport feature.

# Overview

Watchport is a feature that aims to quickly remove a link (that went down) from the WCMP/ECMP group it participates in before the controller (used interchangeably with the external view) can detect the link down event and take the appropriate recovery action. This is mainly to shorten the duration of traffic black hole problems that may arise if a down member exists in a WCMP/ECMP group.

The test-plan aims to verify the correctness of the feature by picking up certain triggers and common use-cases. The testing will not cover the following:

-   Reference or object dependencies like whether a nexthop member exists before being referenced in the WCMP/ECMP group action.
-   Traffic loss/convergence related scenarios.

# Testbed Requirements

The testbed requirements are the existence of a basic blackbox setup that comprises a SUT and control switch which are connected to each other on multiple links.

# Test Cases

## Configured weights are realized

<table>
  <thead>
    <tr>
      <th><strong>Title</strong></th>
      <th>Verify basic WCMP/ECMP packet hashing works with watch port actions.</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Create a WCMP/ECMP group (herein referred to as Action Profile Group APG) with multiple members (herein referred to as Action Profile Members APM) with an associated watch port for each member.</li>
</ul>
<ul>
<li>Send different packets to the SUT from the control switch by varying a field in the packet header that will apply the hashing algorithm to select an APM from the APG.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify the packets are distributed to all the members in the APG by comparing the actual number of packets received on each port vs the expected up members.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

##

## Member down handling

<table>
  <thead>
    <tr>
      <th><strong>Title</strong></th>
      <th>Verify the watchport action when the watch port link is forced down.</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Create a WCMP/ECMP APG with multiple APM.</li>
</ul>
<ul>
<li>Bring down the watch port associated with one member of the APG.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify that the member of the down port is excluded from the APG (via traffic tests) but the read request from P4RT (as in APP_DB) reflects the original set of Action Profile members.</li>
</ul>
<ul>
<li>Send different packets as in the earlier step and verify traffic is distributed only to the members whose watch port link is up.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## Member up handling

<table>
  <thead>
    <tr>
      <th><strong>Title</strong></th>
      <th>Verify the watchport action when the watch port link comes up</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Disable link damping to ensure link up notifications are delivered instantly.</li>
</ul>
<ul>
<li>Bring up the watch port of an excluded member of an APG.</li>
</ul>
<ul>
<li>Resend packets with varying headers that will ensure all members are hashed.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify that packets are distributed as per the new membership.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## Watch port for a single member group

<table>
  <thead>
    <tr>
      <th><strong>Title</strong></th>
      <th>Verify watch port functionality for single member.</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Disable link damping to ensure link up notifications are delivered instantly.</li>
</ul>
<ul>
<li>Create a WCMP/ECMP APG with only one member</li>
</ul>
<ul>
<li>Send different packets to the SUT from the control switch by varying a field in the packet header.</li>
</ul>
<ul>
<li>Bring down the watch port associated with the member.</li>
</ul>
<ul>
<li>Bring up the watch port associated with the member in the APG.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify that all packets are sent out on the same member while the associated watch port is up, no traffic loss.</li>
</ul>
<ul>
<li>Verify that all packets are dropped when the associated watch port is down.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## Modify operation on a watchport member

<table>
  <thead>
    <tr>
      <th><strong>Title</strong></th>
      <th>Verify watch port action along with the controller updates.</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Disable link damping to ensure link up notifications are delivered instantly.</li>
</ul>
<ul>
<li>Create a WCMP/ECMP APG with multiple members and watch ports.</li>
</ul>
<ul>
<li>Bring down one of the watch port associated with a member and verify the member is excluded from the selection process for this APG.</li>
</ul>
<ul>
<li>Send a modify APG request that removes the member whose watch port was brought down.</li>
</ul>
<ul>
<li>Bring the associated watch port up and verify that the deleted member does not get added back to the APG.</li>
</ul>
<ul>
<li>Send traffic with varying packet headers.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify APP_DB state always reflects the membership consistent to the external view and not the membership that the switch implementation modified when the associated watch port went down/up.</li>
</ul>
<ul>
<li>Verify traffic is destined only to the members programmed by the controller and whose associated watch port is up.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Repeat the same steps as above but replace the modify APG with remove APG operation.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify that bringing up the watch port does not result in any critical error reported by the switch. (No group exists since the group was removed)</li>
</ul>
</td>
    </tr>
  </tbody>
</table>

## Specifying a down-port as watch port

<table>
  <thead>
    <tr>
      <th><strong>Title</strong></th>
      <th>Verify the watch port action when the controller adds a member to the APG whose associated watch port is down.</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Procedure</strong></td>
      <td><ul>
<li>Disable link damping to ensure link up notifications are delivered instantly.</li>
</ul>
<ul>
<li>Create a WCMP/ECMP APG with some members whose watch ports are up and some down.</li>
</ul>
<ul>
<li>Send traffic and ensure only non-excluded member ports receive it, no traffic loss.</li>
</ul>
<ul>
<li>Bring up the watch port whose APM was excluded from the APG.</li>
</ul>
</td>
    </tr>
    <tr>
      <td><strong>Expected Results</strong></td>
      <td><ul>
<li>Verify APP_STATE DB read always reflect all members.</li>
</ul>
<ul>
<li>Verify traffic is destined to only members in the APG whose associated watch ports are up and there is no overall traffic loss.</li>
</ul>
</td>
    </tr>
  </tbody>
</table>
