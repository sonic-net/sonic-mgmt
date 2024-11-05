# Hardware Performance Measure Test Plan

## 1 Overview

SONiC runs on various of hardwares for many different purposes, so natually the different hardware performs differently on various tests. The purpose of this test plan is to provide a solution for understanding a particular testbed better and see what role it is capable of.

### 1.1 Scope

The test is targeting a running SONiC system will fully functioning configuration. The purpose of this test is to better understand how a SONiC device performs and verify some of the key performance meters in SONiC devices.

### 1.2 Testbed

The test can run on both physical and virtual testbeds with any topology.

### 1.3 Limitation

## 2 Setup Configuration

Users will have to define their target bench mark for specific hwsku. User can provide number of iterations based on time and precision requirements.

## 3 Test

### Input Parameter

Iteration: User can provide iteration input from run_tests command line as an extra argument as that is prone to change. It should have a small default value so it may be run during nightly tests.

### User defined performance meter

User defined performance meter should be provided in the inventory file under each hwsku or dut. It is is not provided, test will run and collect various results and automatically pass.

format:

performance_meter:
  swss_create:
    min: 100
    max: 200
    avg: 150
    p99: 250
  reboot_to_bgp_up:
    min: 100
    max: 200
    avg: 150
    p99: 250
...

### Test condition

reload, reboot, restart swss

### Items to time

#### BGP up

To verify bgp is up, use run_bgp_facts helper method.

#### SWSS up

Check swss container is up and its services working fine.

#### Critical process up

Use wait_critical_processes to verify the time for critical processes up.
