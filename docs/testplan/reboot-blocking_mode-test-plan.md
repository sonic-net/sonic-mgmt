# Reboot Blocking Mode Test Plan

## 1 Overview

The purpose is to test the functionality of **Reboot Blocking Mode** feature on SONiC switch.

For details of the feature design, please refer to HLD: [Reboot support BlockingMode in SONiC](https://github.com/sonic-net/SONiC/blob/master/doc/reboot/Reboot_BlockingMode_HLD.md).

### 1.1 Scope

The test is targeting a running SONiC system will fully functioning configuration. The purpose of this test is to verify the function of reboot BlockingMode with CLI and config file.

### 1.2 Testbed

The test can run on both physical and virtual testbeds with any topology.

### 1.3 Limitation

The blocking mode only affect device sku with no platform reboot enabled. So test will always success on that kinds of hardware sku.

## 2 Setup Configuration

Because in non-blocking mode, the CLI output is unpredictable. So we need to mock the original reboot file `/sbin/reboot`. We will update this file as an empty script so that in non-BlockingMode, we will always quickly complete the `reboot` command.

## 3 Test

### Test for BlockingMode CLI
#### Test case #1 - Verify original logic will not block
1. Run command `reboot; echo "ExpectedFinished"`. The command needs to have a timeout with 10mins. This is to avoid the script blocked unexpected.
1. Check if the command output contains `ExpectedFinished` as expected.

#### Test case #2 - Verify blocking mode enabled successfully
1. Run command `reboot -b; echo "UnexpectedFinished"`. The command needs to have a timeout with 10mins.
1. Check if the command output not contains `UnexpectedFinished` as expected.

#### Test case #3 - Verify running output when blocking mode enabled
1. Run command `reboot -b -v; echo "UnexpectedFinished"`. The command needs to have a timeout with 10mins.
1. Check if the command output not contains `UnexpectedFinished` as expected.
1. Check if there are extra dots after `Issuing OS-level reboot ...` output.

### Test for BlockingMode config file
#### Test case #1 - Verify blocking mode and running output with config file
1. Backup the config file `/etc/sonic/reboot.conf` if exists. Update the following configs to the config file:
   ```
   blocking_mode=true
   show_timer=true
   ```
1. Run command `reboot; echo "UnexpectedFinished"`. The command needs to have a timeout with 10mins.
1. Check if the command output not contains `UnexpectedFinished` as expected.
1. Check if there are extra dots after `Issuing OS-level reboot ...` output.
1. Restore the config file `/etc/sonic/reboot.conf`

## 4 Cleanup
Since the reboot script already killed the SONiC modules, we need to do another reboot after restore `/sbin/reboot`.