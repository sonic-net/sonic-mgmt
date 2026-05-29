# Test plan for SPC6 support ACL action mirror on egress physical port binding point

- [1.1. Related documents](#11-related-documents)
- [1.2. Overview](#12-overview)
- [1.3. Scale / Performance](#13-scale--performance)
- [1.4. Test duration / Test memory consumptions](#14-test-duration--test-memory-consumptions)
- [1.5. Related DUT CLI commands](#15-related-dut-cli-commands)
  - [1.5.1. Configuration commands](#151-configuration-commands)
  - [1.5.2. Show commands](#152-show-commands)
- [2. Test structure](#2-test-structure)
  - [2.1.1. Setup configuration](#211-setup-configuration)
  - [2.1.2. Configuration diagram](#212-configuration-diagram)
  - [2.1. Test cases](#21-test-cases)

## 1.1. Related documents

| Document Name | Link |
| --- | --- |

## 1.2. Overview

This test plan validates support for MIRROR_EGRESS_ACTION on an ACL table bound to an egress physical port on SPC6 platforms.

Compared with Spectrum-5 and older ASICs, Spectrum-6 egress ACL mirroring behaves like ingress mirroring and sends the mirrored packet without modification.

Another Spectrum-6-specific behavior is that the mirror copy may still be sent when the original packet is dropped by admission or egress checks.

The plan reuses existing Everflow coverage for packet-level validation, and adds validation for these Spectrum-6-specific mirror behaviors.

## 1.3. Scale / Performance

Scale and performance validation are not in scope for this test plan.

## 1.4. Test duration / Test memory consumptions

Test duration is expected to be moderate.

Packet capture based validation may increase runtime slightly.

No significant memory or log size impact is expected.

## 1.5. Related DUT CLI commands

### 1.5.1. Configuration commands

| Command | Comment |
| --- | --- |
| `config acl add table <table_name> MIRROR --stage egress -p <port>` | Create egress ACL table bound to physical port |
| `acl-loader update full <rule_file> --table_name <table_name> --session_name <session_name> --mirror_stage egress` | Apply ACL mirror rule |
| `config mirror_session add <session_name> <src_ip> <dst_ip> <dscp> <ttl> <gre_type>` | Create mirror session |
| `config mirror_session erspan add <session_name> <src_ip> <dst_ip> <dscp> <ttl> <gre_type> '' '' egress` | Create ERSPAN mirror session with direction support |

### 1.5.2. Show commands

| Command | Comment |
| --- | --- |
| `show acl table` | Verify ACL table exists and binding is correct |
| `show acl rule` | Verify ACL rule exists |
| `show mirror_session` | Verify mirror session exists |
| `aclshow` | Verify ACL counters |

## 2. Test structure

### 2.1.1. Setup configuration

All tests are run on a standard SONiC setup on an SPC6 platform.

An egress ACL table is bound to the target physical port, a mirror session is created, and an egress ACL rule with MIRROR_EGRESS_ACTION is applied.

Existing Everflow flows are reused for packet-level validation.

### 2.1.2. Configuration diagram

N/A.

### 2.1. Test cases

| # | Test Area | Test Name | Test Description | Test Expected Result | Status | Tags |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Core functionality | `test_everflow_testbed.py:TestEverflowV4EgressAclEgressMirror::test_everflow_basic_forwarding` | Reuse the existing egress ACL egress mirror forwarding case and update the packet validation logic to distinguish SPC6 behavior from legacy ASIC behavior, according to the feature description. | Mirrored packet is captured and matches the expected behavior for the running ASIC generation. On SPC6, the mirrored packet follows the behavior described in the feature. | In progress | SPC6, everflow, dataplane, mirror |
| 2 | Core functionality | `test_everflow_testbed.py:TestEverflowV4EgressAclEgressMirror::test_everflow_spc6_egress_mirror_mtu_drop` | Reuse the existing egress mirror flow to verify the representative MTU drop scenario described in the feature. | Original packet is dropped on the normal path, while the mirror copy is still observed on the monitor path. | New | SPC6, MTU, dataplane, mirror |
