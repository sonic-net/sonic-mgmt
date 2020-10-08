# Kubernetes Test Plan

- [Kubernetes Test Plan](#Kubernetes-test-plan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
  - [Test cases](#test-cases)
    - [SONiC Worker Node Join/Reset](#test-scenario-joinreset)
    - [Local Mode and Kube Mode Transitions, Manifest Application](#test-scenario-mode-transitions-feature-image-upgrades-with-reachable-master)
    - [Unreachable Master](#test-scenario-unreachable-master)
    - [SONiC Reboot](#test-scenario-reboot-when-master-is-reachable)


# Overview

### Background
 SONiC features can run in either kube mode or local mode. SONiC features (dockers) running in kube mode are managed by the connected Kubernetes master. From the master, we can deploy upgrades to SONiC features running in kube mode with minimal downtime. Features have the ability to switch between kube mode and local mode. For more background on Kubernetes features in SONiC and kube mode vs local mode, refer to [this document](https://github.com/renukamanavalan/SONiC/blob/kube_systemd/doc/kubernetes/Kubernetes-support.md). 

### Scope
This test plan aims to ensure proper Kubernetes management of SONiC features running in kube mode, and seamless transition of a SONiC feature between kube mode and local mode.

### Testbed
Kubernetes tests require a Kubernetes master reachable from the SONiC DUT. In order to connect each SONiC DUT to a High Availability Kubernetes master, we need to set up the following topology on a testbed server: 
![alt text](https://github.com/isabelmsft/k8s-ha-master-starlab/blob/master/k8s-testbed-linux.png)

To set up the high availability Kubernetes master, follow the instructions [here](https://github.com/Azure/sonic-mgmt/blob/master/ansible/doc/README.testbed.k8s.Setup.md#how-to-setup-high-availability-kubernetes-master).

# Test Cases

## Test Scenario: Join/Reset

### TC_JOIN_1: Join Master Once Available
#### Test Objective
Verify Device Under Test (DUT) joins high availability master once the VIP and Kubernetes API Server become available.
#### Test Configuration
- Kube server configured with correct VIP and disable = False
- All features running in local mode, with some having set_owner as kube
- HA Proxy server down and backend master servers up but not running API service
- Running config == saved config_db.json
#### Test Steps
1. Start HAProxy machine
   - VIP is available but VIP::port is not available, as backend master servers are not running Kubernetes API Server
   - **Expect:** No change in kube server status, not connected
2. Start API service in backend master servers with no manifests applied
   - VIP::port and VIP should both be available
   - **Expect:** kube server status shows connected
3. Stop API Service
   - Logs should show kubelet trying to reconnect
   - **Expect:** No change in kube server status, connected
4. Shutdown HAProxy
   - Logs should show kubelet trying to reconnect
   - **Expect:** No change in kube server status, connected
5. Bring back HAProxy and API service
   - Logs should show kubelet has established connection
   - **Expect:** No change in kube server status, connected 

### TC_JOIN_2: Test Disable Flag
#### Test Objective
Verify Device Under Test (DUT) responds appropriately to kube server disable flag by joining master when disable=false and resetting from master when disable=true.
#### Test Configuration
- Pick up from step 2 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
- Server status shows Connected 
#### Test Steps
1. Set server disable=true
   - **Expect:** Kube server status updates to disconnected
2. Set server disable=false
   - Logs should reflect kubelet reestablishing connection
   - **Expect:** Kube server status updates to connected

### TC_JOIN_3: Config Reload with No Config Change
#### Test Objective
Verify Device Under Test (DUT) appropriately remains joined to master upon config reload. In config, disable is saved as false.
#### Test Configuration
- Pick up from step 2 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
- Server status shows Connected
#### Test Steps
1. Do config reload
   - **Expect:** Kube server status remains connected

### TC_JOIN_4: Config Reload Toggles Disable to True
#### Test Objective
Verify Device Under Test (DUT) appropriately disconnects upon config reload toggling disable flag to true. Disable was set to false without being saved prior to config reload. 
#### Test Configuration
- Pick up from step 1 of [TC_JOIN_2](#tc_join_2-test-disable-flag)
- Server status shows Disconnected
- Disable flag is set to true (config not yet saved)
#### Test Steps
1. Save config
2. Set disable flag = false
   - **Expect:** Server status shows connected 
3. Do config reload
   - **Expect:** Server status shows disconnected, disable flag = true

### TC_JOIN_5: Config Reload Toggles Disable to False
#### Test Objective
Verify Device Under Test (DUT) appropriately disconnects upon config reload toggling disable flag to false. Disable was set to true without being saved prior to config reload. 
#### Test Configuration
- Pick up from step 2 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
- Server status shows Connected
- Disable flag is set to false (config saved)
#### Test Steps
1. Set disable flag = true
   - **Expect:** Server status shows disconnected
2. Do config reload
   - **Expect:** Server status shows connected, disable flag = false


## Test Scenario: Mode Transitions, Feature Image Upgrades with Reachable Master

### TC_LOCAL_KUBE_1: Switch between Local Mode and Kube Mode
#### Test Objective
Verify Device Under Test (DUT) properly transitions between local mode and kube mode when manifest is properly applied.
#### Test Configuration
- Pick up from step 2 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
- SNMP current_owner=local, set_owner=kube, remote_state=none, container_version=1.0
#### Test Steps
1. Apply manifest for SNMP v1.1 with valid URL
   - local SNMP container v1.0 should terminate
   - k8s SNMP container v1.1 from remote image should run
   - **Expect:** current_owner=kube, container_version=v1.1
2. Set SNMP desired owner to local (set_owner=local)
   - k8s SNMP container v1.1 from remote image should terminate
   - local SNMP container should run
   - **Expect:** current_owner=local, container_version=v1.0
3. Set SNMP desired owner to kube (set_owner=kube)
   - local SNMP container v1.0 should terminate
   - k8s SNMP container v1.1 from remote image should run
   - **Expect:** current_owner=kube, container_version=1.1

### TC_LOCAL_KUBE_2: Upgrade Kube Feature v1.1 to Kube Feature v2.0 via Successful Manifest Application
#### Test Objective
Verify Device Under Test (DUT) running kube mode feature container v1.1 properly upgrades to kube mode feature v2.0 upon successful application of v2.0 manifest.
#### Test Configuration
- Pick up from step 3 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Deploy SNMP v2.0 manifest with valid URL
   - New k8s SNMP v2.0 container should start running
   - SNMP container v1.1 will continue running until master disables v1.1
   - **Expect:** container_version=v2.0
2. Stop SNMP service
   - k8s SNMP v2.0 container should stop running
   - **Expect:** container_version=2.0, remote_state=stopped
3. Start SNMP service
   - k8s SNMP v2.0 container should start running
   - **Expect:** container_version=2.0, remote_state=running

### TC_LOCAL_KUBE_3: Local to Kube Feature with Failed Manifest Application
#### Test Objective
Verify Device Under Test (DUT) local mode feature properly responds to set_owner=kube when kube mode feature fails to deploy properly (failed manifest application due to invalid URL). Local mode container should keep running until kube mode feature is successfully deployed. 
#### Test Configuration
- Pick up from step 2 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
- SNMP current_owner=local, set_owner=kube, remote_state=none, container_version=1.0
#### Test Steps
1. Apply SNMP v1.1 manifest with invalid URL
   - Local SNMP container should continue running
   - **Expect:** current_owner=local, container_version=1.0
2. Stop SNMP service
   - **Expect:** current_owner=none, container_version=1.0
3. Start SNMP service
   - **Expect:** current_owner=local, container_version=1.0
4. Fix manifest URL and reapply manifest
   - Local container SNMP v1.0 container should stop
   - k8s SNMP container v1.1 should start running 
   - **Expect:** current_owner=kube, container_version=1.1, 

### TC_LOCAL_KUBE_4: Upgrade Kube Feature v1.1 to Kube Feature v2.0 with Failed Manifest Application
#### Test Objective
Verify Device Under Test (DUT) kube mode feature v1.1 properly responds to failed manifest application to upgrade kube mode feature to v2.0. Kube mode feature v1.1 should continue running until v2.0 manifest is successfully applied. 
#### Test Configuration
- Pick up from step 3 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Deploy manifest with invalid URL
   - SNMP k8s v1.1 container continues running
2. Stop SNMP service
   - SNMP k8s v1.1 container should stop running
   - **Expect:** current_owner=none, container_version=1.1, remote_state=stopped
3. Start SNMP service
   - SNMP k8s v1.1 container should start running
   - **Expect:** current_owner=kube, container_version=1.1, remote_state=running
4. Fix manifest URL and reapply manifest
   - SNMP k8s v1.1 container should stop running
   - SNMP k8s v2.0 container should start running
   - **Expect:** current_owner=kube, container_version=2.0, remote_state=running

### TC_LOCAL_KUBE_5: Daemonset Deleted
#### Test Objective
Verify Device Under Test (DUT) properly responds to the application of a manifest to recreate a daemonset that was accidentally deleted. 
#### Test Configuration
- Pick up from step 3 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Delete SNMP kube feature daemonset
   - No SNMP container runs
   - **Expect:** remote_state=stopped, container_version=1.1
2. Reapply SNMP manifest to recreate daemonset
   - SNMP k8s container should start running
   - **Expect:** remote_state=running, container_version=1.1

## Test Scenario: Unreachable Master

### TC_NO_MASTER_1: Kube Mode Feature Running, Unreachable VIP
#### Test Objective
Verify Device Under Test (DUT) kube mode features continue running in kube mode even when VIP is unreachable.
#### Test Configuration
- Pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Shut down HAProxy machine
   - k8s SNMP v1.1 container should continue running
   - **Expect:** current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
2. Stop SNMP service
   - k8s SNMP v1.1 container should stop running
   - **Expect:** current_owner=none, set_owner=kube, remote_state=stopped, container_version=1.1
3. Start SNMP service
   - k8s SNMP v1.1 container should start running
   - **Expect:** current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
4. Start HAProxy machine
5. SNMP container should remain running as before

### TC_NO_MASTER_2: Kube Mode to Local Mode Feature Transition, Kubernetes Master Servers Down
#### Test Objective
Verify Device Under Test (DUT) kube mode feature properly transitions to local mode even when the Kubernetes master servers are down.
#### Test Configuration
- Pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Shut down two backend Kubernetes master servers
2. Set SNMP desired owner to local
   - Local SNMP v1.0 container should start running
   - k8s SNMP v1.2 container will remain present until master is reachable
   - **Expect:** current_owner=local, remote_state=stopped, container_version=1.0
3. Stop SNMP service
   - Local SNMP container should stop running
   - **Expect:** current_owner=none, remote_state=stopped, container_version=1.0
4. Start SNMP service
   - Local SNMP container should start running
   - **Expect:** current_owner=local, remote_state=stopped, container_version=1.0
5. Start all backend Kubernetes master servers
   - Local SNMP v1.0 container remains running
   - k8s SNMP v2.0 container should be removed
   - **Expect:** current_owner=local, remote_state=stopped, container_version=1.0

### TC_NO_MASTER_3: Local Mode to Kube Mode Feature Transition, Kubernetes API Server Down
#### Test Objective
Verify Device Under Test (DUT) appropriately processes offline request to transition feature from local mode to kube mode. The kube mode container should start running once the Kubernetes master API Server is up.  
#### Test Configuration
- Pick up from step 2 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
- SNMP current_owner=local, set_owner=kube, remote_state=none, container_version=1.0
#### Test Steps
1. Kill API Server processes on three backend Kubernetes master servers
2. Set SNMP desired owner to kube
   - Local SNMP container v1.0 should continue running
   - **Expect:** SNMP current_owner=local, set_owner=kube, remote_state=stopped, container_version=1.0
3. Stop SNMP Service
   - Local SNMP container v1.0 should stop running
   - **Expect:** SNMP current_owner=none, set_owner=kube, remote_state=stopped, container_version=1.0
4. Start SNMP Service
   - Local SNMP container v1.0 should start running
   - **Expect:** SNMP current_owner=local, set_owner=kube, remote_state=stopped, container_version=1.0
5. Apply manifest for k8s SNMP v1.1 container
   - This request should hang, as Kubernetes API Server is down 
6. Start API Server processes on three backend Kubernetes master servers
   - Manifest request from step 3 should go through
   - Local SNMP v1.0 container should stop running
   - k8s SNMP v1.1 container should start running
   - **Expect:** SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1

### TC_NO_MASTER_4: Kube Feature Following Reboot When VIP is Unreachable, Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) kube mode feature appropriately falls back to local mode upon reboot when the VIP is unreachable and fallback to local is set. Once VIP becomes reachable, feature transition from local mode (fallback) to kube mode. 
#### Test Configuration
- Pick up from step 1 of [TC_NO_MASTER_1](#tc_no_master_1-kube-mode-feature-running-unreachable-vip)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Turn on SNMP fallback to local (fallback_to_local=true) and save config
   - **Expect:** SNMP current_owner=kube, set_owner=kube, fallback_to_local=true, remote_state=running, container_version=1.1
2. Reboot
   - Local SNMP v1.0 container should start running, as Fallback to Local was set
   - **Expect:** After complete startup, SNMP current_owner=local, set_owner=kube, fallback_to_local=true, remote_state=none, container_version=1.0
3. Stop SNMP service
   - Local SNMP container should stop running
   - **Expect:** SNMP current_owner=none, set_owner=kube, fallback_to_local=true, remote_state=none
4. Start SNMP service
   - Local SNMP v1.0 container should start running
   - **Expect:** SNMP current_owner=local, set_owner=kube, fallback_to_local=true, remote_state=none, container_version=1.0
5. Start HAProxy node to make VIP reachable. Once kubelet connects:
   - Local SNMP v1.0 container should stop running
   - k8s SNMP v1.1 container should start running
   - **Expect:** SNMP current_owner=kube, set_owner=kube, fallback_to_local=true, remote_state=running, container_version=1.1
6. Repeat this test for all 3 kinds of reboots

### TC_NO_MASTER_5: Kube Feature Following Reboot when VIP is Unreachable, No Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) kube mode feature appropriately fails to fall back to local mode upon reboot when the VIP is unreachable and fallback to local is not set. Once VIP becomes reachable, kube mode feature should start running again.  
#### Test Configuration
- Pick up from step 1 of [TC_NO_MASTER_1](#tc_no_master_1-kube-mode-feature-running-unreachable-vip)
- SNMP current_owner=kube, set_owner=kube, remote_state=running, container_version=1.1
#### Test Steps
1. Turn off SNMP fallback to local (fallback_to_local=false) and save config
   - **Expect:** SNMP current_owner=kube, set_owner=kube, fallback_to_local=false, remote_state=running, container_version=1.1
2. Reboot
   - **Expect:** After complete startup, SNMP current_owner=none, set_owner=kube, fallback_to_local=false, remote_state=none
3. Start HAProxy node to make VIP reachable. Once kubelet connects: 
   - k8s SNMP v1.1 container should start running
   - **Expect:** SNMP current_owner=kube, set_owner=kube, fallback_to_local=true, remote_state=running, container_version=1.1
4. Repeat this test for all 3 kinds of reboots

## Test Scenario: Reboot when Master is Reachable

### TC_REBOOT_1: Kube Feature Following Reboot, Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) appropriately joins master upon reboot and successfully starts kube mode feature when fallback to local is set. Feature should run in local mode, and then transition to kube mode once the kubelet service starts in DUT. 
#### Test Configuration
- Pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- Server status shows Connected, SNMP current_owner=kube, container_version=1.1
#### Test Steps
1. Turn on SNMP fallback to local (fallback_to_local=true) and save config
   - **Expect:** SNMP current_owner=kube, set_owner=kube, fallback_to_local=true, remote_state=running, container_version=1.1
2. Do reboot
   - **Expect:** Before kubelet comes up, SNMP is running in local mode
   - **Expect:** After kubelet and statedb_watcherd services come up, current_owner=kube, container_version=1.1
3. Repeat this test for all 3 kinds of reboots

### TC_REBOOT_2: Kube Feature Following Reboot, No Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) appropriately joins master upon reboot and successfully starts kube mode feature once kubelet service is up. Because fallback to local is not set, no feature container will run until the kubelet service is up. 
#### Test Configuration
- Pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
- Server status shows Connected, SNMP current_owner=kube, container_version=1.1
#### Test Steps
1. Turn off SNMP fallback to local (fallback_to_local=false) and save config
   - **Expect:** SNMP current_owner=kube, set_owner=kube, fallback_to_local=false, remote_state=running, container_version=1.1
2. Do reboot
   - **Expect:** Before kubelet comes up, no SNMP container runs
   - **Expect:** After kubelet and statedb_watcherd services come up, current_owner=kube, container_version=1.1
3. Repeat this test for all 3 kinds of reboots
