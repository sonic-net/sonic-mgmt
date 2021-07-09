# Kubernetes Test Plan

- [Kubernetes Test Plan](#Kubernetes-test-plan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
  - [Test cases](#test-cases)
    - [SONiC Worker Node Join/Reset](#test-scenario-joinreset)
    - [Local Mode and Kube Mode Transitions, Manifest Application](#test-scenario-mode-transitions-for-feature-x-feature-image-upgrades-with-reachable-master)
    - [Unreachable Master](#test-scenario-unreachable-master)
    - [SONiC Reboot](#test-scenario-reboot-when-master-is-reachable)

# Overview

### Background
 Each SONiC DUT is considered a worker node managed by the Kubernetes master. From the master, we can deploy upgrades to SONiC features running in kube mode with minimal downtime and without requiring reimaging of the entire SONiC buildimage. A [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/#:~:text=Synopsis,object%20that%20describes%20a%20pod.) agent runs on each SONiC DUT to communicate with the Kubernetes master.
 
 SONiC features can run in either kube mode or local mode. SONiC features (dockers) running in local mode use the image tagged `{feature_name}:latest` in the local image store and run independent of the Kubernetes master. SONiC features running in kube mode use the image sourced from the URL specified in the Kubernetes manifest and are managed by the Kubernetes master.  Features in SONiC have the ability to switch between kube mode and local mode. For more background on Kubernetes features in SONiC and kube mode vs local mode, refer to [this document](https://github.com/renukamanavalan/SONiC/blob/kube_systemd/doc/kubernetes/Kubernetes-support.md). 

### Scope
This test plan aims to ensure proper Kubernetes management of SONiC features running in kube mode, and seamless transition of a SONiC feature between kube mode and local mode.

### Testbed
Kubernetes tests require a Kubernetes master reachable from the SONiC DUT. In order to connect each SONiC DUT to a High Availability Kubernetes master, we need to run a custom SONiC Kubernetes Cluster High Availability master in EAP. As a prerequisite to runnning our tests, the EAP test cluster is already available. 

# Test Cases
These test cases focus on Device Under Test (DUT) status changes in response to different configurations. {feature x} represents the single SONiC feature/container under test. 

Each DUT has the following key configurations related to the Kubernetes server:
- `disable` flag enables and disables the Kubernetes master. `disable=false `enables DUT to join Kubernetes master to allow Kubernetes management of SONiC features. `disable=true` triggers the DUT to reset from Kubernetes master, enforcing local management of all SONiC features. Configured via CLI command: `sudo config kube server disable {on/off}`
- `ip` is the VIP of the high availability Kubernetes master. In these test cases, we assume that the VIP is configured properly. Configured via CLI command: `sudo config kube server ip {VIP}`. The VIP is resolvable via the URL `${AP_MACHINE_FUNCTION}_vip.${AP_ENVIRONMENT}.${AP_CLUSTER}.ap.gbl`

Each DUT has the following key configurations related to each SONiC feature:
- `set_owner` specifies desired owner for each feature- either local or kube. Configured via CLI command: `sudo config feature owner {feature x} {kube/local}`

Each DUT has the following key statuses related to Kubernetes server: 
- `connected` true means that the DUT has successfully joined to high availability Kubernetes master. Observed via CLI command: `show kube server status`

Each DUT has the following key statuses related to each SONiC feature: 
- `container_version` keeps track of which version is currently running for each feature.
- `remote_state` describes the state of Kubernetes-managed container (`stopped`, `running`, `pending`, or `none`) for each feature. 
- `current_owner` describes the current owner for each feature- either local or kube.
- All {feature x} statuses are observed via CLI command `show feature status {feature x}`

## Test Scenario: Join/Reset

### TC_JOIN_1: Join Master Once Available
#### Test Objective
Verify Device Under Test (DUT) joins high availability master once the VIP and Kubernetes API Server running on backend master servers become available.
#### Test Setup
- Feature Status: All features running in local mode
- DUT State: Running config = saved config_db.json, No manifests applied
- Kubernetes Server Configuration: valid VIP configured
- Feature Configuration: Some features are configured with `set_owner=kube`
#### Test Steps 
1. Set kube server `disable=true`
   - **Expect:** kube server status shows `connected=false`
2. Make VIP unreachable
   - **Expect:** No change in kube server status, `connected=false`
3. Set kube server `disable=false`
   - **Expect:** No change in kube server status, `connected=false`
4. Make VIP reachable
   - **Expect:** kube server status shows `connected=true`

### TC_JOIN_2: Test Disable Flag
#### Test Objective
Verify Device Under Test (DUT) responds appropriately to kube server `disable` flag by joining master when `disable=false` and resetting from master when `disable=true`.
#### Test Setup
- Kubernetes Server Status: `connected=true` 
- To get to desired Test Setup state, pick up from step 4 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
#### Test Steps
1. Set kube server `disable=true`
   - **Expect:** Kube server status updates to `connected=false`
2. Set kube server `disable=false`
   - Logs should reflect kubelet reestablishing connection
   - **Expect:** Kube server status updates to `connected=true`

### TC_JOIN_3: Config Reload with No Config Change
#### Test Objective
Verify Device Under Test (DUT) appropriately remains joined to master upon config reload. In config, disable is saved as false.
#### Test Setup
- Kubernetes Server Status: `connected=true` 
- Kubernetes Server Configuration: `disable=false` (config saved)
- To get to desired Test Setup state, pick up from step 4 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
#### Test Steps
1. Do config reload
   - **Expect:** Kube server status remains `connected=true` 

### TC_JOIN_4: Config Reload Toggles Disable to True
#### Test Objective
Verify Device Under Test (DUT) appropriately disconnects upon config reload toggling disable flag to true. Disable was set to false without being saved prior to config reload. 
#### Test Setup
- Kubernetes Server Status: `connected=false`
- Kubernetes Server Configuration: `disable=true` (config not yet saved)
- To get to desired Test Setup state, pick up from step 1 of [TC_JOIN_2](#tc_join_2-test-disable-flag)
#### Test Steps
1. Save config (`disable=true` is saved)
   - **Expect** Kube server status remains `connected=false`
2. Set `disable=false`
   - **Expect:** Kube server status updates to `connected=true`
3. Do config reload
   - **Expect:** Kube server status updates to `connected=false`, `disable=true` from saved config

### TC_JOIN_5: Config Reload Toggles Disable to False
#### Test Objective
Verify Device Under Test (DUT) appropriately disconnects upon config reload toggling disable flag to false. Disable was set to true without being saved prior to config reload. 
#### Test Setup
- Kubernetes Server Status: `connected=true`
- Kubernetes Server Configuration: `disable=false` (config saved)
- To get to desired Test Setup state, pick up from step 4 of [TC_JOIN_1](#tc_join_1-join-master-once-available) 
#### Test Steps
1. Set `disable=true`
   - **Expect:** Kube server status shows `connected=false`
2. Do config reload
   - **Expect:** Kube server status shows `connected=true` , `disable=false` from saved config


## Test Scenario: Mode Transitions for {feature x}, Feature Image Upgrades with Reachable Master
These test cases upgrade the container for {feature x}. The updated image for {feature x} is stored in ACR at the URL specified by the manifest being used in the test case. The manifest is stored in a GitHub repository, along with scripts that modify the manifest as needed by the test case. 

### TC_LOCAL_KUBE_1: Switch between Local Mode and Kube Mode
#### Test Objective
Verify Device Under Test (DUT) properly transitions between local mode and kube mode when manifest is properly applied.
#### Test Setup
- Feature Status of {feature x}: `current_owner=local`, `remote_state=none`, `container_version=1.0.0`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 4 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
#### Test Steps
1. Push manifest for {feature x} v1.1.1 with valid URL
   - local {feature x} v1.0.0 container should terminate
   - k8s {feature x} v1.1.1 container from remote image should run
   - **Expect:** `current_owner=kube`, `container_version=1.1.1`, `remote_state=running`
2. Set {feature x} desired owner to local (`set_owner=local`)
   - k8s {feature x} v1.1.1 container from remote image should terminate
   - local {feature x} v1.0.0 container should run
   - **Expect:** `current_owner=local`, `container_version=1.0.0`, `remote_state=none`
3. Set {feature x} desired owner to kube (`set_owner=kube`)
   - local {feature x} v1.0.0 container should terminate
   - k8s {feature x} v1.1.1 container from remote image should run
   - **Expect:** `current_owner=kube`, `container_version=1.1.1`, `remote_state=running`

### TC_LOCAL_KUBE_2: Upgrade Kube Feature v1.1.1 to Kube Feature v2.0.0 via Successful Manifest Application
#### Test Objective
Verify Device Under Test (DUT) running kube mode feature container v1.1.1 properly upgrades to kube mode feature v2.0.0 upon successful application of v2.0.0 manifest.
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 3 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
#### Test Steps
1. Push manifest for {feature x} v2.0.0 with valid URL
   - New k8s {feature x} v2.0.0 container should start running
   - {feature x} v1.1.1 container will continue running until master disables v1.1.1
   - **Expect:** `container_version=2.0.0`, `remote_state=running`
2. Stop {feature x} service
   - k8s {feature x} v2.0.0 container should stop running
   - **Expect:** `container_version=2.0.0`, `remote_state=stopped`
3. Start {feature x} service
   - k8s {feature x} v2.0.0 container should start running
   - **Expect:** `container_version=2.0.0`, `remote_state=running`

### TC_LOCAL_KUBE_3: Local to Kube Feature with Failed Manifest Application
#### Test Objective
Verify Device Under Test (DUT) local mode feature properly responds to `set_owner=kube` when kube mode feature fails to deploy properly (failed manifest application due to invalid URL). Local mode container should keep running until kube mode feature is successfully deployed.
#### Test Setup
- Feature Status of {feature x}: `current_owner=local`, `remote_state=none`, `container_version=1.0.0`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 4 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
#### Test Steps
1. Push manifest for {feature x} v2.0.0 with invalid URL
   - Local {feature x} container should continue running
   - **Expect:** `current_owner=local`, `container_version=1.0.0`, `remote_state=none`
2. Stop {feature x} service
   - **Expect:** `current_owner=none`, `container_version=1.0.0`, `remote_state=none`
3. Start {feature x} service
   - **Expect:** `current_owner=local`, `container_version=1.0.0`, `remote_state=none`
4. Fix manifest URL and reapply manifest
   - Local {feature x} v1.0.0 container should stop running
   - k8s {feature x} container v1.1.1 should start running 
   - **Expect:** `current_owner=kube`, `container_version=1.1.1`, `remote_state=running`

### TC_LOCAL_KUBE_4: Upgrade Kube Feature v1.1.1 to Kube Feature v2.0.0 with Failed Manifest Application
#### Test Objective
Verify Device Under Test (DUT) kube mode feature v1.1.1 properly responds to failed manifest application to upgrade kube mode feature to v2.0.0. Kube mode feature v1.1.1 should continue running until v2.0.0 manifest is successfully applied.
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 3 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
#### Test Steps
1. Push manifest for {feature x} v2.0.0 with invalid URL
   - {feature x} k8s v1.1.1 container continues running
2. Stop {feature x} service
   - {feature x} k8s v1.1.1 container should stop running
   - **Expect:** `current_owner=none`, `container_version=1.1.1`, `remote_state=stopped`
3. Start {feature x} service
   - {feature x} k8s v1.1.1 container should start running
   - **Expect:** `current_owner=kube`, `container_version=1.1.1`, `remote_state=running`
4. Fix manifest URL and reapply manifest
   - {feature x} k8s v1.1.1 container should stop running
   - {feature x} k8s v2.0.0 container should start running
   - **Expect:** `current_owner=kube`, `container_version=2.0.0`, `remote_state=running`

These test cases will apply for simulated failed & passed PreCheck, and failed & passed PostCheck

## Test Scenario: Unreachable Master

### TC_NO_MASTER_1: Kube Mode Feature Running, Unreachable VIP
#### Test Objective
Verify Device Under Test (DUT) kube mode features continue running in kube mode even when VIP is unreachable.
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
#### Test Steps
1. Make VIP unreachable
   - k8s {feature x} v1.1.1 container should continue running without interruption
   - **Expect:** `current_owner=kube`, `set_owner=kube`, `remote_state=running`, `container_version=1.1.1`
2. Stop {feature x} service
   - k8s {feature x} v1.1.1 container should stop running
   - **Expect:** `current_owner=none`, `set_owner=kube`, `remote_state=stopped`, `container_version=1.1.1`
3. Start {feature x} service
   - After kubelet service retries, k8s {feature x} v1.1.1 container should start running
   - **Expect:** `current_owner=kube`, `set_owner=kube`, `remote_state=running`, `container_version=1.1.1`
4. Make VIP reachable
   - k8s {feature x} v1.1.1 container should remain running as before

### TC_NO_MASTER_2: Kube Mode to Local Mode Feature Transition, Unreachable VIP
#### Test Objective
Verify Device Under Test (DUT) kube mode feature properly transitions to local mode even when VIP is unreachable.
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- DUT State: VIP unreachable from DUT
- To get to desired Test Setup state, pick up from step 1 of [TC_NO_MASTER_1](#tc_no_master_1-kube-mode-feature-running-unreachable-vip)
#### Test Steps
1. Set {feature x} desired owner to local (`set_owner=local`)
   - Local {feature x} v1.0.0 container should start running
   - k8s {feature x} v1.1.1 container should come up and down until master is reachable, at which point it will be permanently stopped (after step 5)
   - **Expect:** `current_owner=local`, `remote_state=none`, `container_version=1.0.0`
2. Stop {feature x} service
   - Local {feature x} container should stop running
   - **Expect:** `current_owner=none`, `remote_state=none`, `container_version=1.0.0`
3. Start {feature x} service
   - Local {feature x} container should start running
   - **Expect:** `current_owner=local`, `remote_state=none`, `container_version=1.0.0`
4. Make VIP reachable
   - Local {feature x} v1.0.0 container remains running
   - k8s {feature x} v1.1.1 container should be removed
   - **Expect:** `current_owner=local`, `remote_state=none`, `container_version=1.0.0`

### TC_NO_MASTER_3: Local Mode to Kube Mode Feature Transition, Unreachable VIP
#### Test Objective
Verify Device Under Test (DUT) appropriately processes offline request to transition feature from local mode to kube mode. The kube mode container should start running once the VIP is reachable.  
#### Test Setup
- Feature Status of {feature x}: `current_owner=local`, `remote_state=none`, `container_version=1.0.0`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 6 of [TC_JOIN_1](#tc_join_1-join-master-once-available)
#### Test Steps
1. Make VIP unreachable
2. Set {feature x} desired owner to kube
   - Local {feature x} v1.0.0 container should continue running
   - **Expect:** {feature x} `current_owner=local`, `set_owner=kube`, `remote_state=none`, `container_version=1.0.0`
3. Stop {feature x} Service
   - Local {feature x} v1.0.0 should stop running
   - **Expect:** {feature x} `current_owner=none`, `set_owner=kube`, `remote_state=none`, `container_version=1.0.0`
4. Start {feature x} Service
   - Local {feature x} container v1.0.0 should start running
   - **Expect:** {feature x} `current_owner=local`, `set_owner=kube`, `remote_state=none`, `container_version=1.0.0`
5. Apply manifest for k8s {feature x} v1.1.1 container
   - {feature x} should not be affected, as VIP is unreachable
   - **Expect:** No change in {feature x} status on DUT
6. Make VIP reachable
   - Local {feature x} v1.0.0 container should stop running
   - k8s {feature x} v1.1.1 container should start running
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `remote_state=running`, `container_version=1.1.1`

### TC_NO_MASTER_4: Kube Feature Following Reboot When VIP is Unreachable, Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) kube mode feature appropriately falls back to local mode upon reboot when the VIP is unreachable and fallback to local is set. Once VIP becomes reachable, feature should transition from local mode (fallback) to kube mode. 
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- DUT State: VIP unreachable from DUT
- To get to desired Test Setup state, pick up from step 1 of [TC_NO_MASTER_1](#tc_no_master_1-kube-mode-feature-running-unreachable-vip)
#### Test Steps
1. Turn on {feature x} fallback to local (`fallback_to_local=true`) and save config
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `fallback_to_local=true`, `remote_state=running`, `container_version=1.1.1`
2. Reboot
   - Local {feature x} v1.0.0 container should start running, as `fallback_to_local=true` in saved config
   - **Expect:** After complete startup, {feature x} `current_owner=local`, `set_owner=kube`, `fallback_to_local=true`, `remote_state=none`, `container_version=1.0.0`
3. Stop {feature x} service
   - Local {feature x} v1.0.0 container should stop running
   - **Expect:** {feature x} `current_owner=none`, `set_owner=kube`, `fallback_to_local=true`, `remote_state=none`
4. Start {feature x} service
   - Local {feature x} v1.0.0 container should start running
   - **Expect:** {feature x} `current_owner=local`, `set_owner=kube`, `fallback_to_local=true`, `remote_state=none`, `container_version=1.0.0`
5. Make VIP reachable. Once kubelet connects:
   - Local {feature x} v1.0.0 container should stop running
   - k8s {feature x} v1.1.1 container should start running
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `fallback_to_local=true`, `remote_state=running`, `container_version=1.1.1`
6. Repeat this test for all 3 kinds of reboots
   - Expected behavior across all reboots is the same, as Phase 1 does not yet support fast and warm reboot.

### TC_NO_MASTER_5: Kube Feature Following Reboot when VIP is Unreachable, No Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) kube mode feature appropriately fails to fall back to local mode upon reboot when the VIP is unreachable and fallback to local is not set. Once VIP becomes reachable, kube mode feature should start running.  
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- DUT State: VIP unreachable from DUT
- To get to desired Test Setup state, pick up from step 1 of [TC_NO_MASTER_1](#tc_no_master_1-kube-mode-feature-running-unreachable-vip) 
#### Test Steps
1. Turn off {feature x} fallback to local (`fallback_to_local=false`) and save config
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `fallback_to_local=false`, `remote_state=running`, `container_version=1.1.1`
2. Reboot
   - No {feature x} container should run, as fallback is not set
   - **Expect:** After complete startup, {feature x} `current_owner=none`, `set_owner=kube`, `fallback_to_local=false`, `remote_state=none`
3. Make VIP reachable. Once kubelet connects: 
   - k8s {feature x} v1.1.1 container should start running
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `fallback_to_local=false`, `remote_state=running`, `container_version=1.1.1`
4. Repeat this test for all 3 kinds of reboots
   - Expected behavior across all reboots is the same, as Phase 1 does not yet support fast and warm reboot.

## Test Scenario: Reboot when Master is Reachable

### TC_REBOOT_1: Kube Feature Following Reboot, Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) appropriately joins master upon reboot and successfully starts kube mode feature when fallback to local is set. Feature should run in local mode, and then transition to kube mode once the kubelet service starts in DUT. 
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
#### Test Steps
1. Turn on {feature x} fallback to local (`fallback_to_local=true`) and save config
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `fallback_to_local=true`, `remote_state=running`, `container_version=1.1.1`
2. Do reboot
   - **Expect:** Before kubelet comes up, local {feature x} container should run
   - **Expect:** After kubelet and statedb_watcherd services come up, `current_owner=kube`, `container_version=1.1.1`
3. Repeat this test for cold, warm, and fast reboot
   - Expected behavior across all reboots is the same, as Phase 1 does not yet support fast and warm reboot.

### TC_REBOOT_2: Kube Feature Following Reboot, No Fallback to Local
#### Test Objective
Verify Device Under Test (DUT) appropriately joins master upon reboot and successfully starts kube mode feature once kubelet service is up. Because fallback to local is not set, original kube mode feature container should not run until the kubelet service is up. 
#### Test Setup
- Feature Status of {feature x}: `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
- Feature Configuration of {feature x}: `set_owner=kube`
- To get to desired Test Setup state, pick up from step 1 of [TC_LOCAL_KUBE_1](#tc_local_kube_1-switch-between-local-mode-and-kube-mode)
#### Test Steps
1. Turn off {feature x} fallback to local (fallback_to_local=false) and save config
   - **Expect:** {feature x} `current_owner=kube`, `set_owner=kube`, `fallback_to_local=false`, `remote_state=running`, `container_version=1.1.1`
2. Do reboot
   - **Expect:** Before kubelet comes up, no {feature x} container runs
   - **Expect:** After kubelet and statedb_watcherd services come up, `current_owner=kube`, `remote_state=running`, `container_version=1.1.1`
3. Repeat this test for all 3 kinds of reboots
   - Expected behavior across all reboots is the same, as Phase 1 does not yet support fast and warm reboot.