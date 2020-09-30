# Kubernetes test plan

- [Kubernetes test plan](#Kubernetes-test-plan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
  - [Test cases](#test-cases)
    - [SONiC Worker Node Join](#test-cases---sonic-worker-node-join)
    - [SONiC Worker Node Reset](#test-cases---sonic-worker-node-reset)
    - [Manifest Deployment](#test-cases---manifest-deployment-from-master)
    - [Transition between Kube and Local Mode](#test-cases---transition-between-kube-and-local-mode)
    - [SONiC Reboot](#test-cases---sonic-reboot)
    - [High Availability Master Functionality](#test-cases---ha-master-functionality)
    - [Miscellaneous](#test-cases---miscellaneous)


## Overview

 SONiC features can run in either kube mode or local mode. SONiC features (dockers) running in kube mode are managed by the connected Kubernetes master. From the master, we can deploy upgrades to SONiC features running in kube mode- without the SONiC reimaging required for changes to features in local mode. Features have the ability to switch between kube and local mode. For more background on Kubernetes features in SONiC and kube vs local mode, refer to [this document](https://github.com/renukamanavalan/SONiC/blob/kube_systemd/doc/kubernetes/Kuberenetes-support.md). 

### Scope

This test plan aims to ensure proper Kubernetes management of SONiC features running in kube mode, and seamless transition of a SONiC feature between kube and local mode.

### Testbed

Kubernetes tests require a Kubernetes master reachable from the SONiC DUT. In order to connect each SONiC DUT to a High Availability Kubernetes master, we need to set up the following topology on a testbed server: 
![alt text](https://github.com/isabelmsft/k8s-ha-master-starlab/blob/master/k8s-testbed-linux.png)

To set up the high availability Kubernetes master, follow the instructions [here](https://github.com/Azure/sonic-mgmt/blob/master/ansible/doc/README.testbed.k8s.Setup.md#how-to-setup-high-availability-kubernetes-master).

## Test Cases

### Test Case - SONiC Worker Node Join

These test cases ensure SONiC worker node is able to properly join cluster managed by Kubernetes master under various configurations.

- Join SONiC 1) master correct VIP set from minigraph, master enabled
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube join`
	3. `kubectl get nodes` on master
		- Should show SONiC DUT with `Ready` status
	4. `show kube server`
		- `IP` should be set to correct VIP from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
        - `connected` should be True

- Join SONiC 2) master incorrect VIP set from minigraph, master enabled
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube join`
		- Should output warning that VIP is incorrect
	3. `show kube server`
		- `IP` should be set to incorrect VIP from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be False
        - `connected` should be False

- Join SONiC 3) master correct VIP set using CLI commands, master enabled
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube server ip <correct VIP>`
	3. `show kube server`
		- `IP` should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	4. `sudo config kube join`
	5. `kubectl get nodes` on master
        - Should show SONiC DUT with `Ready` status

- Join SONiC 4) master incorrect VIP set using CLI commands, master enabled
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube server ip <incorrect VIP>`
	3. `sudo config kube join`
        - Should output warning that VIP is incorrect
	4. `show kube server`
		- `IP` should be set to <incorrect VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be False
		- `connected` should be False

- Join SONiC 5) master disabled
	1. `sudo config kube server disable on`
	2. `sudo config kube server ip <(in)correct VIP>`
    3. `sudo config kube join`
        - Should output warning that master is disabled, join request not processed
	3. `show kube server`
		- `IP` should be set to <(in)correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be True
        - `server_reachability` should be False iff incorrect VIP was used in step 2
		- `connected` should be False

- Join SONiC 6) join when SONiC DUT is already connected

- Join SONiC 7) join, cancel join request before finished, then join again

- Join SONiC 8) join, cancel join request before finished, then reset

- Join SONiC 9) join, change master VIP to an (in)valid master VIP, then join

- Join SONiC 10) In all cases when Insecure is off, output warning that Secure transfer is not yet enabled


### Test Cases - SONiC Worker Node Reset

These test cases ensure SONiC worker node is able to properly remove itself from cluster managed by Kubernetes master under various configurations.

- Reset SONiC 1) master correct VIP set from minigraph, master enabled
	1. `show kube server`
    	- `IP` should be set to <correct VIP> from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	2. `kubectl get nodes` on master
        - Should show SONiC DUT with `Ready` status
    3. `sudo config kube reset`
	4. `kubectl get nodes` on master
		- Should reflect SONiC DUT removed from cluster
	5. `show kube server`
    	- `IP` should be set to <correct VIP> from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be False

- Reset SONiC 2) master incorrect VIP set from minigraph, master enabled (DUT previously joined with correct VIP set)
	1. `show kube server`
    	- `IP` should be set to <incorrect VIP> from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be False
		- `connected` should be True
	2. `kubectl get nodes` on master
        - Should show SONiC DUT with `Ready` status
    3. `sudo config kube reset`
        - Should output warning that VIP is incorrect
	4. `kubectl get nodes` on master
		- Should still show SONiC DUT with `Ready` status

- Reset SONiC 3) master correct VIP set using CLI commands, master enabled
	1. `show kube server`
    	- `IP` should be set to <correct VIP> from CLI command- same VIP used to join DUT
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	2. `kubectl get nodes` on master
        - Should show SONiC DUT with `Ready` status
    2. `sudo config kube reset`
	3. `kubectl get nodes` on master
		- Should reflect SONiC DUT removed from cluster
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be False

- Reset SONiC 4) master incorrect VIP set using CLI command (after DUT joined using correct VIP), master enabled
    1. `sudo config kube server ip <incorrect VIP>`
    2. `show kube server` 
    	- `IP` should be set to <incorrect VIP> from step 1
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be False
		- `connected` should be True
	3. `kubectl get nodes` on master
        - Should show SONiC DUT with `Ready` status
    4. `sudo config kube reset`
        - Should output warning that VIP is incorrect
	5. `kubectl get nodes` on master
		- Should still show SONiC DUT with `Ready` status

- Reset SONiC 5) master valid VIP, but different than the valid VIP used to join cluster (2+ HA masters available)
    1. `sudo config kube server ip <valid VIP 2>` where valid VIP 2 is the VIP of an available HA master, but different than the master used by DUT to join the cluster
    2. `show kube server` 
    	- `IP` should be set to <valid VIP 2> from step 1
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	3. `kubectl get nodes` on master
        - Should show SONiC DUT with `Ready` status
    4. `sudo config kube reset`
        - Should output warning that this is not the valid VIP of the relevant master
	5. `kubectl get nodes` on master
		- Should still show SONiC DUT with `Ready` status

- Reset SONiC 6) master disabled- after valid joining of DUT
	1. `sudo config kube server disable on`
	2. `sudo config kube server ip <(in)correct VIP>`
	3. `show kube server`
		- `IP` should be set to <(in)correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be True
        - `server_reachability` should be False iff incorrect IP was used in step 2
		- `connected` should be True
    4. `sudo config kube reset`
        - Should output warning that master is disabled, reset request not processed
    5. `sudo config kube server disable off`
    6. `sudo config kube server ip <(in)correct VIP>`
    7. `show kube server`
    	- `IP` should be set to <(in)correct VIP> from step 6
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be False iff incorrect VIP was used in step 6
		- `connected` should be True
    8. `sudo config kube reset`
        - Should output warning that VIP is incorrect iff incorrect VIP was used in step 6
    9. `kubectl get nodes` on master
        - Should show DUT properly removed from cluster iff correct VIP was used in step 6

- Reset SONiC 7) reset with correct VIP, reset again with correct VIP, master enabled throughout

- Reset SONiC 8) reset with correct VIP, then change to incorrect VIP and reset again, master enabled throughout

- Reset SONiC 9) reset with correct VIP, cancel reset request in middle, then resubmit reset request, master enabled throughout

- Reset SONiC 10) reset with incorrect VIP, cancel reset request in middle, change to correct VIP, then resubmit reset request, master enabled throughout

- Reset SONiC 11) In all cases when Insecure is off, output warning that Secure transfer is not yet enabled

### Test Cases - Manifest Deployment from Master

These test cases ensure manifest applications from Kubernetes master are properly processed by SONiC DUT worker nodes. "Master reachable" implies master is enabled, and configured VIP is correct and valid. 

- Manifest Deployment from Master 1) kube mode feature, master reachable, update manifest deployment with incorrect image URL, ACR reachable
	1. `config feature owner kube`
	2. `sudo config kube disable off` (by default)
	3. `sudo config kube server ip <correct VIP>`
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from step 3
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	5. `show features`
	6. `docker ps`
		- Should see k8s container for feature running in kube mode
	7. From master: deploy manifest with wrong URL
		- Should output warning that image does not exist at URL
	8. `docker ps`
		- Should observe same k8s container from step 6 running in kube mode
	9. Fix manifest URL
	10. From master: reapply manifest
	11. `docker ps`
		- Should observe new k8s container with newer image version, feature running in kube mode
	12. `kubectl get pods`
        - Should observe new pod that corresponds to new container

- Manifest Deployment from Master 2) kube mode feature, master reachable, update manifest deployment with incorrect image URL, ACR unreachable
	1. `config feature owner kube`
	2. `sudo config kube disable off` (by default)
	3. `sudo config kube server ip <correct VIP>`
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from step 3
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	5. `show features`
	6. `docker ps`
		- Should see k8s container for feature running
	7. Remove proxy to simulate unreachable ACR
	8. From master: deploy manifest with incorrect URL
		- Should output warning that cannot reach ACR
	9. Add proxy to reach ACR
	10. Proceed prior test from step 9

- Manifest Deployment from Master 3) kube mode feature, master reachable, update manifest deployment with correct image URL, ACR reachable
	1. `config feature owner kube`
	2. `sudo config kube disable off` (by default)
	3. `sudo config kube server ip <correct VIP>`
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from step 3
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	5. `show features`
	6. `docker ps`
		- Should observe feature running in kube mode
	7. From master: Deploy manifest with correct URL
	8. `docker ps`
		- Should observe new k8s container with newer image version, feature running in kube mode
	9. `kubectl get pods`
        - Should observe new pod that corresponds to new container

- Manifest Deployment from Master 4) kube mode feature, master reachable, update manifest deployment with correct image URL, ACR unreachable
	1. `config feature owner kube`
	2. `sudo config kube disable off` (by default)
	3. `sudo config kube server ip <correct VIP>`
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from step 3
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	5. `show features`
	6. `docker ps`
		- Should see k8s container for feature running in kube mode
	7. Remove proxy to simulate unreachable ACR
	8. From master: deploy manifest with correct URL
		- Output warning that cannot reach ACR
	9. Add proxy to simulate reachable ACR
	10. Repeat prior test from step 7

- Manifest Deployment from Master 5) kube mode, when master starts as not reachable when manifest is deployed: 
	1. `config feature owner kube`
	2. `sudo config kube disable on` AND/OR `sudo config kube server <incorrect VIP>`
	3. `show kube server`
		- `IP` should be set to <incorrect VIP> iff <incorrect VIP> was set in step 2. Otherwise, it should be the previously set <correct VIP>
		- `insecure` should be True
		- `disable` should be True iff master was disabled in step 2
        - `server_reachability` should be False iff <incorrect VIP> was set in step 2. Else, should be True
		- `connected` should be True
	4. From master: `kubectl get pods`
	5. From master: apply manifest
	6. From master: `kubectl get pods`
		- Should observe the same pods that were output in step 4
	7. Make master reachable, fixing either VIP or enabling master connection as necessary
	8. `kubectl get pods` or `docker ps`
		- Should observe correct pods/containers from most recent manifest deployment that originally did not go through due to unreachable master

- Manifest Deployment from Master 6) kube mode, when master starts as reachable and changes to unreachable in middle of manifest deployment: 
	1. `config feature owner kube`
	2. `sudo config kube disable off` (by default)
	3. `sudo config kube server ip <correct VIP>`
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from step 3
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	5. From master: `kubectl get pods`
	6. From master: apply manifest
	7. Before deployment in DUT, make master unreachable (disable and/or set incorrect VIP)
	8. Wait
	9. `docker ps`
		- Check if updated manifest image container was created
		- If it was:
			- `kubectl get pods` at master would not reflect new pod until after master is made reachable again
			- `kubectl get pods` on SONiC will not work, as there is no connection to master
	10. Make master reachable (set correct VIP or enable master as necessary)
    11. `docker ps`
    12. `kubectl get pods`
         - Should observe new pod that corresponds to new k8s feature from udpated manifest


To kube with higher, same, and lower image version

Deploy manifest,
Remove DUT
Deploy manifest
Join DUT

All of the above conditions with new manifest as well (not just updating preexisting manifest)

### Test Cases - Transition between Kube and Local Mode

These test cases ensure transitions betbetween kube and local mode for a SONiC feature happen as expected when the master is reachable and unreachable. 

- Mode Transition 1) local to kube with master reachable, kube version exists
	1. `sudo config kube disable off` (by default)
	2. `sudo config kube server ip <correct VIP>`
	3. `show kube server`
        - `IP` should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	4. `show features`
		- Should observe feature currently in `local` mode
		- Should observe `remote_state` set to `None`
	5. `kubectl get pods`
	6. Deploy manifest successfully (test case 3 from MANIFEST DEPLOYMENT)
	7. `show features`
		- Should observe `remote_state` set to `pending`
	8. `kubectl get nodes --show-labels`
	9. `kubectl get pods`
	10. `sudo config feature owner kube`
	11. `kubectl get nodes --show-labels`
		- Should observe newly created label
	12. `kubectl get pods`
		- Should observe new pod come up for nearly set kube feature
	13. `Docker ps`
		- Should observe local feature container killed
		- Should observe new kube feature container created

- Mode Transition 2) local to kube with master reachable, kube version does not exist
	1. `sudo config kube disable off` (by default)
	2. `sudo config kube server ip <correct VIP>`
	3. `show kube server`
        - `IP` should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	4. `show features`
		- Should observe feature currently in `local` mode
		- Should observe `remote_state` set to `None`
	5. `kubectl get pods`
	7. `sudo config feature owner kube`
		- Should output error that this feature does has `remote_state` set to `None`

- Mode Transition 3) local to kube without master reachable, kube version exists
	1. `sudo config kube disable on` AND/OR `sudo config kube server <incorrect VIP>`
	2. `show kube server`
		- `IP` should be set to <incorrect VIP> iff <incorrect VIP> was set in step 1. Otherwise, it should be the previously set <correct VIP>
		- `insecure` should be True
		- `disable` should be True iff master was disabled in step 1
        - `server_reachability` should be False iff <incorrect VIP> was set in step 1. Else, should be True
		- `connected` should be True
	3. `docker ps`
	4. `show features`
		- Should observe feature currently in local mode
		- Should observe `remote_state` set to `pending` (manifest was deployed previously when master was reachable)
	6. `sudo config feature owner kube`
		- Should output warning that server is disabled if disabled. If not disabled, should output warning that VIP is invalid
		- Label request should go to transient DB 
	7. `docker ps`
		- Local container continues to run until master is reachable, label is created, and kubelet can spin up the new container
		
- Mode Transition 4) local to kube without master reachable, kube version does not exist
	1. `sudo config kube disable on` AND/OR `sudo config kube server <incorrect VIP>`
	2. `show kube server`
		- `IP` should be set to <incorrect VIP> iff <incorrect VIP> was set in step 1. Otherwise, it should be the previously set <correct VIP>
		- `insecure` should be True
		- `disable` should be True iff master was disabled in step 1
        - `server_reachability` should be False iff <incorrect VIP> was set in step 1. Else, should be True
		- `connected` should be True
	3. `show features`
		- Feature currently in local mode
		- Remote_state shows None
	4. `sudo config feature owner kube`
		- Should output warning that master is disabled if master is disabled. If not disabled, should output warning that VIP is incorrect. And there is no valid kube version. 
	5. `docker ps`
		a. Local container continues to run

- Mode Transitions 5) kube to local with master reachable
	1. `sudo config kube disable off` (by default)
	2. `sudo config kube server ip <correct VIP>`
	3. `show kube server`
        - `IP` should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	4. `show features`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	5. `docker ps`
		- Should observe k8s container running
	6. `kubectl get nodes --show-labels`
	7. `sudo config feature owner local`
	8. `kubectl get nodes --show-labels`
		- Should observe _enabled label for this node removed
	9. `docker ps`
		- Should observe k8s container stopped
		- Should observe local container running
	10. `show features`
		- Should observe feature currently in local mode

- Mode Transitions 6) kube to local without master reachable 
	1. `sudo config kube disable on` AND/OR `sudo config kube server <incorrect VIP>`
	2. `show kube server`
		- `IP` should be set to <incorrect VIP> iff <incorrect VIP> was set in step 1. Otherwise, it should be the previously set <correct VIP>
		- `insecure` should be True
		- `disable` should be True iff master was disabled in step 1
        - `server_reachability` should be False iff <incorrect VIP> was set in step 1. Else, should be True
		- `connected` should be True
	3. `show features`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	4. `sudo config feature owner local`
		- Should output warning that server is disabled if disabled. If not disabled, should output warning that VIP is invalid
		- Label request should go to transient DB 
	5. `docker ps`
		- Should observe local container running
	6. `show features`
		- Should observe feature in local mode
	7. When master is reachable, label removal request should go through and kube container should not come up again
		
Kube to Kube considered in MANIFEST DEPLOYMENT section

Also consider master starts as reachable, then changes to unreachable
Also consider master starts as unreachable, then changes to reachable


### Test Cases - SONiC Reboot

These test cases ensure that kube and local features behave as expected across a switch reboot. 

- SONiC Reboot 1) kube mode feature, server reachable persistent across reboot and following transition to unreachable (consider both incorrect VIP and disabled server)
	1. `sudo config kube disable off` (by default)
	2. `sudo config kube server ip <correct VIP>`
	3. `show kube server`
        - `IP` should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	4. `show features`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	5. reboot
	6. `kubectl get nodes`
		- API Server should be reachable from DUT
	7. `sudo config kube disable on` AND/OR `sudo config kube server <incorrect VIP>`
	8. `show kube server`
		- `IP` should be set to <incorrect VIP> iff <incorrect VIP> was set in step 1. Otherwise, it should be the previously set <correct VIP>
		- `insecure` should be True
		- `disable` should be True iff master was disabled in step 1
        - `server_reachability` should be False iff <incorrect VIP> was set in step 1. Else, should be True
		- `connected` should be True
	9. `kubectl get nodes`
		- Should output warning that server is disabled if disabled. If not, output warning that VIP is invalid.
	10. `docker ps`
		- Should still show kube feature containers running
	

- SONiC Reboot 2) kube mode feature, server unreachable (consider both incorrect VIP and disabled server) persistent across reboot and following transition to reachable
	1. `sudo config kube disable on` AND/OR `sudo config kube server <incorrect VIP>`
	2. `show kube server`
		- `IP` should be set to <incorrect VIP> iff <incorrect VIP> was set in step 1. Otherwise, it should be the previously set <correct VIP>
		- `insecure` should be True
		- `disable` should be True iff master was disabled in step 1
        - `server_reachability` should be False iff <incorrect VIP> was set in step 1. Else, should be True
		- `connected` should be True
	3. `docker ps`
	4.  reboot
	5. `kubectl get nodes`
		- API Server should be unreachable
	6. `sudo config kube disable off` AND/OR sudo `config kube server <correct VIP>` as necessary to make master reachable
	7. `show kube server`
        - `IP` should be set to <correct VIP> 
		- `insecure` should be True
		- `disable` should be False
        - `server_reachability` should be True
		- `connected` should be True
	8. `kubectl get nodes`
		- API Server should be reachable
	9. `docker ps`
		- All kube managed containers running in step 3 should still be working, relevant features may have changed from local to kube mode once server became reachable
	

- SONiC Reboot 3) reboot SONiC while feature in kube mode, fallback to local set to true
	1. `docker ps` or `show features`
		- Should observe feature/container running local mode
	2. `config feature owner kube`
		- Local to kube transition
	3. `docker ps`
		- Should observe feature running kube mode
	4. reboot
		- Should bring in local version (fallback to local)
		- Kube will connect
		- Local to kube transition
	5. `docker ps`
		- Should observe feature running kube mode

- SONiC Reboot 4) reboot SONiC while feature in kube mode, fallback to local set to false
	1. `docker ps`
		- Should observe feature running local mode
	2. `config feature owner kube`
		- Local to kube transition
	3. `docker ps`
		- Should observe feature running kube mode
	4. reboot
		- Kube will connect
	5. `docker ps`
		- Should observe feature running kube mode



### Test Cases - HA Master Functionality

When master transitions between reachable and unreachable: transient DB label processing


### Test Cases - Miscellaneous

Systemctl start/stop/restart works as today for both local and kube modes

When node joins, make sure the proper manufacturer labels and others are set (included in manifest deployment test)

SONiC HW labels present when SONiC join

Deployment of new feature not already part of SONiC switch