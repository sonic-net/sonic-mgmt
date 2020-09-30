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

- Reset SONiC 9) reset with correct VIP, cancel reset request in middle, then resubmit reset request


### Test Cases - Manifest Deployment from Master

Kube mode feature, master reachable, update manifest deployment with incorrect image URL, ACR reachable
	1. Config feature owner kube
	2. Sudo config kube disable = false (by default)
	3. Sudo config kube server IP <correct VIP>
	4. Show kube server
		a. Server VIP should be set to <correct VIP> from step 3
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	5. Show features
	6. Docker ps
		a. Observe feature running in kube mode
	7. From master: deploy manifest with wrong URL
		a. Should output warning that image does not exist at URL
	8. Docker ps
		a. Observe same container from 6a running in kube mode
	9. Fix manifest URL
	10. From master: reapply manifest
	11. Docker ps
		a. Observe new container with newer version running in kube mode

Kube mode feature, master reachable, update manifest deployment with incorrect image URL, ACR unreachable
	1. Config feature owner kube
	2. Sudo config kube disable = false (by default)
	3. Sudo config kube server IP <correct VIP>
	4. Show kube server
		a. Server VIP should be set to <correct VIP> from step 3
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	5. Show features
	6. Docker ps
		a. Observe feature running in kube mode
	7. Remove proxy to simulate unreachable ACR
	8. From master: deploy manifest with incorrect URL
		a. Output warning that cannot reach ACR
	9. Add proxy to reach ACR
	10. Proceed prior test from step 9

Kube mode feature, master reachable, update manifest deployment with correct image URL, ACR reachable
	1. Config feature owner kube
	2. Sudo config kube disable = false (by default)
	3. Sudo config kube server IP <correct VIP>
	4. Show kube server
		a. Server VIP should be set to <correct VIP> from step 3
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	5. Show features
	6. Docker ps
		a. Observe feature running in kube mode
	7. From master: Deploy manifest with correct URL
	8. Docker ps
		a. Observe feature running in kube mode- updated image version
	9. Kubectl get pods

Kube mode feature, master reachable, update manifest deployment with correct image URL, ACR unreachable
	1. Config feature owner kube
	2. Sudo config kube disable = false (by default)
	3. Sudo config kube server IP <correct VIP>
	4. Show kube server
		a. Server VIP should be set to <correct VIP> from step 3
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	5. Show features
	6. Docker ps
		a. Observe feature running in kube mode
	7. Remove proxy to simulate unreachable ACR
	8. From master: deploy manifest with correct URL
		a. Output warning that cannot reach ACR
	9. Add proxy
	10. Repeat prior test from step 7

To test all kube mode feature cases, when master starts as not reachable: 
	1. Config feature owner kube
	2. Sudo config kube disable = true AND/OR sudo config kube server <incorrect VIP>
	3. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2 OR <incorrect VIP> from step 2, where applicable
		b. Insecure should be True
		c. Disable should be true OR False if only <incorrect VIP> was set in step 2
		d. Connected should be True OR False if <incorrect VIP> was set in step 2
	4. From master: kubectl get pods
	5. From master: apply manifest
	6. From master: kubectl get pods
		a. Should be same pods output as in step 4
	7. Make master reachable, fixing either VIP or enabling master connection
	8. Kubectl get pods
		a. Observe correct pods come up from most recent manifest deployment that originally did not go through due to unreachable master

To test all kube mode feature cases, when master starts as reachable and changes to unreachable in middle of manifest deployment: 
	1. Config feature owner kube
	2. Sudo config kube disable = false (by default)
	3. Sudo config kube server IP <correct VIP>
	4. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	5. From master: kubectl get pods
	6. From master: apply manifest
	7. Before deployment finishes, go into node not yet updated and make master unreachable (disable or make incorrect VIP)
	8. Wait
	9. Docker ps
		a. Check if updated manifest image container was created
		b. If it was:
			i. Kubectl get pods at master would not reflect new pod until after master is made reachable again
			ii. Kubectl get pods on SONiC will not work, as there is no connection to master
	10. Make master reachable
		a. Kubectl get pods at master should show new pod that corresponds to container

To kube with higher, same, and lower image version

All of the above conditions with new manifest as well (not just updating preexisting manifest)

### Test Cases - Transition between Kube and Local Mode

MODE TRANSITIONS

Kube version exists: feature has remote_state ready

Local to kube with master reachable, kube version exists
	1. Sudo config kube disable = false (by default)
	2. Sudo config kube server IP <correct VIP>
	3. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	4. Show features
		a. Feature currently in local mode
		b. Remote_state set to none
	5. Kubectl get pods
	6. Deploy manifest successfully (test case 3 from MANIFEST DEPLOYMENT)
	7. Show feature
		a. Remote_state of feature shows ready
	8. Kubectl get nodes --show-labels
	9. Kubectl get pods
	10. Sudo config feature owner kube
	11. Kubectl get nodes --show-labels
		a. Should show newly created label
	12. Kubectl get pods
		a. New pod comes up with newly configured feature
	13. Docker ps
		a. Old local feature container killed
		b. New kube feature container created
	

Local to kube with master reachable, kube version does not exist
	1. Sudo config kube disable = false (by default)
	2. Sudo config kube server IP <correct VIP>
	3. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	4. Show features
		a. Feature currently in local mode
		b. Remote_state set to none
	5. Kubectl get pods
	6. Show feature
		a. Remote_state shows none
	7. Sudo config feature owner kube
		a. Output error that this feature does has remote_state none

Local to kube without master reachable, kube version exists
	1. Sudo config kube disable = true OR false (by default)
	2. Sudo config kube server IP <correct VIP> OR <incorrect VIP> 
	3. Docker ps
	4. Show kube server
		a. Server VIP should be set to <correct VIP> OR <incorrect VIP> from step 2
		b. Insecure should be True
		c. Disable should be true OR false if only <incorrect VIP> was set in step 2 
		d. Connected should be True or False if <incorrect VIP> was set in step 2
	5. Show features
		a. Feature currently in local mode
		b. Remote_state shows pending (manifest was deployed previously when master was reachable)
	6. Sudo config feature owner kube
		a. Output warning that server is disabled if disabled. If not, output warning that server is not reachable. Check VIP connection.
		b. Label request should go to transient DB 
	7. Docker ps
		a. Local container continues to run until master is reachable, label is created, and kubelet can spin up the new container
		
Local to kube without master reachable, kube version does not exist
	1. Sudo config kube disable = true OR false (by default)
	2. Sudo config kube server IP <correct VIP> OR <incorrect VIP> 
	3. Docker ps
	4. Show kube server
		a. Server VIP should be set to <correct VIP> OR <incorrect VIP> from step 2
		b. Insecure should be True
		c. Disable should be true OR false if only <incorrect VIP> was set in step 2 
		d. Connected should be True or False if <incorrect VIP> was set in step 2
	5. Show features
		a. Feature currently in local mode
		b. Remote_state shows None
	6. Sudo config feature owner kube
		a. Output warning that master is disabled (or incorrect VIP, check VIP connection), and there is no valid kube version. Check connectivity and availability of kube image
	7. Docker ps
		a. Local container continues to run
	

Kube to local with master reachable
	1. Sudo config kube disable = false (by default)
	2. Sudo config kube server IP <correct VIP>
	3. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	4. Show features
		a. Feature currently in kube
		b. Remote_state set to running
	5. Docker ps
		a. K8s container running
	6. Kubectl get nodes --show-labels
	7. Sudo config feature owner local
	8. Kubectl get nodes --show-labels
		a. Labels for this node removed
	9. Docker ps
		a. K8s container stopped
		b. Local container running
	10. Show features
		a. Feature currently in local


Kube to local without master reachable 
	1. Sudo config kube disable = true OR false (by default)
	2. Sudo config kube server IP <correct VIP> OR <incorrect VIP> 
	3. Docker ps
	4. Show kube server
		a. Server VIP should be set to <correct VIP> OR <incorrect VIP> from step 2
		b. Insecure should be True
		c. Disable should be true OR false if only <incorrect VIP> was set in step 2 
		d. Connected should be True or False if <incorrect VIP> was set in step 2
	5. Show features
		a. Feature currently in kube mode
		b. Remote_state set to Running
	6. Sudo config feature owner local
		a. Output warning that server is disabled if disabled. If not, output warning that server is not reachable. Check VIP connection.
		b. Label removal request should go to transient DB 
	7. Docker ps
		a. Should show local container running
	8. Show features
		a. Feature should be local mode
	9. When master is reachable, label removal request will go through and kube container should not come up again
		
Kube to Kube considered in MANIFEST DEPLOYMENT section

Also consider master starts as reachable, then changes to unreachable
Also consider master starts as unreachable, then changes to reachable


### Test Cases - SONiC Reboot

REBOOT SONiC

Server reachable persistent across reboot and following transition to unreachable (consider both incorrect VIP and disabled server)
	1. Sudo config kube disable = false (by default)
	2. Sudo config kube server IP <correct VIP>
	3. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2
		b. Insecure should be True
		c. Disable should be false
		d. Connected should be True
	4.  reboot
	5. Kubectl get nodes
		a. API Server should be reachable
	6. Sudo config kube disable = true AND/OR sudo config kube server <incorrect VIP>
	7. Show kube server
		a. Server VIP should be set to <correct VIP> from step 2 OR <incorrect VIP> from step 6, where applicable
		b. Insecure should be True
		c. Disable should be true OR False if only <incorrect VIP> was set in step 6
		d. Connected should be True OR False if <incorrect VIP> was set in step 6
	8. Kubectl get nodes
		a. Output warning that server is disabled if disabled. If not, output warning that server is not reachable. Check VIP connection
	9. Docker ps
		a. Should still show kube feature containers running
	

Server unreachable (consider both incorrect VIP and disabled server) persistent across reboot and following transition to reachable
	1. Sudo config kube disable = true OR false (by default)
	2. Sudo config kube server IP <correct VIP> OR <incorrect VIP> 
	3. Docker ps
	4. Show kube server
		a. Server VIP should be set to <correct VIP> OR <incorrect VIP> from step 2
		b. Insecure should be True
		c. Disable should be true OR false if only <incorrect VIP> was set in step 2 
		d. Connected should be True or False if <incorrect VIP> was set in step 2
	5.  reboot
	6. Kubectl get nodes
		a. API Server should be unreachable
	7. Sudo config kube disable = false AND/OR sudo config kube server <correct VIP>
	8. Show kube server
		a. Server VIP should be set to <correct VIP> from step 6 
		b. Insecure should be True
		c. Disable should False
		d. Connected should be True
	9. Kubectl get nodes
		a. Server should now be connected
	10. Docker ps
		a. All kube managed containers running in step 3 should still be working, relevant features may have changed from local to kube mode once server became reachable
	

Reboot system while feature in kube mode, fallback to local set to true
	1. Docker ps
		a. Observe feature running local mode
	2. Config feature owner kube
		a. Local to kube transition
	3. Docker ps
		a. Observe feature running kube mode
	4. Reboot
		a. Should bring in local version (fallback to local)
		b. Kube will connect
		c. Local to kube transition
	5. Docker ps
		a. Observe feature running kube mode

Reboot system while feature in kube mode, fallback to local set to false
	1. Docker ps
		a. Observe feature running local mode
	2. Config feature owner kube
		a. Local to kube transition
	3. Docker ps
		a. Observe feature running kube mode
	4. Reboot
		a. Kube will connect
	5. Docker ps
		a. Observe feature running kube mode




### Test Cases - HA Master Functionality
When master transitions from unreachable to reachable: 

Process transient DB data
	1) Relevant container could be running in either kube or local mode (depending on if container was killed)
	2) Start with 1 of 3 masters up
	3) Check master connection status
	4) Add 1 or 2 masters up
	5) Check master connection status
	6) Send requests from transientDB to API server
After step 1, make sure master shows unconnected status
After step 3, make sure master shows connected status
After step 5- make sure when applicable, container transitions from local to kube mode (conditions listed in `when master reachable` section)
After step 5- make sure all label addition and removal requests are appropriately processed 
After step 5- make sure all join and remove requests are appropriately processed

When master transitions from reachable to unreachable:

Continue running existing kube-managed containers as usual
	1) Start with 2 or 3 of 3 masters up
	2) Docker ps
	3) Check master connection status
	4) Leave 0 or 1 master up
	5) Check master connection status
	6) Wait 
	7) Docker ps
After step 1, make sure master shows connected status
After step 5, make sure master shows unconnected status
After step 7, make sure kube-managed container is still running



### Test Cases - Miscellaneous

Systemctl start/stop/restart works as today for both local and kube modes

When node joins, make sure the proper manufacturer labels and others are set (included in manifest deployment test)

SONiC HW labels present when SONiC join

Deployment of new feature not already part of SONiC switch