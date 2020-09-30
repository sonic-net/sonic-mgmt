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

- Join SONiC 9) join, change master VIP to an (in)valid master VIP, then reset

- Join SONiC 10) join, change master VIP to an (in)valid master VIP, then join

- Join SONiC 11) In all cases when Insecure is off, output warning that Secure transfer is not yet enabled


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

- Reset, then reset again

### Test Cases - Manifest Deployment from Master
asdf

### Test Cases - Transition between Kube and Local Mode
asdf

### Test Cases - SONiC Reboot
asdf

### Test Cases - HA Master Functionality
asdf

### Test Cases - Miscellaneous
asdf