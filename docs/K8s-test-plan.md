# Kubernetes test plan

- [Kubernetes test plan](#Kubernetes-test-plan)
  - [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
  - [Test cases](#test-cases)
    - [SONiC Worker Node Join](#test-case---sonic-worker-node-join)

    - [SONiC Worker Node Reset](#test-case---sonic-worker-node-reset)

    - [Manifest Deployment](#test-case---manifest-deployment-from-master)

    - [Transition between Kube and Local Mode](#test-case---transition-between-kube-and-local-mode)

    - [SONiC Reboot](#test-case---sonic-reboot)

    - [HA Master Functionality](#test-case---ha-master-functionality)

    - [Miscellaneous](#test-case---miscellaneous)


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
These test cases ensure SONiC worker node is able to properly join cluster managed by Kubernetes master under various configurations

- Master correct VIP set from minigraph, master enabled
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube join`
	3. `kubectl get nodes`
		a. SONiC DUT should show with `Ready` status
	4. `show kube server`
		a. Server VIP should be set to correct VIP from minigraph
		b. Insecure should be True
		c. Disable should be false
        d. Connected should be True

### Test Case - SONiC Worker Node Reset
asdf

### Test Case - Manifest Deployment from Master
asdf

### Test Case - Transition between Kube and Local Mode
asdf

### Test Case - SONiC Reboot
asdf

### Test Case - HA Master Functionality
asdf

### Test Case - Miscellaneous
asdf