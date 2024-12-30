# KubeSonic Test Plan

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
    - [Testbed](#testbed)
    - [k8s version](#k8s-version)
    - [Supported hwsku](#supported-hwsku)
- [Topology](#topology)
- [Test SONIC DUT join and disjoin from k8s cluster](#test-sonic-dut-join-and-disjoin-from-k8s-cluster)
  - [Pre-requisite steps](#pre-requisite-steps)
    - [Install Minikube and start Minikube](#install-minikube-and-start-minikube)
    - [Update the server kernel parameter](#update-the-server-kernel-parameter)
    - [Update the kubelet configmap](#update-the-kubelet-configmap)
    - [Deploy the daemonset](#deploy-the-daemonset)
    - [Prepare the cert](#prepare-the-cert)
    - [Prepare Minikube VIP DNS](#prepare-minikube-vip-dns)
  - [[Case-1] Join the SONIC DUT to the Minikube cluster and check](#case-1-join-the-sonic-dut-to-the-minikube-cluster-and-check)
  - [[Case-2] Deploy daemonset pod on the SONIC DUT and check](#case-2-deploy-daemonset-pod-on-the-sonic-dut-and-check)
  - [[Case-3] Remove daemonset pod from the SONIC DUT and check](#case-3-remove-daemonset-pod-from-the-sonic-dut-and-check)
  - [[Case-4] Disjoin the SONIC DUT from the Minikube cluster and check](#case-4-disjoin-the-sonic-dut-from-the-minikube-cluster-and-check)
  - [Teardown](#teardown)
    - [Clean up](#clean-up)
    - [Keep the Minikube cluster running](#keep-the-minikube-cluster-running)
  - [File Lock to avoid Minikube cluster setup conflict](#file-lock-to-avoid-minikube-cluster-setup-conflict)


## Revision

| Rev |     Date    |       Author          |         Change Description         |
|:---:|:-----------:|:---------------------:|:----------------------------------:|
| 0.1 |  12/25/2024 |         Yun           |          Initial version           |

## Overview

The purpose is to test the functionality of k8s feature on the SONIC DUT. The tests expect that SONIC can join a k8s cluster and k8s daemonset pod can run on SONIC.

## Scope

### Testbed

The test is able to run on SONIC KVM testbed and SONIC DUT testbed

### K8s version

This case only runs for k8s v1.22.2

### Supported hwsku

Arista-7060CX/Arista-7050QX/Arista-7050-Q16S64/Celestica-E1031-T48S4 is not supported, other hwskus should be supported

## Topology

Supported any topology

## Test SONIC DUT join and disjoin from k8s cluster

### Pre-requisite steps

Use Minikube to startup a single master k8s cluster on the server where the ptf container and simulating neighbor containers are running on in the testbed.

#### Install Minikube and start Minikube
- Install Minikube and start Minikube on the server of the testbed by following the instructions in the [Minikube installation guide](https://minikube.sigs.k8s.io/docs/start/).

#### Update the server kernel parameter
- Update the server kernel parameter by running the following command ```sysctl fs.protected_regular=0```. [Check the issue here](https://github.com/kubernetes/minikube/issues/7053)

#### Update the kubelet configmap
- The Minikube cluster's pki cert root directory is `/var/lib/minikube/certs`, SONIC DUT's kubelet is using `/etc/kubernetes/pki` as the pki cert root directory. So need to update the kubelet configmap.

#### Deploy the daemonset
- Deploy the daemonset with nodeSelector `deployDaemonset=true` so that we can control whether the daemonset pod runs on the SONIC DUT by labeling node and unlabeling node.

#### Prepare the cert
- SONIC DUT will need a cert to join the k8s cluster, so need to prepare the cert for it. Copy the cert from the Minikube cluster to the SONIC DUT.

#### Prepare Minikube VIP DNS
- Minikube cluster's VIP is ```control-plane.minikube.internal```, SONIC DUT will not resolve this VIP by default, so need to add the VIP to the SONIC DUT's `/etc/hosts` file.

### [Case-1] Join the SONIC DUT to the Minikube cluster and check

- ```sudo config kube server ip <server_ip> && sudo config kube server disable off``` to trigger the SONIC DUT to join the k8s cluster, check if the SONIC DUT is in the k8s cluster by running `kubectl get nodes` on the server.

### [Case-2] Deploy daemonset pod on the SONIC DUT and check
- ```kubectl label node <node_name> deployDaemonset=true``` to control the k8s daemonset pod to run on the SONIC DUT, check if the pod is running on the SONIC DUT by running `kubectl get pods` on the server.

### [Case-3] Remove daemonset pod from the SONIC DUT and check
- ```kubectl label node <node_name> deployDaemonset-``` to prevent the k8s daemonset pod from running on the SONIC DUT, check if the pod is removed from the SONIC DUT by running `kubectl get pods` on the server.

### [Case-4] Disjoin the SONIC DUT from the Minikube cluster and check
- ```sudo config kube server disable on``` to trigger the SONIC DUT to disjoin the k8s cluster, check if the SONIC DUT is not in the k8s cluster by running `kubectl get nodes` on the server.

### Teardown

#### Clean up
- Remove the Minikube cluster and restore all changes on the server of the testbed and the SONIC DUT.

#### Keep the Minikube cluster running
- If the server of testbed is shared with other tests, need keep the Minikube cluster running to avoid conflict.

### File Lock to avoid Minikube cluster setup conflict
- When the server is shared with other testbed, need to lock the server when setup the Minikube cluster to avoid conflict, otherwise, two test plans may create the Minikube cluster on the same server at the same time which is not expected. When one test plan is creating the Minikube cluster, another test plan just need to wait and directly use the Minikube cluster after it's ready. In the setup step, require a file lock to setup the Minikube cluster, after the Minikube cluster is setup, release the file lock. When the test case trys to setup the Minikube cluster, check if the file lock is acquired. If yes, wait until the file lock is released. If the wait time is longer than max wait time, re-acquire the file lock and setup the Minikube cluster again.
