# MCLAG Test Plan

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
    - [Testbed](#testbed)
    - [k8s version](#k8s-version)
    - [Supported hwsku](#supported-hwsku)
- [Topology](#topology)
- [Test DUT join and disjoin from k8s cluster](#test-dut-join-and-disjoin-from-k8s-cluster)
    - [Setup](#setup)
      - [Install Minikube and start Minikube](#install-minikube-and-start-minikube)
      - [Update the server kernel parameter](#update-the-server-kernel-parameter)
      - [Update the kubelet configmap](#update-the-kubelet-configmap)
      - [Deploy the daemonset](#deploy-the-daemonset)
      - [Prepare the cert](#prepare-the-cert)
      - [Prepare Minikube VIP DNS](#prepare-minikube-vip-dns)
    - [Trigger DUT to join](#trigger-dut-to-join)
    - [Trigger DUT to be deployed daemonset pod](#trigger-dut-to-be-deployed-daemonset-pod)
    - [Trigger daemonset pod to be removed from the DUT](#trigger-daemonset-pod-to-be-removed-from-the-dut)
    - [Trigger DUT to disjoin](#trigger-dut-to-disjoin)
    - [Teardown](#teardown)
      - [Clean up](#clean-up)
      - [Keep the Minikube cluster running](#keep-the-minikube-cluster-running)
    - [Server lockup](#server-lockup)


## Revision

| Rev |     Date    |       Author          |         Change Description         |
|:---:|:-----------:|:---------------------:|:----------------------------------:|
| 0.1 |  12/25/2024 |         Yun           |          Initial version           |

## Overview

The purpose is to test the functionality of KubeSonic feature on the SONIC switch DUT. The tests expecting that SONIC can join a k8s cluster and can be deployed a k8s daemonset pod.

## Scope

### Testbed

The test is able to run on KVM testbed and DUT testbed

### K8s version

This case only runs on k8s v1.22.2

### Supported hwsku

7060 / 7050qx is not supported

## Topology

Supported any topology

## Test DUT join and disjoin from k8s cluster

### Setup

Use Minikube to startup a single master k8s cluster on the server of the testbed where the ptf container and simulating neighbor contianers are running.

#### Install Minikube and start Minikube
1. Install Minikube and start Minikube on the server of the testbed by following the instructions in the [Minikube installation guide](https://minikube.sigs.k8s.io/docs/start/).

#### Update the server kernel parameter
2. Update the server kernel parameter by running the following command ```sysctl fs.protected_regular=0```. [Check the issue here](https://github.com/kubernetes/minikube/issues/7053)

#### Update the kubelet configmap
3. The Minikube cluster's pki cert root directory is `/var/lib/minikube/certs`, DUT's kubelet is using `/etc/kubernetes/pki` as the pki cert root directory. So need to update the kubelet configmap.

#### Deploy the daemonset
4. Deploy the daemonset with nodeSelector `deployDaemonset=true` so that we can trigger the daemonset pod to be deployed or to be removed on the DUT with label and unlabel.

#### Prepare the cert
5. DUT will need a cert to join the k8s cluster, so need to prepare the cert for the DUT. Copy the cert from the Minikube cluster to the DUT.

#### Prepare Minikube VIP DNS
6. Minikube cluster's VIP is ```control-plane.minikube.internal```, DUT will not resolve this VIP by default, so need to add the VIP to the DUT's `/etc/hosts` file.

### Trigger DUT to join

1. ```sudo config kube server ip <server_ip> && sudo config kube server disable off``` to trigger the DUT to join the k8s cluster, check if the DUT is in the k8s cluster by running `kubectl get nodes` on the server.

### Trigger DUT to be deployed daemonset pod
2. ```kubectl label node <node_name> deployDaemonset=true``` to trigger the k8s daemonset pod to be deployed on the DUT, check if the pod is running on the DUT by running `kubectl get pods` on the server.

### Trigger daemonset pod to be removed from the DUT
3. ```kubectl label node <node_name> deployDaemonset-``` to trigger the k8s daemonset pod to be removed from the DUT, check if the pod is removed from the DUT by running `kubectl get pods` on the server.

### Trigger DUT to disjoin
4. ```sudo config kube server disable on``` to trigger the DUT to disjoin the k8s cluster, check if the DUT is not in the k8s cluster by running `kubectl get nodes` on the server.

### Teardown

#### Clean up
Remove the Minikube cluster and restore all changes on the server of the testbed and the DUT.

#### Keep the Minikube cluster running
If the server of testbed is shared with other tests, need keep the Minikube cluster running to avoid conflict.

### Server lockup
When the server is shared with other testbed, need to lock the server when setup the Minikube cluster to avoid conflict. In the setup step, require a file lock to setup the Minikube cluster, after the Minikube cluster is setup, release the file lock. When the test case trys to setup the Minikube cluster, check if the file lock is acquired, if yes, wait until the file lock is released.
If the wait time is longer than max wait time, re-acquire the file lock and setup the Minikube cluster again.
