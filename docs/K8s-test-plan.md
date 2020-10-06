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

 SONiC features can run in either kube mode or local mode. SONiC features (dockers) running in kube mode are managed by the connected Kubernetes master. From the master, we can deploy upgrades to SONiC features running in kube mode with minimal downtime. Features have the ability to switch between kube mode and local mode. For more background on Kubernetes features in SONiC and kube mode vs local mode, refer to [this document](https://github.com/renukamanavalan/SONiC/blob/kube_systemd/doc/kubernetes/Kubernetes-support.md). 

### Scope

This test plan aims to ensure proper Kubernetes management of SONiC features running in kube mode, and seamless transition of a SONiC feature between kube mode and local mode.

### Testbed

Kubernetes tests require a Kubernetes master reachable from the SONiC DUT. In order to connect each SONiC DUT to a High Availability Kubernetes master, we need to set up the following topology on a testbed server: 
![alt text](https://github.com/isabelmsft/k8s-ha-master-starlab/blob/master/k8s-testbed-linux.png)

To set up the high availability Kubernetes master, follow the instructions [here](https://github.com/Azure/sonic-mgmt/blob/master/ansible/doc/README.testbed.k8s.Setup.md#how-to-setup-high-availability-kubernetes-master).

## Test Cases

### Test Case - SONiC Worker Node Join

These test cases ensure SONiC worker node is able to properly join cluster managed by Kubernetes master under various configurations.

- Join SONiC 1) master correct VIP set from minigraph
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. `show kube server` upon bootup after services stabilized
		- `ip` in config and state should be set to correct VIP from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `connected` should be True
	2. `kubectl get nodes` on master
		- Should show newly joined SONiC DUT with `Ready` status

- Join SONiC 2) master incorrect VIP set from minigraph
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. `show kube server` upon bootup after services stabilized
		- `ip` in config should be set to incorrect VIP from minigraph
		- `insecure` should be True
		- `disable` should be False
        - `connected` should be False
	2. `kubectl get nodes` on master
		- No new SONiC DUT reflected

- Join SONiC 3) master correct VIP set using CLI commands
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube server ip <correct VIP>`
	3. `kubectl get nodes` on master
	    - Should show newly joined SONiC DUT with `Ready` status
	4. `show kube server`
		- `ip` in config and state should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be True

- Join SONiC 4) master incorrect VIP set using CLI commands
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube server ip <incorrect VIP>`
	3. `kubectl get nodes`
	   - No new SONiC DUT reflected
	4. `show kube server`
		- `ip` in config should be set to <incorrect VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be False

- Join SONiC 5) rejoin master by disabling and enabling kube server
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo config kube server ip <correct VIP>`
	3. `kubectl get nodes` on master
	    - Should show newly joined SONiC DUT with `Ready` status
	4. `show kube server`
		- `ip` in config and state should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be True
	5. `docker ps` and `show feature status`
	6. `sudo config kube server disable on` disables master
	7. `kubectl get nodes` on master
	8. `docker ps` and `show feature status`
	    - Kube mode containers from step 5 should now be running in local mode
	9. `show kube server`
		- `ip` in config and state should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be True
		- `connected` should be False
	10. `sudo config kube server disable off` enables master
	11. `show kube server`
		- `ip` in config and state should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be True
	12. `docker ps` and `show feature status`
	    - Expect same kube mode containers running as after step 5

- Join SONiC 6) connect to new valid master VIP
	0. `ping` original set of HAProxy and 3 backend master servers
	    - All should respond
	1. Follow steps from Test Case Join SONiC 3 to start with joined SONiC DUT
	2. `ping` second set of HAProxy and backend master servers
	    - All should respond
	3. `sudo config kube server ip <correct VIP 2>`
	4. `kubectl get nodes` on master 2
	   - Should show newly joined SONiC DUT with `Ready` status
	4. `show kube server`
		- `ip` in config and state should be set to <correct VIP 2> from step 3
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be True

- Join SONiC 7) connect to new invalid master VIP
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. Follow steps from Test Case Join SONiC 3 to start with joined SONiC DUT
	2. `sudo config kube server ip <incorrect VIP 2>`
	3. `show kube server`
	   - `ip` in config and state should be set to <incorrect vip 2> from step 2
	   - `insecure` should be True
	   - `disable` should be False
	   - `connected` should be False
	4. `kubectl get nodes` on original master should no longer show SONiC DUT with `Ready` status


- Join SONiC 8) connect to unreachable master server
	0. `ping` HAProxy and 3 backend master servers
	    - All should respond
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo virsh shutdown <backend master servers 1 and 2>`
	3. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	4. `sudo config kube server ip <correct VIP>`
	5. `show kube server` 
		- `ip` in config and state should be set to <correct VIP> from step 4
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be False 
	6. `sudo virsh start <backend master servers 1 and 2>`
	7. `ping` HAProxy and 3 backend master servers
	    - All should respond
	5. `show kube server` 
		- `ip` in config and state should be set to <correct VIP> from step 4
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be True 

- Join SONiC 9) connect to HA master server when just one backend server is down
	0. `ping` HAProxy and 3 backend master servers
	    - All should be respond
	1. `sudo config kube server disable off` enables master (default configuration)
	2. `sudo virsh shutdown <backend master server 1>`
	3. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and two backend masters should respond
	2. `sudo config kube server ip <correct VIP>`
	3. `kubectl get nodes` on master
	    - Should show newly joined SONiC DUT with `Ready` status
	4. `show kube server`
		- `ip` in config and state should be set to <correct VIP> from step 2
		- `insecure` should be True
		- `disable` should be False
		- `connected` should be True

TODO: insecure transfer cases


### Test Cases - SONiC Worker Node Reset

These test cases ensure SONiC worker node is able to properly remove itself from cluster managed by Kubernetes master under various configurations.

- Reset SONiC 1) master reachable after successful join
	1. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
    2. `sudo config kube server disable on`
	3. `kubectl get nodes` on master
		- Should reflect SONiC DUT removed from cluster
	4. `show kube server`
    	- `IP` should be set to <correct VIP> from Test Case Join SONiC 3
		- `insecure` should be True
		- `disable` should be True
		- `connected` should be False

- Reset SONiC 2) master unreachable after successful join
    1. Follow steps from Test Case SONiC 3 to properly join SONiC DUT
	2. `sudo virsh shutdown <backend master servers 1 and 2>`
	3. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	4. `sudo config kube server disable on`
        - Should warn that master is unreachable, so reset request was not processed


config feature owner kube, disable, then enable

### Test Cases - Manifest Deployment from Master

These test cases ensure manifest applications from Kubernetes master are properly processed by SONiC DUT worker nodes. 


- Manifest Deployment from Master 1) kube feature v1 to kube feature v2, master reachable, incorrect image URL for v2, ACR reachable (this is also tested in test case 2, can be removed)
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  From master: Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	6. From master: Apply manifest v2 for `{feature-name}` with wrong URL
	7. `docker ps`
		- Should observe same k8s container from step 4 running v1
	8. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	9. From master: reapply manifest v2 for `{feature-name}` with correct URL
	10. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	11. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	12. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container

- Manifest Deployment from Master 2) kube feature v1 to kube feature v2, master reachable, incorrect image URL for v2, ACR unreachable
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  From master: Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	6. Delete secret to simulate unreachable ACR
	7. From master: Apply manifest v2 for `{feature-name}` with incorrect URL
	8. `docker ps`
		- Should observe same k8s container from step 4 running in kube mode
	9. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	10. Create secret to simulate reachable ACR
	11. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	12. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	13. From master: reapply manifest v2 for `{feature-name}` with correct URL
	14. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	15. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	16. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container

- Manifest Deployment from Master 3) kube feature v1 to kube feature v2, master reachable, correct image URL for v2, ACR reachable
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	6. From master: Apply manifest v2 for `{feature-name}` with correct URL
	7. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	8. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	9. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container v2

- Manifest Deployment from Master 4) kube feature v1 to kube feature v2, master reachable, correct image URL for v2, ACR unreachable
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. Delete secret to simulate unreachable ACR
	6. From master: Apply manifest v2 for `{feature-name}` with correct URL
	7. `docker ps`
		- Should observe same k8s container from step 4 running v1
	8. `show feature status {feature-name}`
	    - Should show `{feature-name}` owner status is kube and running v1
	9. Create secret to simulate reachable ACR
	10. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	11. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	12. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container v2

- Manifest Deployment from Master 5) kube feature v1 to kube feature v2, when master starts as not reachable when manifest is deployed: 
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `sudo virsh shutdown <backend master servers 1 and 2>`
	6. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	7. From master: Apply manifest v2 for `{feature-name}` hangs
	8. `docker ps`
	    - Should observe same k8s container from step 4 running v1
	9. `show feature status {feature-name}`
	   - Should show `{feature-name}` owner status is kube and running v1
	10. `sudo virsh start <backend master servers 1 and 2>`
	11. `ping` HAProxy and 3 backend masters
	    - All should respond
	12. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	13. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	14. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container v2


- Manifest Deployment from Master 6) kube feature v1 to kube feature v2, when master starts as reachable and changes to unreachable in middle of manifest deployment: 
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. From master: Apply manifest v2 for `{feature-name}` with correct URL
	6. `sudo virsh shutdown <backend master servers 1 and 2>`
	7. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	8. Check if v2 request reached kubelet before master became unreachable
	9. `docker ps`
		- Should see v1 or v2 depending on if v2 request reached kubelet before master became unreachable

- Manifest Deployment from Master 7) kube feature v2 to kube feature v1, under all conditions
	0. Follow any of the Manifest Deployment from Master Test Cases above to reach running kube feature v2
	1. Apply manifest v1 for `{feature-name}`
	2. `docker ps`
		- Should show k8s container v2 for `{feature-name}` and no v1
	3. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2

- Manifest Deployment from Master 7) kube feature v2 to kube feature v2, under all conditions
	0. Follow any of the Manifest Deployment from Master Test Cases above to reach running kube feature v2
	1. Apply manifest v2 for `{feature-name}`
	2. `docker ps`
		- Should show one k8s container v2 for `{feature-name}` 
	3. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2


### Test Cases - Transition between Kube Mode and Local Mode

These test cases ensure transitions between kube mode and local mode for a SONiC feature happen as expected.

- Mode Transition 1) local to kube with master reachable
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `show feature status {feature-name}`
		- Should show current owner is local
	2. `sudo config feature owner {feature-name} kube`
	3. `show feature config {feature-name}`
		- Should show config owner is kube 
	4. From master: Apply manifest for v2 `{feature-name}`
	5. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	6. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	7. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container v2

- Mode Transition 2) local to kube without master reachable
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `show feature status {feature-name}`
		- Should show current owner is local
	2. `sudo config feature owner {feature-name} kube`
	3. `show feature config {feature-name}`
		- Should show config owner is kube 
	4. `sudo virsh shutdown <backend master servers 1 and 2>`
	5. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	6. From master: Apply manifest v2 for `{feature-name}` hangs
	7. `show feature status {feature-name}`
		- Should show current owner is local
	8. `docker ps`
		- Should show local container running
	9. `sudo virsh start <backend master servers 1 and 2>`
	10. `ping` HAProxy and 3 backend masters
	    - All should respond
	11. `docker ps`
		- Should observe new k8s container v2 for `{feature-name}`
	12. `show feature status {feature-name}` 
	    - Should show `{feature-name}` owner status is kube and running v2
	13. `kubectl get pods` on master
        - Should observe new pod that corresponds to new container v2

- Mode Transitions 5) kube to local with master reachable
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `sudo config feature owner {feature-name} local`
	6. `show feature config {feature-name}`
		- Should show feature config owner is local
	7. `docker ps`
		- Should show docker container running in local mode, k8s container from step 4 terminated
	8. `show feature status {feature-name}`
		- Should show docker container current owner is local

- Mode Transitions 6) kube to local without master reachable 
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `sudo virsh shutdown <backend master servers 1 and 2>`
	6. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	7. `sudo config feature owner {feature-name} local`
	8. `show feature config {feature-name}`
		- Should show feature config owner is local
	9. `docker ps`
		- Should show docker container running in local mode, k8s container from step 4 terminated
	10. `show feature status {feature-name}`
		- Should show docker container current owner is local
	11. Ensure transient DB is properly populated
	12. `sudo virsh start <backend master servers 1 and 2>`
	13. `ping` HAProxy and 3 backend masters
	    - All should respond
	14. Ensure `{feature-name}_enabled` label is removed


### Test Cases - SONiC Reboot

These test cases ensure that kube and local features behave as expected across a switch reboot. 

- SONiC Reboot 1) kube mode feature, fallback to local, server reachable persistent across reboot
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	6. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Take note of labels present
	7. `sudo reboot`
	8. `docker ps` 
		- Should show `{feature-name}` running in local mode before kubelet service starts
	9. `show feature status {feature-name}`
		- Should show `{feature-name}` as current owner local
	10. After kubelet service starts, `docker ps`
		- Should show `{feature-name}` running in kube mode 
	11. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	12. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Labels present output should be the same as step 6
	

- SONiC Reboot 2) kube mode feature, fallback to local, server unreachable persistent across reboot
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	6. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Take note of labels present
	7. `sudo virsh shutdown <backend master servers 1 and 2>`
	8. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	9. `sudo reboot`
	10. `docker ps` 
		- Should show `{feature-name}` running in local mode before kubelet service starts
	11. `show feature status {feature-name}`
		- Should show `{feature-name}` as current owner local
	12. After kubelet service starts, `docker ps`
		- Should show `{feature-name}` running in local mode 
	13. `show feature status {feature-name}`
		- Should show `{feature-name}` as current owner local
	14. `sudo virsh start <backend master servers 1 and 2>`
	15. `ping` HAProxy and 3 backend master servers
	    - All should respond
	16. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Labels present output should be the same as step 6
	15. `docker ps`
		- Should show `{feature-name}` running in kube mode 
	16. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`

- SONiC Reboot 3) kube mode feature, no fallback to local, server reachable persistent across reboot
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	6. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Take note of labels present
	7. `sudo reboot`
	8. `docker ps` 
		- Should show no `{feature-name}` container running
	9. `show feature status {feature-name}`
		- Should show `{feature-name}` as current owner None
	10. After kubelet service starts, `docker ps`
		- Should show `{feature-name}` running in kube mode 
	11. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	12. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Labels present output should be the same as step 6

- SONiC Reboot 4) kube mode feature, no fallback to local, server unreachable persistent across reboot
	0. Follow steps from Test Case Join SONiC 3 to properly join SONiC DUT
	1. `sudo config feature owner {feature-name} kube`
	2. `show feature config {feature-name}`
	   - Should show `{feature-name}` in kube mode
	3.  Apply manifest v1 for `{feature-name}`
	4. `docker ps`
		- Should show k8s container v1 for `{feature-name}` 
	5. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`
	6. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Take note of labels present
	7. `sudo virsh shutdown <backend master servers 1 and 2>`
	8. `ping` HAProxy and 3 backend master servers
	    - Only HAProxy and one backend master should respond
	9. `sudo reboot`
	10. `docker ps` 
		- Should show no `{feature-name}` container running
	11. `show feature status {feature-name}`
		- Should show `{feature-name}` as current owner None
	12. After kubelet service starts, `docker ps`
		- Should show no `{feature-name}` container running
	13. `sudo virsh start <backend master servers 1 and 2>`
	14. `ping` HAProxy and 3 backend master servers
	    - All should respond
	15. From master: `kubectl get nodes --show-labels | grep <DUT-name> | cut -c54- | tr "," "\n"’`
		- Labels present output should be the same as step 6
	16. After kubelet service starts, `docker ps`
		- Should show `{feature-name}` running in kube mode 
	17. `show feature status {feature-name}`
		- Should observe feature currently in kube mode
		- Should observe `remote_state` set to `Running`


### Test Cases - Miscellaneous

Systemctl start/stop/restart works as today for both local and kube modes

Ensure SONiC DUT additional labels are present (OS_VERSION, etc)

Deployment of new feature not already part of SONiC switch

Warm Reboot

Multi ASiC

