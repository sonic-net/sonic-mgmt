# Description

The goal of a virtual chassis is to simulate a SONiC disaggregated chassis on a Linux server. Currently, we have defined a virtual T2 testbed with Nokia-7250 SKUs in sonic-mgmt framework, named vms-kvm-t2. It uses a minimal topology configuration (topo_t2_2lc_min_ports-masic) that cobtains 3 KVM devices: one supervisor module(hostname: vlab-t2-1-sup1) and two linecard modules(hostname: vlab-t2-1-1, vlab-t2-1-2). The midplane and in-band connectivity among the modules are established through OVS bridges. Each linecard has 2 eBGP peers - 1 over a 2-port LAG and 1 over a single interface port as shown below:

The topology graph is as follows:

          VM0100                                      VM0101
            ||                                          |
  +---------||------------------------------------------|-------------------+
  |         ||                                          |                   |
  |   +----------------------------------------------------------------+    |
  |   |                         Linecard1                              |    |
  |   +----------------------------------------------------------------+    |
  |                                   |                      |              |
  |   +------------+      +--------------------+     +-----------------+    |
  |   | Supervisor |------|  ovs br-T2Midplane |     | ovs br-T2Inband |    |
  |   +------------+      +--------------------+     +-----------------+    |
  |                                   |                      |              |
  |   +----------------------------------------------------------------+    |
  |   |                          Linecard2                             |    |
  |   +----------------------------------------------------------------+    |
  |           ||                                         |                  |
  +-----------||-----------------------------------------|------------------+
              ||                                         |
            VM0102                                     VM0103

# Prerequesites

Before you begin, ensure you have followed the sonic-mgmt virtual testbed documentation: sonic-mgmt/README.testbed.VsSetup.md to setup ansible configuration and get yourself familiar with the sonic-mgmt framework.

For SONiC images, you should use the ones built from sonic-buildimage-msft/202205 branch or sonic-buildimage-msft/202405 branch.

# T2 Virtual Chassis Setup Process (with vSONiC neighbors)

    1. Enter your SONiC management container with this command: `docker exec -it <container_name> /bin/bash`
    2. Navagate to the ansible directory: `cd /data/sonic-mgmt/ansible`
    3. Start a bunch of vSONiC neighbors: `./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -n 8 -k vsonic start-vms server_1 password.txt`
    4. Spin up a t2 testbed using this command: `./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k vsonic add-topo vms-kvm-t2 password.txt`
    5. Deploy the minigraph: ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-t2 veos_vtb password.txt

# Accessing Supervisor and Linecards

You will now have a virtual chassis deployed. Congratulations! You can access your supervisor by SSHing into its management IP: `ssh admin@10.250.0.125`
Similarly, you should be able to access the linecards via their management IPs as well.
The management IPs of all the modules can be found in the inventory file veos_vtb.

# Running tests

A T2 testbed consists of multiple DUTs since there are multiple modules each of which is deemed as a testable device. So, when you run tests on T2 virtual chassis, you generally should not use the `-d` option.

Example test run: (assuming you are using vsonic neighbors)
./run_tests.sh -n vms-kvm-t2 -c bgp/test_bgp_fact.py -f vtestbed.yaml -i ../ansible/veos_vtb -e "--neighbor_type=sonic"
