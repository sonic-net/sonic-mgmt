# Example of Testbed Configuration
Here is an example of how to manually get the testbed information when you want to allocate some tests on the DUTs. It includes how to get the testbed IP address, location, and how to find where is the PTF docker from the configuration files.

## Testbed Inventory

- [```ansible/lab```](/ansible/lab): Include all lab DUTs, fanout switches, and testbed server topologies
- [```ansible/veos```](/ansible/veos): all servers and VMs
- [```ansible/testbed.csv```](/ansible/testbed.csv) is the topology configuration file for the testbed (Will be replaced by testbed.yaml).
- [```ansible/testbed.yaml```](/ansible/testbed.yaml) is the topology configuration file for the testbed .
- [```ansible/lab```](/ansible/lab) [```ansible/inventory ```](/ansible/inventory ) are the inventory files for the testbed.

*Note: All the samples come with phony data, the data might not exist in the real world, but the relation amount them are well organized, they are just used for the demo.*


## Testbed example
Say here, we want to use the DUT as the name `vlab-01`, the testbed with the name `vms-kvm-t0`.

*`vlab-01` is set up by following the doc [KVM Testbed Setup](/docs/testbed/README.testbed.VsSetup.md). You can follow it to make it in your local environment.*

Then we can get the related information from [```ansible/vtestbed.csv```](/ansible/vtestbed.csv) or [```ansible/vtestbed.yaml```](/ansible/vtestbed.yaml).

*Notes: For virtual environment, the related files are [```ansible/vtestbed.csv```](/ansible/vtestbed.csv) or [```ansible/vtestbed.yaml```](/ansible/vtestbed.yaml) and [```ansible/veos_vtb```](/ansible/veos_vtb), and for physical environment, they are [```ansible/testbed.csv```](/ansible/testbed.csv) or [```ansible/testbed.yaml```](/ansible/testbed.yaml) and [```ansible/veos```](/ansible/veos).*

### Access the DUT

```
grep 'vlab-01' ./vtestbed.csv                          
vms-kvm-t0,vms6-1,t0,docker-ptf,ptf-01,10.250.0.102/24,fec0::ffff:afa:2/64,server_1,VM0100,[vlab-01],veos_vtb,False,Tests virtual switch vm
```
```
grep 'vlab-01' -A 4 -B 11 ./vtestbed.yaml 

- conf-name: vms-kvm-t0
  group-name: vms6-1
  topo: t0
  ptf_image_name: docker-ptf
  ptf: ptf-01
  ptf_ip: 10.250.0.102/24
  ptf_ipv6: fec0::ffff:afa:2/64
  server: server_1
  vm_base: VM0100
  dut:
    - vlab-01
  inv_name: veos_vtb
  auto_recover: 'False'
  comment: Tests virtual switch vm
```
From the two output above, we can see, the content in that two files are same, the files format are different. 

Here we get the information for `vlab-01`.

Then we can check the inventory file as `inv_name`
```
grep 'vlab-01' -A 2 ./veos_vtb
        vlab-01:
        vlab-02:
        vlab-03:
--
        vlab-01:
          ansible_host: 10.250.0.101
          ansible_hostv6: fec0::ffff:afa:1
```
this is the IP for the DUT.


Then, you can use this IP `10.250.0.101` to access that DUT.

```
ssh admin@10.250.0.101
admin@10.250.0.101's password: 
Linux vlab-01 4.19.0-12-2-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64
You are on
  ____   ___  _   _ _  ____
 / ___| / _ \| \ | (_)/ ___|
 \___ \| | | |  \| | | |
  ___) | |_| | |\  | | |___
 |____/ \___/|_| \_|_|\____|

-- Software for Open Networking in the Cloud --

Unauthorized access and/or use are prohibited.
All-access and/or use are subject to monitoring.

Help:    http://azure.github.io/SONiC/

Last login: Fri Apr 23 08:38:36 2021 from 10.250.0.1
```

### Access PTF
From the above information, besides the DUT info, we also get other information, like PTF location.
```
  ptf_image_name: docker-ptf
  ptf: ptf-01
  ptf_ip: 10.250.0.102/24
  ptf_ipv6: fec0::ffff:afa:2/64
  server: server_1
```
Find out what the PTF server alias is.
```
grep 'server_1' -A 5 ./veos_vtb
        server_1:
    lab:
      hosts:
        vlab-01:
        vlab-02:
        vlab-03:
--
server_1:
  vars:
    host_var_file: host_vars/STR-ACS-VSERV-01.yml
  children:
    vm_host_1:
    vms_1:
```
Here, in `children` section, we get a element `vm_host_1`. Then we can get the host for our PTF instance.
```
grep '^vm_host_1' -A 5 ./veos_vtb 
vm_host_1:
  hosts:
    STR-ACS-VSERV-01:
      ansible_host: 172.17.0.1
      ansible_user: use_own_value
```

Then, there might be a question, we have a host IP address `172.17.0.1`, and a PTF ip address `10.250.0.102`, which one can we use to get accessed to that PTF? ``BOTH!``

Let's check.

Access from IP
```
ssh root@10.250.0.102
root@10.250.0.102's password: 
Last login: Tue Jul 20 09:50:31 2021 from 10.250.0.1
root@8d3f7f4475cd:~# 
```
Access from host
```
docker ps

4af0b31053ae   debian:jessie                                         "bash"                   3 months ago   Up 3 months                                                  net_vms6-1_VM0102
3ac5d5af9cc1   debian:jessie                                         "bash"                   3 months ago   Up 3 months                                                  net_vms6-1_VM0101
8d3f7f4475cd   sonicdev-microsoft.azurecr.io:443/docker-ptf:latest   "/usr/local/bin/supe…"   3 months ago   Up 3 months                                                  ptf_vms6-1
fa3e18a6c4f4   docker-sonic-mgmt-richardyu                           "bash"                   3 months ago   Up 3 months   22/tcp                                         local-sonic-mgmt
```
Then we can see, the docker id is identical `8d3f7f4475cd`.



## References
For this article, some of the reference docs as:

- [```Testbed Topologies```](/docs/testbed/README.testbed.Topology.md): Testbed topologies. 
- [```Testbed Configuration```](/docs/testbed/README.testbed.Config.md): Introduction about Testbed configuration, mainly about the testbed.csv (Will be replaced by testbed.yaml). 
- [```New Testbed Configuration```](/docs/testbed/README.new.testbed.Configuration.md): Introduction about Testbed configuration, mainly about the Testbed.yaml.
- [```KVM Testbed Setup```](/docs/testbed/README.testbed.VsSetup.md)
  