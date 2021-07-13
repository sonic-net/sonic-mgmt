# Example of Testbed Configuration
Here is an example of how to manually get the testbed information when you want to allocate some tests on the DUTs. It includes how to get the testbed IP address, location, and how to find where is the PTF docker from the configuration files.

## Testbed Inventory

- [```ansible/lab```](/ansible/lab): Include all lab DUTs, fanout switches, and testbed server topologies
- [```ansible/veos```](/ansible/veos): all servers and VMs
- [```ansible/testbed.csv```](/ansible/testbed.csv) is the topology configuration file for the testbed (Will be replaced by testbed.yaml).
- [```ansible/testbed.yaml```](/ansible/testbed.yaml) is the topology configuration file for the testbed .
- [```ansible/lab```](/ansible/lab) [```ansible/inventory ```](/ansible/inventory ) are the inventory files for the testbed.

*Note:All the samples come with phony data, the data might not exist in the real world, but the relation amount them are well organized, they are just used for the demo.*

## Testbed example
Say here, we want to use the DUT as the name `vms-s6000-t0-mock`, the testbed with the name `vms-s6000-t0-mock`.
Then we can get the related information from [```ansible/testbed.csv```](/ansible/testbed.csv) or [```ansible/testbed.yaml```](/ansible/testbed.yaml).

### Access the DUT

```
grep 'vms-s6000-t0-mock' ./testbed.csv

vms-s6000-t0-mock,vms2-1,t0,docker-ptf,vms2-1,1.2.4.17/23,,server_1,VM0100,vms-s6000-t0-mock,lab,True,****
```
```
grep 'vms-s6000-t0-mock' -A 2 -B 11 ./testbed.yaml

- conf-name: vms-s6000-t0-mock
  group-name: vms2-1
  topo: t0
  ptf_image_name: docker-ptf
  ptf: vms2-1
  ptf_ip: 1.2.4.17/23
  ptf_ipv6:
  server: server_1
  vm_base: VM0100
  dut:
    - vms-s6000-t0-mock
  inv_name:lab
  auto_recover: 'True'
```
From the two output above, we can see, the content in that two files are same, the files format are different. 

Here we get the information for `vms-s6000-t0-mock`.

Then we can check the inventory file as `inv_name`
```
grep 'vms-s6000-t0-mock' -A 2 ./lab
    vms-s6000-t0-mock:
      ansible_host: 1.2.5.252
      model: 07VJDK
```
this is the IP for the DUT.


Then, you can use this ip `1.2.5.252` to access that DUT.

```
Linux vms-s6000-t0-mock 4.9.0-14-2-amd64 #1 SMP Debian 4.9.246-2 (2020-12-17) x86_64
You are on
  ____   ___  _   _ _  ____
 / ___| / _ \| \ | (_)/ ___|
 \___ \| | | |  \| | | |
  ___) | |_| | |\  | | |___
 |____/ \___/|_| \_|_|\____|

-- Software for Open Networking in the Cloud --
```

### Access PTF
From above information, besides the DUT info, we also get other information, like PTF location.
```
  ptf_image_name: docker-ptf
  ptf: vms2-1
  ptf_ip: 1.2.4.17/23
  ptf_ipv6:
  server: server_1
```
Find out what the PTF server alias.
```
grep 'server_1' -A 5 ./veos
        server_1:
        server_16:
        server_17:
        server_18:
        server_20:
        server_21:
--
server_1:
  vars:
    host_var_file: host_vars/MOCK-ACS-SERV-1.yml
  children:
    mock_vm_host_13:
    vms_13:
```
Then we can get the host for our PTF instance.
```
grep 'mock_vm_host_13' -A 5 ./veos         
        mock_vm_host_13:
        vm_host_16:
        vm_host_17:
        vm_host_18:
        vm_host_20:
        vm_host_21:
--
mock_vm_host_13:
  hosts:
    MOCK-ACS-SERV-1:
      ansible_host: 1.2.3.246
```

Then, there might be a question, we have a host IP address `1.2.3.246`, and a PTF ip address `1.2.4.17`, which one can we use to get accessed to that PTF? ``BOTH!``

Let's check.

Access from IP
```
ssh root@1.2.4.17
root@1.2.4.17's password: 
Last login: Fri Jul  2 15:39:13 2021 from 1.2.3.30
root@6794c6ae5f9b:~# 
```
Access from host
```
mock-acs-serv-1:~$ docker ps
CONTAINER ID        IMAGE                                                COMMAND                  CREATED             STATUS              PORTS               NAMES
6794c6ae5f9b        acs-repo.corp.mock.com:5000/docker-ptf:latest   "/usr/local/bin/supe…"   10 days ago         Up 10 days                              ptf_vms2-1
93bd106d8ea8        acs-repo.corp.mock.com:5000/docker-ptf:latest   "/usr/local/bin/supe…"   3 months ago        Up 3 months                             ptf_v13-51
184de617cbef        acs-repo.corp.mock.com:5000/docker-ptf:latest   "/usr/local/bin/supe…"   3 months ago        Up 3 months                             ptf_vms13-4
5eef56eda0e5        acs-repo.corp.mock.com:5000/docker-ptf:latest   "/usr/local/bin/supe…"   3 months ago        Up 3 months                             ptf_vms13-5
azure@mock-acs-serv-1:~$ docker exec -it ptf_vms2-1 bash
root@6794c6ae5f9b:/# 
```
Then we can see, the docker id is identical `6794c6ae5f9b`.



## References
For this article, some of the reference docs as:

- [```Testbed Topologies```](/docs/testbed/README.testbed.Topology.md): Testbed topologies. 
- [```Testbed Configuration```](/docs/testbed/README.testbed.Config.md): Introduction about Testbed configuration, mainly about the testbed.csv (Will be replaced by testbed.yaml). 
- [```New Testbed Configuration```](/docs/testbed/README.new.testbed.Configuration.md): Introduction about Testbed configuration, mainly about the Testbed.yaml.
  