# pdu_controller fixture user guide

PSU controller is usually a PDU device which can supply power to PSUs of SONiC switch. The PDU devices usually provide management interface like SNMP, web GUI, telnet, SSH, etc.

This plugin defined a fixture named pdu_controller. It returns a python object implements the interface of PsuControllerBase defined in controller_base.py.

## Add PDU information in inventory file

To get a pdu_controller object using the pdu_controller fixture, PDU host information must be known.

PDU information of each DUT device need to be added to the inventory file. The minimum required information information of PDU host is:
* IP address of the PDU host
* Management protocol supported by the PDU host

Possibly other information like authentication username and password are required as well.

### 1. Add `pdu_host` variable to DUT host in inventory file

In the inventory file, we can add the 'pdu_host' variable to DUT host:

```
[sonic_latest]
switch1  ansible_host=10.0.0.100  sonic_version=v2  sonic_hwsku=Force10-S6000 pdu_host=pdu-1
```

In the above example, `pdu_host` variable is added to DUT host `switch1`.

### 2. Add `ansible_host` and `protocol` to the pdu host under `[pdu]` group in inventory file

Then, in the inventory file, we can add a group `[pdu]`. Under the group, we can add the pdu host and its basic information in variables `ansible_host` and `protocol`.

```
[pdu]
pdu-1 ansible_host=192.168.99.2 protocol=snmp
```

If 'protocol' variable is missed, it will take default value "snmp" in code.

### 3. Extend PDU host configuration

If we need to add more PDU configuration information, we can simply add more variables to the corresponding PDU host in the inventory file.

## Example inventory file with PDU host information

```
[sonic_latest]
switch1  ansible_host=10.0.0.100  sonic_version=v2  sonic_hwsku=Force10-S6000 pdu_host=pdu-1
switch2  ansible_host=10.0.0.101  sonic_version=v2  sonic_hwsku=ACS-MSN2700 pdu_host=pdu-1
switch3  ansible_host=10.0.0.102  sonic_version=v2  sonic_hwsku=Force10-S6000   # LAG topo: 8 LAGs x 2 members/lag to spines; 16 ports to Tors
switch4  ansible_host=10.0.0.103  sonic_version=v2  sonic_hwsku=AS7512 sonic_portsku=32x40 pdu_host=pdu-2
switch5  ansible_host=10.0.0.104  sonic_version=v2  sonic_hwsku=ACS-MSN2700 # LAG topo: 8 LAGs x 2 members/lag to spines; 16 ports to Tors

[sonic:children]
sonic_latest

[leaf_topo_1]
switch1
switch5

[ptf]
ptf-1 ansible_host=10.0.0.200 ansible_ssh_user=root ansible_ssh_pass=password

[pdu]
pdu-1 ansible_host=192.168.9.2 protocol=snmp
pdu-2 ansible_host=192.168.9.3
```
