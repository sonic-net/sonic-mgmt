1. Build and load PTF docker
```bash
git clone https://github.com/Pterosaur/sonic-buildimage.git
cd sonic-buildimage
git checkout ptf_with_teamd
make init
make configure PLATFORM=vs ;#takes about 1 hour or more
make target/docker-ptf.gz

cd target/
docker load -i docker-ptf.gz
```

2. Clone this repo
```bash
git clone https://github.com/Pterosaur/sonic-mgmt.git
cd sonic-mgmt
git checkout test_mellanox_sn2700_d40c8s8
```

3. Prepare environment

Follow this section [Setup host public key in sonic-mgmt docker](https://github.com/Azure/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#setup-host-public-key-in-sonic-mgmt-docker), replace `ansible_user: zegan` to your username

execute the following commands in sonic-mgmt
```bash
cd ansible
sudo ./setup-management-network.sh
cd ..
./setup-container.sh -n sonic-mgmt -d /data
```

execute the following commands in the container, sonic-mgmt
```bash
docker exec -ti sonic-mgmt bash
cp /home/$USER/.ssh/* /var/$USER/.ssh/
```

4. Build testbed
execute the following commands in the container, sonic-mgmt
```bash
# docker exec -ti sonic-mgmt bash
cd /data/sonic-mgmt/ansible/
./testbed-cli.sh -m veos_vtb -n 8 start-vms server_1 password.txt
./testbed-cli.sh -t vtestbed.csv -m veos_vtb add-topo vms-kvm-t0-56 password.txt
./testbed-cli.sh -t vtestbed.csv -m veos_vtb deploy-mg vms-kvm-t0-56 veos_vtb password.txt
```

5. Confige port channel in container ptf
Execute the following commands in the container, ptf_vms6-1
``` bash
docker exec -ti ptf_vms6-1 bash
ip link set dev eth0 down
ip link set dev eth4 down
teamd -r -t PortChannel101 -c '{"device":"PortChannel101","runner":{"active":true,"name":"lacp","min_ports":1},"ports":{"eth0":{},"eth4":{}}}' -g
ip link set dev PortChannel101 up
```

6. Verify port channel success
execute the following commands in the dut, 
``` bash
ssh admin@10.250.0.101 # password is: password
show int portchannel
```
The `PortChannel101 LACP(A)` should be `(UP)`
```
Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
       S - selected, D - deselected, * - not synced
  No.  Team Dev         Protocol     Ports
-----  ---------------  -----------  -------------------------
 0001  PortChannel0001  LACP(A)(Up)  Ethernet24(S)
 0002  PortChannel0002  LACP(A)(Up)  Ethernet28(S)
 0003  PortChannel0003  LACP(A)(Up)  Ethernet32(S)
 0004  PortChannel0004  LACP(A)(Up)  Ethernet36(S)
 0005  PortChannel0005  LACP(A)(Up)  Ethernet88(S)
 0006  PortChannel0006  LACP(A)(Up)  Ethernet92(S)
 0007  PortChannel0007  LACP(A)(Up)  Ethernet96(S)
 0008  PortChannel0008  LACP(A)(Up)  Ethernet100(S)
  101  PortChannel101   LACP(A)(Up)  Ethernet0(S) Ethernet8(S)
```