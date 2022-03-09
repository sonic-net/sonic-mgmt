## Introduction

This documention is proof of concept for testing multidut scenarios. It comprises of the contents of the ansible files used for the tgen port to multidut connection and the pytest command that is used to execute a testcase.

## Topology

The topology consists of 2 DUTs ( Arista and Edgecore ) and an Ixia chassis. Ports 1 to 4 of card 6 is connected to first 4 ports of 
DUT1(Arista-7060CX-32S-C32). Ports 1 to 4 of card 9 is connected to last 4 ports of DUT2 (Accton-AS7726-32X). Ports 


Chassis IP: 10.36.78.53

DUT1: 10.36.78.144

DUT2: 10.36.79.215

API Server : 10.36.83.101

TgenPorts (Card6/Ports1-4) ----- (Ethernet 0-12) DUT1 ----- DUT2 (Ethernet112-124) ----- (Card9/Ports1-4)TgenPorts

## ansible/files/snappi_sonic_connection_graph.xml

The port connection info between the tgen ports and the duts are mentioned below in the snappi_sonic_connection_graph.xml as follows:
Hostname sonic-s6100-dut1 is referenced for DUT1 and sonic-s6100-dut2 is referenced for DUT2.

Note: The inter-connection details between the DUTS are not included here
Please state if we have to mention the details.

```
<LabConnectionGraph>
  <PhysicalNetworkGraphDeclaration>
    <Devices>
      <Device Hostname="snappi-sonic" HwSku="IXIA-tester" Type="DevIxiaChassis"/>
      <Device Hostname="sonic-s6100-dut1" HwSku="Arista-7060CX-32S-C32" Type="DevSonic"/>
      <Device Hostname="sonic-s6100-dut2" HwSku="Accton-AS7726-32X" Type="DevSonic"/>
      <Device Hostname="snappi-sonic-api-serv" HwSku="IXIA-tester" Type="DevIxiaApiServ"/>
    </Devices>
    <DeviceInterfaceLinks>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card6/Port1" StartDevice="sonic-s6100-dut1" StartPort="Ethernet0"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card6/Port2" StartDevice="sonic-s6100-dut1" StartPort="Ethernet4"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card6/Port3" StartDevice="sonic-s6100-dut1" StartPort="Ethernet8"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card6/Port4" StartDevice="sonic-s6100-dut1" StartPort="Ethernet12"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card9/Port1" StartDevice="sonic-s6100-dut2" StartPort="Ethernet112"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card9/Port2" StartDevice="sonic-s6100-dut2" StartPort="Ethernet116"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card9/Port3" StartDevice="sonic-s6100-dut2" StartPort="Ethernet120"/>
      <DeviceInterfaceLink BandWidth="100000" EndDevice="snappi-sonic" EndPort="Card9/Port4" StartDevice="sonic-s6100-dut2" StartPort="Ethernet124"/>
    </DeviceInterfaceLinks>
  </PhysicalNetworkGraphDeclaration>
  <DataPlaneGraph>
    <DevicesL3Info Hostname="snappi-sonic">
      <ManagementIPInterface Name="ManagementIp" Prefix="10.36.78.53/32"/>
    </DevicesL3Info>
    <DevicesL2Info Hostname="snappi-sonic">
      <InterfaceVlan mode="Access" portname="Card9/Port1" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card9/Port2" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card9/Port3" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card9/Port4" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card6/Port1" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card6/Port2" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card6/Port3" vlanids="2"/>
      <InterfaceVlan mode="Access" portname="Card6/Port4" vlanids="2"/>
    </DevicesL2Info>
  </DataPlaneGraph>
</LabConnectionGraph>
```

## ansible/files/snappi_sonic_devices.csv

The snappi_sonic_devices.csv containes the information of the setups.

```
Hostname,ManagementIp,HwSku,Type
snappi-sonic,10.36.78.53/32,SNAPPI-tester,DevSnappiChassis
sonic-s6100-dut1,10.36.78.144/32,Arista-7060CX-32S-C32,DevSonic
sonic-s6100-dut2,10.36.79.215/32,Accton-AS7726-32X,DevSonic
snappi-sonic-api-serv,10.36.83.101/32,SNAPPI-tester,DevSnappiApiServ
```

## ansible/files/snappi_sonic_link.csv

snappi_sonic_link.csv comprises of the details for speed of the links used between the tgen and the duts.

```
StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode
sonic-s6100-dut1,Ethernet0,snappi-sonic,Card6/Port1,100000,2,Access
sonic-s6100-dut1,Ethernet4,snappi-sonic,Card6/Port2,100000,2,Access
sonic-s6100-dut1,Ethernet8,snappi-sonic,Card6/Port3,100000,2,Access
sonic-s6100-dut1,Ethernet12,snappi-sonic,Card6/Port4,100000,2,Access
sonic-s6100-dut2,Ethernet112,snappi-sonic,Card9/Port1,100000,2,Access
sonic-s6100-dut2,Ethernet116,snappi-sonic,Card9/Port2,100000,2,Access
sonic-s6100-dut2,Ethernet120,snappi-sonic,Card9/Port3,100000,2,Access
sonic-s6100-dut2,Ethernet124,snappi-sonic,Card9/Port4,100000,2,Access
```
## ansible/snappi_sonic
```
[sonic_dell64_40]
sonic-s6100-dut1    ansible_host=10.36.78.144
sonic-s6100-dut2    ansible_host=10.36.79.215

[sonic_dell64_40:vars]
hwsku="Force10-S6100"
iface_speed='40000'

[Server_6]
snappi-sonic          ansible_host=10.36.78.53   os=snappi

[sonic:children]
sonic_dell64_40

[sonic:vars]
mgmt_subnet_mask_length='23'

[snappi-sonic:children]
sonic
snappi_chassis

[ptf]
snappi-sonic-ptf     ansible_host='10.36.83.101'
```
## ansible/testbed.csv

The dut information is passed in the form of a list [sonic-s6100-dut1;sonic-s6100-dut2] at the last line.

```
# conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,ptf_ipv6,server,vm_base,dut,inv_name,auto_recover,comment
ptf1-m,ptf1,ptf32,docker-ptf,ptf-unknown,10.255.0.188/24,,server_1,,str-msn2700-01,lab,False,Test ptf Mellanox
ptf2-b,ptf2,ptf64,docker-ptf,ptf-unknown,10.255.0.189/24,,server_1,,lab-s6100-01,lab,False,Test ptf Broadcom
vms-sn2700-t1,vms1-1,t1,docker-ptf,ptf-unknown,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests Mellanox SN2700 vms
vms-sn2700-t1-lag,vms1-1,t1-lag,docker-ptf,ptf-unknown,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests Mellanox SN2700 vms
vms-sn2700-t0,vms1-1,t0,docker-ptf,ptf-unknown,10.255.0.178/24,,server_1,VM0100,str-msn2700-01,lab,True,Tests Mellanox SN2700 vms
vms-s6000-t0,vms2-1,t0,docker-ptf,ptf-unknown,10.255.0.179/24,,server_1,VM0100,lab-s6000-01,lab,True,Tests Dell S6000 vms
vms-a7260-t0,vms3-1,t0-116,docker-ptf,ptf-unknown,10.255.0.180/24,,server_1,VM0100,lab-a7260-01,lab,True,Tests Arista A7260 vms
vms-s6100-t0,vms4-1,t0-64,docker-ptf,ptf-unknown,10.255.0.181/24,,server_1,VM0100,lab-s6100-01,lab,True,Tests Dell S6100 vms
vms-s6100-t1,vms4-1,t1-64,docker-ptf,ptf-unknown,10.255.0.182/24,,server_1,VM0100,lab-s6100-01,lab,True,Tests Dell S6100 vms
vms-s6100-t1-lag,vms5-1,t1-64-lag,docker-ptf,ptf-unknown,10.255.0.183/24,,server_1,VM0100,lab-s6100-01,lab,True,ests Dell S6100 vms
vms-multi-dut,vms1-duts,ptf64,docker-ptf,ptf-unknown,10.255.0.184/24,,server_1,VM0100,[dut-host1;dut-host2],lab,True,Example Multi DUTs testbed
vms-example-ixia-1,vms6-1,t0-64,docker-ptf-ixia,example-ixia-ptf-1,10.0.0.30/32,,server_6,VM0600,example-s6100-dut-1,lab,True,superman
ixanvl-vs-conf,anvl,ptf32,docker-ptf-anvl,ptf-unknown,10.250.0.100/24,,server_1,,vlab-01,lab,True,Test ptf ANVL SONIC VM
vms-snappi-sonic,vms6-1,ptf64,docker-ptf-snappi,snappi-sonic-ptf,10.36.83.101,,Server_6,,[sonic-s6100-dut1;sonic-s6100-dut2],lab,True,Batman
```
## ansible/testbed.yaml

sonic-s6100-dut1 and sonic-s6100-dut2 are passed as values for dut key

```
- conf-name: vms-snappi-sonic
  group-name: vms6-1
  topo: ptf64
  ptf_image_name: docker-ptf-snappi
  ptf: snappi-sonic-ptf
  ptf_ip: 10.36.83.101
  ptf_ipv6:
  server: Server_6
  vm_base:
  dut:
    - sonic-s6100-dut1
    - sonic-s6100-dut2
  inv_name: lab
  auto_recover: 'True'
  comment: Batman
```

## Pytest command to run a testcase
 
In pytest command for testcase execution we have passed the --host-pattern as "all" instead of the dut hostname.

```
py.test --inventory ../ansible/snappi-sonic --host-pattern all --testbed vms-snappi-sonic --testbed_file ../ansible/testbed.csv --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer <script name>
```