# SONiC Testbed with Keysight IxNetwork as Traffic Generator

This section gives an overview of the stand-alone testbed topology where SONiC DUT is directly connected with Keysight’s protocol emulator and traffic generator (IxNetwork).

## Physical Topology

Based on test need there may be multiple topologies possible as shown below :

- Single DUT Topology
![](img/single-dut-topology.png)


- Multiple DUT Topology
![](img/multiple-dut-topology.png)


- Multiple IxNetwork Topology
![](img/multiple-ixnetwork.PNG)

## Topology Description

### Ixia Chassis (IxNetwork)
Keysight IxNetwork is used as the network tester to emulate protocol sessions eg. OSPF, BGP, LACP etc. and send data traffic with various user defined traffic profiles at line rate. Based on test need this can support line cards of varying speed ranging from 1G to 400G. It also supports vlan separated logical interfaces over each physical port.

### IxNetwork API Server Docker

The IxNetwork API Server docker is installed in the Testbed server along with sonic-mgmt docker. It provides API server, that is used to configure the Traffic Generator (IxNetwork) using restPy APIs. It is capable of offering multiple sessions of IxNetwork API server. Each session runs independent of each other and configures IxNetwork.

### Network connections
- IxNetwork API server is connected to IxNetwork via the management port.
- IxNetwork test ports are directly connected to single or multiple DUTs.

## Deploy IxNetwork API Server

### Download IxNetwork API Server docker image
1. Download IxNetwork Web Edition (Docker deployment) from [ here ](https://ks-aws-prd-itshared-opix.s3-us-west-1.amazonaws.com/IxSoftwareUpgrades/IxNetwork/9.0_Update3/Ixia_IxNetworkWeb_Docker_9.00.100.213.tar.bz2)

2. Copy the tar.bz2 file on the testbed server.

3. Make sure the interface has promiscuous mode enabled
```
 ifconfig ens160  promisc
 ```

3. Decompress the file (it may take a few minutes):
```
tar xvjf <path_to_tar_file>
```
### Run IxNetwork API Server docker

1. Load the image to docker:
```
docker load -i Ixia_IxNetworkWeb_Docker_<version>.tar
```
2. Loaded image : `ixnetworkweb_<version>_image`

3. Create the macvlan bridge to be used by IxNetwork Web Edition:
```
docker network create -d macvlan -o parent=ens160 --subnet=192.168.x.0/24 --gateway=192.168.x.254 <bridge_name>
(NOTE: Use your subnet, prefix length and gateway IP address.)
```

4. Verify bridge got created properly:
```
docker network ls
docker network inspect IxNetVlanMac
```
5. Deploy the IxNetwork Web Edition container using the following command ixnetworkweb_\<version>_image  should be as shown in step 2 above):
```
docker run --net <bridge_name> \
--ip <container ip> \
--hostname <hostname> \
--name <container name> \
--privileged \
--restart=always \
--cap-add=SYS_ADMIN \
--cap-add=SYS_TIME \
--cap-add=NET_ADMIN \
--cap-add=SYS_PTRACE \
-i -d \
-v /sys/fs/cgroup:/sys/fs/cgroup \
-v /var/crash/=/var/crash \
-v /opt/container/one/configs:/root/.local/share/Ixia/sdmStreamManager/common \
-v /opt/container/one/results:/root/.local/share/Ixia/IxNetwork/data/result \
-v /opt/container/one/settings:/root/.local/share/IXIA/IxNetwork.Globals \
--tmpfs /run \
ixnetworkweb_<version>_image

Note : The folders within /opt/container/one/ should to be created with read and write permission prior docker run.

```

6. Launch IxNetworkWeb using browser `https://container ip`
