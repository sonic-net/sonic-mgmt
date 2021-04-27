# cEOS

This document discusses how to use cEOS as DUT neighbor device.

cEOS is the container-based EOS. All the software running inside
the container. Compared with vEOS, cEOS has much smaller memory
footprint.

Follow [instruction](README.testbed.VsSetup.md) to setup cEOS testbed.

In below example, there are four cEOS containers.

```
lgh@jenkins-worker-15:~$ docker ps
CONTAINER ID        IMAGE                                                        COMMAND                  CREATED             STATUS              PORTS               NAMES
fe48c207a51c        ceosimage:4.23.2F-1                                          "/sbin/init systemd.…"   8 days ago          Up 8 days                               ceos_vms6-1_VM0103
52297010e66a        ceosimage:4.23.2F-1                                          "/sbin/init systemd.…"   8 days ago          Up 8 days                               ceos_vms6-1_VM0102
8dd95269b312        ceosimage:4.23.2F-1                                          "/sbin/init systemd.…"   8 days ago          Up 8 days                               ceos_vms6-1_VM0101
3a50dd481bfb        ceosimage:4.23.2F-1                                          "/sbin/init systemd.…"   8 days ago          Up 8 days                               ceos_vms6-1_VM0100
b91b48145def        debian:jessie                                                "bash"                   8 days ago          Up 8 days                               net_vms6-1_VM0103
d1ff26d84249        debian:jessie                                                "bash"                   8 days ago          Up 8 days                               net_vms6-1_VM0102
1489f52b9617        debian:jessie                                                "bash"                   8 days ago          Up 8 days                               net_vms6-1_VM0101
ce1214a008ed        debian:jessie                                                "bash"                   8 days ago          Up 8 days                               net_vms6-1_VM0100
```

## Resource consumption

A cEOS containers consumes around 1G memory.

```
lgh@jenkins-worker-15:~$ docker stats --no-stream
CONTAINER ID        NAME                 CPU %               MEM USAGE / LIMIT     MEM %               NET I/O             BLOCK I/O           PIDS          6
fe48c207a51c        ceos_vms6-1_VM0103   2.04%               970.9MiB / 125.9GiB   0.75%               0B / 0B             365MB / 55.8GB      138
52297010e66a        ceos_vms6-1_VM0102   2.19%               965.4MiB / 125.9GiB   0.75%               0B / 0B             237MB / 55.6GB      139
8dd95269b312        ceos_vms6-1_VM0101   1.93%               980.9MiB / 125.9GiB   0.76%               0B / 0B             300MB / 55.9GB      138
3a50dd481bfb        ceos_vms6-1_VM0100   2.05%               970.2MiB / 125.9GiB   0.75%               0B / 0B             365MB / 56.1GB      138
```

## Network Setup

We first create a base container `net_${testbed_name}_${vm_name}`, inject six ethernet ports into the base container, 
and then start cEOS `ceos_${testbed_name}_${vm_name}` container on top of the base container. The six ethernet ports
are used for
- 1 management port
- 4 front panel ports to DUT
- 1 backplane port to PTF docker

```
         +------------+                      +----+
         |  cEOS  Ma0 +--------- VM0100-m ---+ br |
         |            |                      +----+
         |            |
         |            |                      +--------------+
         |        Et1 +----------VM0100-t0---+  br-VM0100-0 |
         |            |                      +--------------+
         |            |
         |            |                      +--------------+
         |        Et2 +----------VM0100-t1---+  br-VM0100-1 |
         |            |                      +--------------+
         |            |
         |            |                      +--------------+
         |        Et3 +----------VM0100-t2---+  br-VM0100-2 |
         |            |                      +--------------+
         |            |
         |            |                      +--------------+
         |        Et4 +----------VM0100-t3---+  br-VM0100-3 |
         |            |                      +--------------+
         |            |
         |            |                       +--------------+
         |        Et5 +----------VM0100-back--+  br-b-vms6-1 |
         |            |                       +--------------+
         +------------+
```

## Configuration

The `/mnt/flash` in cEOS container is mount to `/data/ceos/ceos_${testbed_name}_${vm_name}` on the host. The `/mnt/flash`
contiains the configuration file and logs.

```
lgh@jenkins-worker-15:~$ ls -l /data/ceos/ceos_vms6-1_VM0100/
total 40
-rw-rw-r--+ 1 root root  924 Mar 31 07:35 AsuFastPktTransmit.log
drwxrwxr-x+ 2 root root 4096 Mar 31 03:31 Fossil
-rw-rw-r--+ 1 root root  568 Mar 31 07:35 SsuRestore.log
-rw-rw-r--+ 1 root root  568 Mar 31 07:35 SsuRestoreLegacy.log
drwxr-xr-x+ 4  897   88 4096 Mar 31 07:35 archive
drwxrwx---+ 3 root root 4096 Mar 18 06:12 debug
drwxrwxr-x+ 2 root root 4096 Mar 18 06:12 fastpkttx.backup
-rw-rw-r--+ 1 root root  180 Mar 31 07:35 kickstart-config
drwxrwxr-x+ 3 root root 4096 Apr  8 09:11 persist
-rw-rwxr--+ 1 root root 1915 Mar 18 06:12 startup-config
```

## Login

There are two ways to get into cEOS container

1. docker exec
```
lgh@jenkins-worker-15:~$ docker exec -it ceos_vms6-1_VM0100 Cli
ARISTA01T1>show int status
Port       Name      Status       Vlan     Duplex Speed  Type            Flags Encapsulation
Et1                  connected    in Po1   full   unconf EbraTestPhyPort                    
Et2                  connected    1        full   unconf EbraTestPhyPort                    
Et3                  connected    1        full   unconf EbraTestPhyPort                    
Et4                  connected    1        full   unconf EbraTestPhyPort                    
Et5        backplane connected    routed   full   unconf EbraTestPhyPort                    
Ma0                  connected    routed   full   10G    10/100/1000                        
Po1                  connected    routed   full   unconf N/A    

ARISTA01T1>
```

2. ssh
```
lgh@jenkins-worker-15:~$ ssh admin@10.250.0.51
Password: 
ARISTA01T1>show int status
Port       Name      Status       Vlan     Duplex Speed  Type            Flags Encapsulation
Et1                  connected    in Po1   full   unconf EbraTestPhyPort                    
Et2                  connected    1        full   unconf EbraTestPhyPort                    
Et3                  connected    1        full   unconf EbraTestPhyPort                    
Et4                  connected    1        full   unconf EbraTestPhyPort                    
Et5        backplane connected    routed   full   unconf EbraTestPhyPort                    
Ma0                  connected    routed   full   10G    10/100/1000                        
Po1                  connected    routed   full   unconf N/A                                

ARISTA01T1>
```

