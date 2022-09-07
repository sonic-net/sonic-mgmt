# PTF-SAIv2 testing guide
## Overview
This article will introduce the detailed processing of entire PTF-SAIv2 testing, including:
* Build PTF-SAIv2 infras leveraged by [sonic-buildimage](https://github.com/sonic-net/sonic-buildimage)
* Setup the testbed by sonic-mgmt
* Setup saiserverv2 docker on DUT (Device under testing)
* Prepare the testing env and start PTF-SAIv2 testing within ptf-sai docker

## Build PTF-SAIv2 infras leveraged by sonic-buildimage
In this part, we will build PTF-SAIv2 infras using sonic-buildimage.

1. Check the sonic image version and commit id: [Check SAI Header Version And SONiC Branch](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/sai_quality/ExampleCheckSonicVersionAndBuildSaiserverDocker.md)
2. Reset the sonic-buildimage with the branch and commit id previous checked
    ```
    rm -rf ./sonic-buildimage
    git clone https://github.com/sonic-net/sonic-buildimage.git
    cd sonic-buildimage

    git checkout <specific branch>
    git reset --hard <specific commit id>
    ```
3. Build PTF-SAIv2 infras
    ```
    # Init env
    make init
    # BLDENV=buster: Current image is buster
    # PLATFORM=<vendor name> Setup platform environment e.g. broadcom
    make BLDENV=buster configure PLATFORM=broadcom

    # SAITHRIFT_V2=y: build the saiserver version 2rd
    # build brcm saiserverv2 docker
    make BLDENV=buster SAITHRIFT_V2=y -f Makefile.work target/docker-saiserverv2-brcm.gz

    # build ptf-sai docker
    # Clean environment
    make reset

    # Setup platform environment e.g. virtul switch
    make BLDENV=buster configure PLATFORM=vs

    make BLDENV=buster SAITHRIFT_V2=y -f Makefile.work target/docker-ptf-sai.gz
    ```

## Setup the testbed by sonic-mgmt

In this section, we will setup the physical switch testbed.
1. Install the sonic image in the DUT, as for how to install a sonic image on supported switch, please refer to this doc [Install sonic eos image](https://github.com/sonic-net/SONiC/wiki/Quick-Start#install-sonic-eos-image)
2. Remove the topology for the current Testbed
3. Deploy the non-topology
4. Push the mini-graph to DUT

For the detailed command of step 2-4, please check [Deploy SAI Test Topology With SONiC-MGMT](https://github.com/sonic-net/sonic-mgmt/tree/master/docs/testbed/sai_quality)

For the setup of ptf-sai docker, you can refer to this section [Setup Docker Registry for docker-ptf](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Setup.md#setup-docker-registry-for-docker-ptf), please replace the `docker-ptf` with `docker-ptf-sai`

## Prepare the saiserverv2 docker on DUT (Device under testing)
In this section, we will introduce how to setup the saiserverv2 docker in DUT.
1. Stop all the other services besides `database`, which might impact PTF-SAIv2 testing. (Recommanded)

   You may activate some services acording to your scenario, but please be sure to stop `swss` and `syncd`.
    ```shell
    services=("swss" "syncd" "radv" "lldp" "dhcp_relay" "teamd" "bgp" "pmon" "telemetry" "acms" "snmp")
    stop_service(){
        for serv in ${services[*]}; do
            echo "stop service: [$serv]."
            sudo systemctl stop $serv
        done
    }
    stop_service
    ```
3. Upload the saiserverv2 docker you built from previous section to your DUT or Pull saiserverv2 docker image from registry, as for the detailed setup of docker registry, please refer to [Example: Start SaiServer Docker In DUT](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/sai_quality/ExampleStartSaiServerDockerInDUT.md)

4. Start your saiserver binary from saiserverv2 docker, as for detailed information, please refer to this section [Prepare testing environment on DUT](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/sai_quality/SAI.Example.md#prepare-testing-environment-on-dut):

After successfully starting the saiserver binary, we can get those output from shell:
```
admin@s6000:~$ usr/sbin/saiserver -p /etc/sai.d/sai.profile -f /usr/share/sonic/hwsku/port_config.ini

profile map file: /usr/share/sonic/hwsku/sai.profile

port map file: /usr/share/sonic/hwsku/port_config.ini

insert: SAI_INIT_CONFIG_FILE:/usr/share/sonic/hwsku/td2-s6000-32x40G.config.bcm

insert: SAI_NUM_ECMP_MEMBERS:32

Starting SAI RPC server on port 9092
```

## Prepare the testing env and start PTF-SAIv2 testing within ptf-sai docker
In the last section, we will setup our testing environment and run a sanity test on PTF side.

1. Login to the ptf-sai docker, you can find the ip address of docker which is connected to the DUT in [testbed.yaml](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/testbed.yaml).
2. Install the sai python header `python-saithriftv2_0.9.4_amd64.deb` into ptf-sai docker.
    ```
    # install the deb package into ptf-sai docker
    dpkg -i python-saithriftv2_0.9.4_amd64.deb
    ```
3. Make sure Github is accessible on ptf-sai docker and download the SAI repo which contains PTF-SAIv2 test cases
    ```
    rm -rf ./SAI
    git clone https://github.com/opencomputeproject/SAI.git
    cd SAI
    git checkout v1.9
    ```

4. Start PTF-SAIv2 testing within ptf-sai docker

   Note: Prepare a port_map_file named [default_interface_to_front_map.ini](https://github.com/opencomputeproject/SAI/blob/master/test/saithrift/src/msn_2700/default_interface_to_front_map.ini) in advance
    ```shell
    # set the platform name
    export PLATFORM=<vendor name>

    # run a sanitytest
    ptf --test-dir ptf saisanity.L2SanityTest --interface '<used port number and dataplane interface>' -t "thrift_server='<DUT ip address>';port_map_file='default_interface_to_front_map.ini'"

    # use a broadcom switch with 32-port as exmaple
   export PLATFORM=brcm
   ptf --test-dir /tmp/SAI/ptf saisanity.L2SanityTest --interface '0-0@eth0' --interface '0-1@eth1' --interface '0-2@eth2' --interface '0-3@eth3' --interface '0-4@eth4' --interface '0-5@eth5' --interface '0-6@eth6' --interface '0-7@eth7' --interface '0-8@eth8' --interface '0-9@eth9' --interface '0-10@eth10' --interface '0-11@eth11' --interface '0-12@eth12' --interface '0-13@eth13' --interface '0-14@eth14' --interface '0-15@eth15' --interface '0-16@eth16' --interface '0-17@eth17' --interface '0-18@eth18' --interface '0-19@eth19' --interface '0-20@eth20' --interface '0-21@eth21' --interface '0-22@eth22' --interface '0-23@eth23' --interface '0-24@eth24' --interface '0-25@eth25' --interface '0-26@eth26' --interface '0-27@eth27' --interface '0-28@eth28' --interface '0-29@eth29' --interface '0-30@eth30' --interface '0-31@eth31' "--test-params=thrift_server='<DUT ip address>'"
    ```
Finally, we can see the result as shown below:

```
Using packet manipulation module: ptf.packet_scapy

saisanity.L2SanityTest ... Waiting for switch to get ready, 5 seconds ...

...

Check port31 forwarding...

ok

----------------------------------------------------------------------

Ran 1 test in 21.184s


OK
```

## Reference

* [SAI Testing Example](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/sai_quality/SAI.Example.md)