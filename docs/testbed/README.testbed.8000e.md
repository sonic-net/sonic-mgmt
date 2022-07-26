# 8000e

This document discusses how to use 8000e as DUT virtual device.
8000e is a custom kvm based functional emulator of Cisco 8000 Series routers. The 8000e emulator is running inside a docker container for ease of deployment.


## Installing 8000e sonic image
Cisco customers can contact account team for 8000e image access.


Download and unpack 8000e sonic tar files
```
tar -xvf 8000-emulator-<REL>.tar
tar -xvf 8000-sonic-<REL>.tar
```

Move downloaded sonic image to 8000e sonic image directory
```
mkdir -p $HOME/8000e/images
cd 8000-<REL>
mv packages/images/8000/sonic/sonic-cisco-8000.bin $HOME/8000e/images/
```

Build 8000e-sonic docker image
```
scripts/build_docker_image.sh 8000e-sonic docker/sonic/Dockerfile
```

Verify that 8000e-sonic docker image is available
```
docker images |grep 8000e-sonic
8000e-sonic    latest   f5f181cf2a51    27 minutes ago   6.58GB
```

Follow [instructions](README.testbed.VsSetup.md) to setup virtual sonic testbed. 


## Bring up 8000e T0 topology 

Start neighboring devices

Note: while vEOS or cEOS can be used as neighboring devices, we used vsonic as neighboring devices in our example.
```
./testbed-cli.sh -m veos_vtb -n 4 -k vsonic start-vms server_1 password.txt
```

Deploy 8000e T0 topology
```
./testbed-cli.sh -k vsonic -t vtestbed.yaml -m veos_vtb add-topo 8000e-t0 password.txt
```

Deploy minigraph on the DUT
```
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg 8000e-t0 veos_vtb password.txt
```

Run a simple bgp test
```
cd ../tests
./run_tests.sh -n 8000e-t0 -d vlab-8k-01 -c bgp/test_bgp_fact.py -f vtestbed.yaml -i veos_vtb -e --disable_loganalyzer

bgp/test_bgp_fact.py::test_bgp_facts[vlab-8k-01-None] PASSED
```


