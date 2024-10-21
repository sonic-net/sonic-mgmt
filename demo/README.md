# Demo

1. [1. Setup](#1-setup)
2. [2. Initial config on DPU](#2-initial-config-on-dpu)
   1. [2. Setup mgmt network connection on DPU](#2-setup-mgmt-network-connection-on-dpu)
   2. [2. (Optional) Upgrade DPU image to latest build](#2-optional-upgrade-dpu-image-to-latest-build)
3. [3. Demo setup](#3-demo-setup)
4. [4. Send sample traffic from PTF container](#4-send-sample-traffic-from-ptf-container)

## 1. Setup

First, please make sure the VM images are placed in the right location:

- Your NPU image should be named as "sonic-vs.img" and be put under `~/sonic-vm/images`.
- Your DPU image should be named as "sonic-vs.img" too and be put under `~/veos-vm/images`.

To setup the topology, run the following commands in mgmt container the steps below:

```bash
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos add-topo vms-kvm-t1-smartswitch password.txt
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb gen-mg vms-kvm-t1-smartswitch veos_vtb password.txt
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-t1-smartswitch veos_vtb password.txt
```

To remove the topology, run the following commands in mgmt container:

```bash
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos remove-topo vms-kvm-t1-smartswitch password.txt
```

Run the following commands **outside the mgmt container**:

```bash
virsh destroy VM0104
virsh undefine VM0104
rm -f ~/veos-vm/disks/vsonic_VM0104.img
```

More details can be found in [the SmartSwitch VS setup doc](../docs/testbed/README.testbed.SmartSwitch.VsSetup.md).

## 2. Initial config on DPU

### 2. Setup mgmt network connection on DPU

1. telnet to DPU VM

    ```bash
    telnet 127.0.0.1 7004

    User: admin
    Password: YourPaSsWoRd
    ```

1. Setup ether interface

    ```bash
    sudo config interface ip add eth0 10.250.0.55/24
    sudo ifconfig eth1 10.0.0.37/31 up && sudo ifconfig eth2 10.0.0.39/31 up
    sudo config save -y
    ```

### 2. (Optional) Upgrade DPU image to latest build

1. Push DPU image to DPU VM

    ```bash
    ./push_dpu_image.sh
    ```

1. Install DPU image

    ```bash
    sudo sonic-installer install -y sonic-vs.bin
    sudo reboot now
    ```

## 3. Demo setup

All demo related scripts are located under `demo` directory:

- `install_scripts.sh`: Script that pushes all demo related contents to all devices. More details are listed below.
  - `demo/npu_scripts`: Scripts that runs on NPU.
  - `demo/dpu_scripts`: Scripts that runs on DPU.
  - `demo/ptf_scripts`: Scripts that runs on PTF.
- `.tmuxinator.yml`: Tmuxinator configuration file that setups the tmux session for demo.
- `push_dpu_image.sh`: Script that pushes the locally build DPU VS image to DPU.
- `push_dpu_container.sh`: Script that pushes the locally build DPU containeres to DPU, such as dash-engine container.
- `debug_dpu.sh`: Script that setups the debug environment, such as copying dump files, installing symbol deb packages.

To setup the demo environment, follow the steps below:

1. Push all demo related scripts to all devices:

    ```bash
    ./install_scripts.sh
    ```

1. Setup the tmux session:

    ```bash
    # Under demo folder
    tmuxinator start
    ```

1. The tmux session will create panes to NPU, DPU, PTF, mgmt and so on. Then we can start to use it to init each device.

    ```bash
    # On NPU pane
    ./init.sh

    # On DPU pane:
    # 1. Setup minigraph
    sudo cp SONIC01DPU.xml /etc/sonic/minigraph.xml
    sudo config load_minigraph -y
    sudo config save -y

    # 2. Initialize SONiC VM with BMv2 data plane enabled
    ./init.sh
    ```

## 4. Send sample traffic from PTF container

After all setup completes, we can start to send sample traffic from PTF container.

In PTF container, we have a few scripts that sends different traffic:

- `underlay_ping.py`: Sends ICMP packets using underlay network directly. There is no VNET VxLAN encapsulation.
- `vnet_tcp_connect.py`: Sends TCP packets using VNET VxLAN encapsulation.

If the scripts run successfully, you should see the following output, which starts with the detailed packet format, then sends 1 packet every second:

```text
root@1e49d3082bc0:~# python underlay_ping.py
WARNING: No route found for IPv6 destination :: (no default route?)
###[ Ethernet ]###
  dst       = 22:48:23:27:33:d8
  src       = 9a:50:c1:b1:9f:00
  type      = 0x800
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     =
     frag      = 0
     ttl       = 64
     proto     = icmp
     chksum    = None
     src       = 10.0.0.1
     dst       = 10.0.0.37
     \options   \
###[ ICMP ]###
        type      = echo-request
        code      = 0
        chksum    = None
        id        = 0x0
        seq       = 0x0
###[ Raw ]###
           load      = ''
###[ Raw ]###
              load      = '000000000000000000'
.
Sent 1 packets.
.
Sent 1 packets.
.
```
