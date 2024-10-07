# Demo

1. [1. Setup](#1-setup)
2. [2. (Optional) Upgrade DPU image to latest build](#2-optional-upgrade-dpu-image-to-latest-build)
3. [3. Demo setup](#3-demo-setup)

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

## 2. (Optional) Upgrade DPU image to latest build

1. Push DPU image to DPU VM

    ```bash
    ./push_dpu_image.sh
    ```

1. telnet to DPU VM

    ```bash
    telnet 127.0.0.1 7004

    User: admin
    Password: YourPaSsWoRd
    ```

1. Upgrade DPU image

    ```bash
    sudo sonic-installer install -y sonic-vs.bin
    ```

## 3. Demo setup

All demo related scripts are located under `demo` directory:

- `install_scripts.sh`: Script that pushes all demo related contents to all devices. More details are listed below.
  - `demo/npu_script.sh`: Scripts that runs on NPU.
  - `demo/dpu_script.sh`: Scripts that runs on DPU.
  - `demo/ptf_script.sh`: Scripts that runs on PTF.
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
    cd demo
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
