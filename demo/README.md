# Demo

1. [1. Setup](#1-setup)
2. [2. Configurate DPU](#2-configurate-dpu)
   1. [2.1. Setup mgmt network connection on DPU](#21-setup-mgmt-network-connection-on-dpu)
   2. [2.2. Setup port config on DPU](#22-setup-port-config-on-dpu)
3. [3. Demo setup](#3-demo-setup)

## 1. Setup

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
virsh destroy VM0104
virsh undefine VM0104
```

## 2. Configurate DPU

### 2.1. Setup mgmt network connection on DPU

1. telnet to DPU VM

    ```bash
    telnet 127.0.0.1 7004

    User: admin
    Password: YourPaSsWoRd
    ```

1. Configure mgmt interface

    ```bash
    sudo config interface ip add eth0 10.250.0.55/24
    ```

### 2.2. Setup port config on DPU

1. copy minigraph to DPU

    ```bash
    scp sonic-mgmt/ansible/minigraph/SONIC01DPU.xml admin@10.250.0.55:

    User:admin
    Password: YourPaSsWoRd
    ```

1. load minigraph on DPU

    ```bash
    sudo cp SONIC01DPU.xml /etc/sonic/minigraph.xml
    sudo config load_minigraph -y

    sudo config save -y
    ```

## 3. Demo setup

All demo related scripts are located under `demo` directory:

- `install_scripts.sh`: Script that pushes all demo related contents to all devices. More details are listed below.
  - `demo/npu_script.sh`: Scripts that runs on NPU.
  - `demo/dpu_script.sh`: Scripts that runs on DPU.
  - `demo/ptf_script.sh`: Scripts that runs on PTF.
- `.tmuxinator.yml`: Tmuxinator configuration file that setups the tmux session for demo.
- `push_dpu_image.sh`: Script that pushes the locally build DPU containeres to DPU, such as dash-engine container.
- `debug.sh`: Script that setups the debug environment, such as copying dump files, installing symbol deb packages.

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

    # On DPU pane
    ./init.sh
    ```
