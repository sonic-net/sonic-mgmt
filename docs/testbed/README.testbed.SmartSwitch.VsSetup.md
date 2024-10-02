1. Follow [instructions](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#option-2-ceos-container-based-image-recommended) to download cEOS image, this image will be used for T2 and T0 neighbors.

1. Follow [instructions](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#download-the-sonic-vs-image) to download sonic-vs images.

    In our case, images are probably built locally, make sure:

    * Your NPU image should be named as "sonic-vs.img" and be put under `~/sonic-vm/images`.
    * Your DPU image should be name as "sonic-vs.img" too and be put under `~/veos-vm/images`.

1. If you haven't, follow instructions below to setup your sonic-mgmt docker.
    * [Setup sonic-mgmt docker](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#setup-sonic-mgmt-docker)

    * [Setup host public key in sonic-mgmt docker](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#setup-host-public-key-in-sonic-mgmt-docker)

1. Fetch my branch from [sonic-mgmt PR#14595](https://github.com/sonic-net/sonic-mgmt/pull/14595).

1. Deploy the topology.
    ```
    cd /data/sonic-mgmt/ansible
    ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos add-topo vms-kvm-t1-smartswitch password.txt
    ```

1. Deploy minigraph.

    ```
    ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb gen-mg vms-kvm-t1-smartswitch veos_vtb password.txt
    ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-t1-smartswitch veos_vtb password.txt
    ```

1. Configure DPU.

    * telnet to DPU VM
        ```
        telnet 127.0.0.1 7004

        User: admin
        Password: YourPaSsWoRd
        ```
    * Configure mgmt interface
        ```
        sudo config interface ip add eth0 10.250.0.55/24
        ```

    * copy minigraph to DPU
        ```
        scp sonic-mgmt/ansible/minigraph/SONIC01DPU.xml admin@10.250.0.55:

        User:admin
        Password: password
        ```

    * load minigraph on DPU
        ```
        sudo cp SONIC01DPU.xml /etc/sonic/minigraph.xml
        sudo config load_minigraph -y
        ```

    * config default route to NPU
        ```
        sudo ip route add default via 10.0.0.36 dev Ethernet0
        ```
