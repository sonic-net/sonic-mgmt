# Automatically recover unhealthy testbed via console

## Background
The success rate of nightly test depends on the health of the testbeds.
In the past, we used pipelines to re-deploy testbeds when they had problems. This could fix some issues like configuration loss, but it was not enough.
Sometimes, the pipeline failed to restore the testbeds, and we had to do it manually. This was time-consuming and inefficient.
Therefore, we need a better way to automatically recover unhealthy testbeds, which can handle more situations and respond faster.

## Design
Our script is designed to recover devices that lose their management ip and cannot be accessed via ssh.
The script uses console as an alternative way to connect to the device and reinstall the image from the boot loader.

The script first checks the ssh connectivity of the device.
If ssh is working, it then checks the availability of `sonic-installer` on the device.
If `sonic-installer` is working, the device is considered healthy and no further action is needed.
Otherwise, the script proceeds to the recovery process via console.

The recovery process depends on the console access of the device.
If console access is not possible, the script cannot proceed.
The script obtains a console session and power cycles the device. It then waits for the right timing to enter the boot loader.
The script supports four types of boot loaders:
+ ONIE: used by Mellanox, Cisco, Acs, Celestica hwskus
+ Marvell: used by Nokia hwskus
+ Loader: used by Nexus hwskus
+ Aboot: used by Arista hwskus

In the boot loader, the script sets the temporary management ip and default route, and then reinstalls the image.
After the image is reinstalled, the script logs in to the device via console again and sets the permanent management ip and default route in Sonic.
It also writes these configurations to `/etc/network/interfaces` file to prevent losing them after reboot.

Finally, the script verifies that ssh and `sonic-installer` are working on the device. If both are ok, the recovery process is completed.

## Description of parameters
+ `inventory` - Inventory name
+ `testbed-name` - Testbed name
+ `tbfile` - Testbed file (testbed.yaml as default)
+ `verbosity` - Log verbosity (Level 2 as default)
+ `log-level` - Log level (Debug as default)
+ `image` - Golden image url of this testbed
+ `hwsku` - HwSku of this dut

## How to run the script
We can execute the script using such command
`python3 ../.azure-pipelines/recover_testbed/recover_testbed.py -i {inventory} -t {tbname} --tbfile {tbfile} --log-level {log-level} --image {image url} --hwsku {hwsku}
`
under the folder `sonic-mgmt/ansible`
