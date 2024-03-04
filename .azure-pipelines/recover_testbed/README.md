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

## Structure
Our scripts are under the folder `.azure-pipelines/recover_testbed`
```buildoutcfg
 .azure-pipelines
    |
    |-- recover_testbed
        |
        |-- common.py
        |-- constants.py
        |-- dut_connection.py
        |-- interfaces.j2
        |-- recover_testbed.py
        |-- testbed_status.py
```

+ `common.py` - This module contains the common functions that are used for recovering testbeds, such as how to enter the boot loader mode.
   These functions are imported by other modules that implement the specific recovery steps for different devices.


+ `constants.py` - This module defines the constants that are used under the recover_testbed folder, such as sonic prompt, key words of timing.
   These constants are used to avoid hard-coding and to make the code more readable and maintainable.


+ `dut_connection.py` - This module defines the connection of the DUT, including ssh and console connections.
   It provides functions to create these connections, as well as to handle exceptions and errors.
   These functions are used to communicate with the DUT and execute commands on it.


+ `interfaces.j2` - This is a Jinja2 template file that is used to generate the file `/etc/network/interfaces` on the DUT.
   It defines the network interfaces and their configurations, such as IP address, netmask, gateway, etc.
   The template file takes some variables as input, such as the interface name, the IP address range, etc. These variables are passed by the recover_testbed.py module.


+ `recover_testbed.py` - This is the main module that implements the recovery process for the testbed.
   It takes some arguments as input, such as the inventory, the device name, the hwsku, etc.
   It then calls the appropriate functions from the common.py and dut_connection.py modules to establish a connection with the DUT and enter the recovery mode.
   It also uses the interfaces.j2 template file to generate and apply the network configuration on the DUT.
   Finally, it verifies that the DUT is successfully recovered and reports the result.


+ `testbed_status.py` - This module defines some status of the DUT, such as losing management IP address.
   It provides functions to check and update these status, as well as to log them.
   These functions are used by the recover_testbed.py module to monitor and troubleshoot the recovery process.



## Description of parameters
+ `inventory` - The name of the inventory file that contains the information about the devices in the testbed, such as hostname, IP address, hwsku, etc.


+ `testbed-name` - The name of the testbed. The testbed name should match the name of the testbed file that defines the topology and connections of the devices in the testbed.


+ `tbfile` - The name of the testbed file that defines the topology and connections of the devices in the testbed. The default value is `testbed.yaml`.


+ `verbosity` - The level of verbosity that is used for logging the automation steps and results. Verbosity level can be 0 (silent), 1 (brief), 2 (detailed), or 3 (verbose). The default value is 2.


+ `log-level` - The level of severity that is used for logging the automation messages. Log level can be Error, Warning, Info, or Debug. The default value is Debug.


+ `image` - The URL of the golden image that is used to install DUT. The golden image should be a valid SONiC image file that can be downloaded from a image server.


+ `hwsku` - The hardware SKU that identifies the model and configuration of the DUT in the testbed.

## How to run the script
The script should be run from the `sonic-mgmt/ansible` directory with the following command:
`python3 ../.azure-pipelines/recover_testbed/recover_testbed.py -i {inventory} -t {tbname} --tbfile {tbfile} --log-level {log-level} --image {image url} --hwsku {hwsku}
`
