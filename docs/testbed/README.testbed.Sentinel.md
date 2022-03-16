# Sentinel

Currently, we don't have a system to monitor all devices of the testbed, including SONiC DUT, EOS neighbors and PTF. Testbed management which is a web tool to manage testbeds, developers use it to book testbed for development work, it also allocates corresponding testbeds for nightly test. It should have a monitor tool to collect health information for these devices and decide which testbeds are healthy and which are not, then can avoid nightly test running on an unhealth testbed.
Sentinel is a service in sonic-mgmt container, which collects all kinds of health information from all devices of the testbed periodically. It levarages existing classes and functions to login to devices and run commands to show related information, then transforms the output of command to json format data and reports these data to testbed management finally. The process is running all the time to make sure to collect the latest information and aim to monitor the health status of testbed.

# Design
Sentinel will be deployed by testbed management. Once testbed is set up, testbed management will deploy sentinal service on host server for this testbed. And then sentinel will run as an endless service in sonic-mgmt docker container.
It has 3 modules, including scheduler, connector and monitor. 
1. Scheduler is responsible to get credential information of all devices with testbed name, then create one thread to start and maintain ssh connections for all devices, create another thread to collect related health information for all devices. It also reports all health data to testbed management with POST API. For credential part, this is the benefit of running sentinel in sonic-mgmt container, it can easily get credential information without having to send sensitive credential data with parameters.
2. Connector is responsbile to login devices and maintain all ssh connections. When devices go down due to reboot or there is network issue, the ssh connections will be updated and monitor can't collect any data from these devices. If devices come back, their ssh connections will also be created again and monitor is able to collect health data too. SSH login part uses existing SSHClient class in devutils, it's another benefit to run sentinel in sonic-mgmt, it's easy to use libaries and modules in sonic-mgmt, doesn't have to write duplicated code here.
3. Monitor is going to run different commands on different devices, then parse the output of commands to json format data. For CPU/memory/disk, these are common health data, it has to be collected on every device. For DUT, monitor collects docker services, bgp sessions and interfaces status additionally. For EOS neighbors, monitor collects bgp sessions and etc. This module can be enhanced by adding and parsing more health commands in the future.

The design framework of sentinel is shown in the following figure:
![Sentinel framework](./img/sentinel_framework.png)

# Usage
The basic usage does like this:

```
sudo python sentinel.py <testbed name> [-v]
```

`testbed name` is `conf-name` in [ansible/testbed.yaml](https://github.com/Azure/sonic-mgmt/tree/master/ansible/testbed.yaml), it can be used to read credential, ip and hostname for DUT, PTF and EOS neighbors for this testbed.

sentinel log is saved in `/tmp/sentinel.log`

The following three values are intervals of monitor process, connection checking process and report process.

```
MONITOR_INTERVAL = 60
CONNECTION_INTERVAL = 60
REPORT_INTERVAL = 60
```


# Post API

TBD.
