# Introduction
This document describes the high level design for integrating OIR (Online Insertion and Removal) robot into the existing sonic-mgmt framework. The OIR robot is used to test the hot-plug and hot-unplug of SFPs on a DUT. The robot is controlled by running a custom command line script with various args on a robot server (a linux machine). The robot server is also connected to the sonic-mgmt test framework via SSH.

# Requirements
1. The robot server should use the same auth mechanism as other sonic devices.
2. The design should be extensible to support multiple robot servers in the future.
3. The design should follow the OIR API design guidelines mentioned in the transceiver OIR testplan.
4. The design should allow the details of the robot to be kept private from the public repo.

# Design
Following changes are proposed to integrate the OIR robot server into the sonic-mgmt framework:
1. OIR robot server integration will follow the same design as the PTF (Packet Test Framework) host integration.
2. A new ansible host instance will be created for the robot server in the ansible inventory.
3. The robot server will be reachable from the sonic-mgmt test framework using the same auth mechanism as other sonic devices.
4. The testbed config file will be updated to include the robot server ip and robot id.

## Design Details
1. A new class `RobotHost` will be created in `tests/common/devices/oir_robot.py` to represent the robot server. This class will inherit from `AnsibleHostBase`.
2. The `RobotHost` class will have methods to run the various robot commands such as `plug_in_all`, `unplug_all`, `plug_in_one`, `unplug_one`, `start_nodes`, `stop_nodes`, and `node_status`. The implementation of the class will be adapted from the original [robot.py from Networking-scripts-libs.](https://msazure.visualstudio.com/One/_git/Networking-scripts-lib?path=%2Fapproved-internal-libraries%2Flib%2Fpython%2Fpackages%2Fstarlab-3po%2Fstarlab_3po%2Frobot_3po%2Frobot.py)
3. `PhysicalOIR` class in `tests/common/physical_oir.py` will be updated to use the `RobotHost` class to interact with the robot server.
4. The `PhysicalOIR` class will have methods according to the [OIR API design guidelines](./transceiver_onboarding/optics_insertion_removal_testplan.md#physical-oir-api) to perform the required operations on the robot server.
5. Ansible inventory will be updated to include the robot server details. The format will be similar to the PTF host entry. For example:
```yaml
# sample addition to ansible inventory file: ansible/str
sonic_oir_robot:
  hosts:
    str43-3po-robot:
      ansible_host: 10.3.158.75
      ansible_ssh_user: admin
```
6. The testbed config file will be updated to include the robot server ip and robot id. The format will be similar to the PTF host entry. For example:
```yaml
# sample addition to testbed config file: ansible/testbed.yaml
- conf-name: ptp-robot-7060-1
  group-name: ''
  topo: ptp-256
  robot_server: str43-3po-robot
  robot_id: 1
  dut:
    - str43-3po-robot-7060
  inv_name: str
  auto_recover: 'True'
  comment: arizzubair
```

## Control Flow
The control flow for using the OIR robot server in a test will be as follows:
1. The test will create an instance of the `PhysicalOIR` class.
2. The `PhysicalOIR` instance will create an instance of the `RobotHost` class using the robot server ip and robot id from the testbed config file.
3. The test will call the required methods on the `PhysicalOIR` instance to perform the desired operations on the robot server.
4. The `PhysicalOIR` instance will use the `RobotHost` instance to run the appropriate robot commands on the robot server.
The overall class interaction is as follows:

```plaintext
+----------------+                 +----------------+                +---------------------+               +-------------------+
|   OIR Tests    | --------------> |  PhysicalOIR   | -------------> |      RobotHost      | ------------> |  AnsibleHostBase  |
|                |  Instantiates   |                | Instantiates   |                     |    Inherits   |                   |
+----------------+                 +----------------+                +---------------------+               +-------------------+
```

The server communication flow is as follows:

```plaintext
+-----------------------------------+                 +---------------------------------+                +-------+
| Server running sonic-mgmt tests   | --------------> |  Robot Server running CLI app   | -------------> | Robot |
| e.g. starlab-srv-14, sonic dev vm |   Ansible SSH   |  to control the robot remotely  |       SSH      |       |
+-----------------------------------+                 +---------------------------------+                +-------+

```

## Robot server changes
Following changes are required on the robot server for the integration to work:
1. Add a user with `admin` username and one of the sonic passwords for SSH access. Give it root privileges.
```bash
sudo adduser admin # Set password when prompted
sudo usermod -aG sudo admin
```
2. Configure `admin` user to do passwordless sudo.
```bash
sudo visudo
# Add the following line in the end
admin ALL=(ALL) NOPASSWD:ALL
```
3. Add the public and private keys to `/home/admin/.ssh` from another user (e.g. administrator).
4. Add authorized keys to `/home/admin/.ssh/authorized_keys` from another user (e.g. administrator).
5. Add private key to `/root/.ssh` for root user to allow ssh to robot nodes.
