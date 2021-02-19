# Mux Simulator

In dualtor testbed, mux Y cable is simulated by OVS in test server. An OVS bridge is created for each of the mux. The PTF interface and test server VLAN interfaces are attached to the bridge. The VLAN interfaces are connected to DUT ports through fanout switches.

```
                          +--------------+
                          |              +----- upper_if
          PTF (host_if) --+  OVS bridge  |
                          |              +----- lower_if
                          +--------------+
```

Open flow rules are configured for the OVS bridge to simulate upstream broadcasting and downstream dropping traffic from standby side.

To further simulate mux Y cable active/standby querying and setting, a process need to be started in the test server. The process needs to expose APIs for querying and setting active/standby status. On DUT side, a plugin can be injected to intercept the calls to mux Y cable. Instead of calling the actual mux driver functions, the APIs of mux simulator are called. Then the process checks and updates open flow configurations of the OVS bridge accordingly

The mux_simulator.py script is for such purpose. It is a [Flask](https://flask.palletsprojects.com/en/1.1.x/) based program exposing HTTP API. While running `testbed-cli.sh add-topo`, it is deployed to test server and started as a systemd service. By default, it listens on port `8080'.

On SONiC DUT side, script [y_cable_simulator_client.py](https://github.com/Azure/sonic-mgmt/blob/master/ansible/dualtor/y_cable_simulator_client.j2) will be injected to DUT during `testbed-cli.sh deploy-mg`. The [y_cable driver](https://github.com/Azure/sonic-platform-common/blob/master/sonic_y_cable/y_cable.py) has been enhanced to call the simulator client if it is available.

## Configuration
The default TCP port that the mux simulator will be listening on is configurable by variable `mux_simulator_port` in [https://github.com/Azure/sonic-mgmt/blob/master/ansible/group_vars/all/variables](https://github.com/Azure/sonic-mgmt/blob/master/ansible/group_vars/all/variables).

The mux simulator would be deployed to test server as a systemd service `mux-simulator` during `testbed-cli.sh add-topo`.
```
azure@str2-acs-serv-17:~$ sudo systemctl status mux-simulator
● mux-simulator.service - mux simulator
   Loaded: loaded (/etc/systemd/system/mux-simulator.service; static; vendor preset: enabled)
   Active: active (running) since Fri 2020-12-25 07:56:21 UTC; 6 days ago
 Main PID: 928 (python)
    Tasks: 1 (limit: 11059)
   CGroup: /system.slice/mux-simulator.service
           └─928 python /home/azure/veos-vm/mux_simulator.py 8080

Dec 25 07:56:21 str2-acs-serv-17 systemd[1]: Started mux simulator.
Dec 25 07:56:21 str2-acs-serv-17 env[928]:  * Serving Flask app "mux_simulator" (lazy loading)
Dec 25 07:56:21 str2-acs-serv-17 env[928]:  * Environment: production
Dec 25 07:56:21 str2-acs-serv-17 env[928]:    WARNING: This is a development server. Do not use it in a production deployment.
Dec 25 07:56:21 str2-acs-serv-17 env[928]:    Use a production WSGI server instead.
Dec 25 07:56:21 str2-acs-serv-17 env[928]:  * Debug mode: off
```

You can update its service file to manually change the listening port.

```
azure@test-server:~/veos-vm$ sudo cat /etc/systemd/system/mux-simulator.service
[Unit]
Description=mux simulator
After=network.target

[Service]
ExecStart=/usr/bin/env python /home/azure/veos-vm/mux_simulator.py 8080
```

After the service file is changed, run below commands to restart it:
```
sudo systemctl daemon-reload
sudo systemctl restart mux-simulator
```

## Shared by multiple test setups
The mux-simulator service is shared by multiple dualtor test setups using the same test server. Any dualtor test setups using it is recorded in a persistent file on test server `{{ root_path }}/mux_simulator.setups.txt`. During `testbed-cli.sh add-topo`, the vm set name of current setup will be added into it. During `testbed-cli.sh remove-topo`, the vm set name of current setup will be removed from it. When the file is empty, the mux-simulator service will be stopped.


## How to troubleshoot mux simulator
By default, the mux-simulator service output its logs to `/tmp/mux_simulator.log`. Default debug level is INFO. If DEBUG level logging is needed for troubleshooting, please follow below steps:

1. Stop the mux-simulator service.
```
sudo systemctl stop mux-simulator
```
2. Find out path of the mux_simulator.py script from the mux-simulator systemd service file.
```
cat /etc/systemd/system/mux-simulator.service
```
3. Manually run the mux_simulator.py script with `-v` option to **turn on DEBUG level logging**.
```
 sudo /usr/bin/env python /home/azure/veos-vm/mux_simulator.py 8080 -v
```
4. Try to call the mux simulator HTTP APIs and check the log file `/tmp/mux_simulator.log` for detailed logging.
5. After troubleshooting is done, stop the manually started mux_simulator.py script (for example: Ctrl+C).
6. Start the mux-simulator service again.
```
sudo systemctl start mux-simulator
```

## APIs
The APIs using json for data exchange.

### Typical json data format

* mux_status
```
{
  "active_port": "enp59s0f1.3216",
  "active_side": "upper_tor",
  "bridge": "mbr-vms17-8-0",
  "flows": {
    "enp59s0f1.3216": [
      {
        "action": "output",
        "out_port": "muxy-vms17-8-0"
      }
    ],
    "muxy-vms17-8-0": [
      {
        "action": "output",
        "out_port": "enp59s0f1.3272"
      },
      {
        "action": "output",
        "out_port": "enp59s0f1.3216"
      }
    ]
  },
  "port_index": "0",
  "ports": {
    "nic": "muxy-vms17-8-0",
    "upper_tor": "enp59s0f1.3216",
    "lower_tor": "enp59s0f1.3272"
  },
  "vm_set": "vms17-8"
}
```

* all_mux_status
```
{
    "mbr-vms17-8-0": <mux_status>,
    "mbr-vms17-8-2": <mux_status>,
    "mbr-vms17-8-3": <mux_status>,
    ...
}
```

* err_msg: Responded in case of anything wrong.
```
{
    "err_msg": <msg>
}
```

### GET `/mux/<vm_set>/<port_index>`

* `vm_set`: Value of column `group_name` in `testbed.csv` of current testbed.
* `port_index`: Index of DUT front panel port. Starting from `0`.

Response: `mux_status`

### POST `/mux/<vm_set>/<port_index>`
Post json data format:
```
{
    "active_side": "upper_tor|lower_tor|toggle|random"
}
```

* "upper_tor": set active side to "upper_tor".
* "lower_tor": set active side to "lower_tor".
* "toggle": toggle active side.
* "random": Randomly set active side to one of "upper_tor" and "lower_tor".

Response: `mux_status`

### GET `/mux/<vm_set>`
Response: `all_mux_status`

### POST `/mux/<vm_set>`

Post json data format:
```
{
    "active_side": "upper_tor|lower_tor|toggle|random"
}
```
Set active side for all bridges of specified vm_set.

Response: `all_mux_status`

### POST `/mux/<vm_set>/<port_index>/<action>`

* `action`: one of: `output`, `drop`.

Post json data format:
```
{
    "out_ports": ["nic", "upper_tor", "lower_tor"],
}
```

* `out_ports` is a list. It can contain single or multiple items from: `nic`, `upper_tor`, `lower_tor`.

This API is to set specified out ports to `output` or `drop`.

Response: `mux_status`
