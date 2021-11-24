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

The mux_simulator.py script is for such purpose. It is a [Flask](https://flask.palletsprojects.com/en/1.1.x/) based program exposing HTTP API. While running `testbed-cli.sh add-topo`, it is deployed to test server and started as a systemd service.

On SONiC DUT side, script [y_cable_simulator_client.py](https://github.com/Azure/sonic-mgmt/blob/master/ansible/dualtor/y_cable_simulator_client.j2) will be injected to DUT during `testbed-cli.sh deploy-mg`. The [y_cable driver](https://github.com/Azure/sonic-platform-common/blob/master/sonic_y_cable/y_cable.py) has been enhanced to call the simulator client if it is available.

## Configuration

A test server may serve multiple dualtor testbeds. The original design is to start a single `mux-simulator` systemd service for all the dualtor testbeds using the server. It turns out that this approach is not flexible enough. Sometimes we may need to restart the mux-simulator server for one testbed. If the other testbeds are running tests, they could be negatively affected. The new design is to have a mux simulator service running for each testbed. Each of the mux simulator server listens on different TCP port. TCP port of mux simulator server for each dualtor testbed needs to be defined in file [https://github.com/Azure/sonic-mgmt/blob/master/ansible/group_vars/all/mux_simulator_http_port_map.yml](https://github.com/Azure/sonic-mgmt/blob/master/ansible/group_vars/all/mux_simulator_http_port_map.yml). For example:
```
mux_simulator_http_port:
    # Format requirement:
    #   <testbed_name>: <port>

    # On server1
    dualtor-testbed-1: 8080
    dualtor-testbed-1: 8082

    # On server2
    dualtor-testbed-3: 8080
    dualtor-testbed-4: 8082

```
Please assign unused port for each testbed. On the same server, the ports must not be same for different testbeds.

The mux simulator would be deployed to test server as a systemd service `mux-simulator-<port>` during `testbed-cli.sh add-topo`.
```
azure@test-server:~$ sudo systemctl status mux-simulator-8080.service
● mux-simulator-8080.service - mux simulator
     Loaded: loaded (/etc/systemd/system/mux-simulator-8080.service; static; vendor preset: enabled)
     Active: active (running) since Tue 2021-09-14 09:02:23 UTC; 2s ago
   Main PID: 298236 (python)
      Tasks: 1 (limit: 77147)
     Memory: 24.0M
     CGroup: /system.slice/mux-simulator-8080.service
             └─298236 python /home/azure/veos-vm/mux_simulator.py 8080 vms6-1 -v

Sep 14 09:02:23 test-server systemd[1]: Started mux simulator.
Sep 14 09:02:24 test-server env[298236]:  * Serving Flask app "mux_simulator" (lazy loading)
Sep 14 09:02:24 test-server env[298236]:  * Environment: production
Sep 14 09:02:24 test-server env[298236]:    WARNING: This is a development server. Do not use it in a production deployment.
Sep 14 09:02:24 test-server env[298236]:    Use a production WSGI server instead.
Sep 14 09:02:24 test-server env[298236]:  * Debug mode: off
Sep 14 09:02:24 test-server env[298236]:  * Running on all addresses.
Sep 14 09:02:24 test-server env[298236]:    WARNING: This is a development server. Do not use it in a production deployment.
Sep 14 09:02:24 test-server env[298236]:  * Running on http://192.168.0.20:8080/ (Press CTRL+C to quit)
```

Each testbed has its own mux simulator service. Name of the service is `mux-simulator-<port>`. Where `port` is the http port assigned to the mux simulator server of the testbed (`ansible/group_vars/all/mux_simulator_http_port_map`)

Example content of example mux-simulator-8080 service:

```
azure@test-server:~/veos-vm$ sudo cat /etc/systemd/system/mux-simulator-8080.service
[Unit]
Description=mux simulator
After=network.target

[Service]
ExecStart=/usr/bin/env python /home/azure/veos-vm/mux_simulator.py 8080 vms6-1 -v
```

The parameter `vms6-1` after port `8080` in the above example is the vm_set name of the current testbed. It is value of column `group-name` in testbed.csv or value of field `group-name` in testbed.yml. When a dualtor testbed is deployed on test server, we use vm_set name in name of OVS bridges to differentiate multiple dualtor testbeds. That's why the vm_set name information is needed for mux simulator server for each testbed.

If the service file is changed, need to run below commands to restart it:
```
sudo systemctl daemon-reload
sudo systemctl restart mux-simulator-8080
```

## Shared by multiple test setups
Originally the mux-simulator service is shared by multiple dualtor test setups using the same test server. Now the design has changed. A mux simulator server is started on a different TCP port for each dualtor testbed now.

## How to troubleshoot mux simulator
By default, the mux-simulator service output its logs to `/tmp/mux_simulator.log`. Default debug level is INFO. If DEBUG level logging is needed for troubleshooting, please follow below steps:

1. Check mux simulator http port map, find out the port used by mux simulator of current testbed. Assume the assigned port is 8080. Then name of the mux simulator server service would be `mux-simulator-8080`.
```
cat ansible/group_vars/all/mux_simulator_http_port_map.yml
```
2. Stop the mux-simulator service.
```
sudo systemctl stop mux-simulator-8080
```
3. Find out path of the mux_simulator.py script from the mux-simulator systemd service file.
```
cat /etc/systemd/system/mux-simulator-8080.service
```
4. Manually run the mux_simulator.py script with `-v` option to **turn on DEBUG level logging**.
```
 sudo /usr/bin/env python /home/azure/veos-vm/mux_simulator.py 8080 vms6-1 -v
```
5. Try to call the mux simulator HTTP APIs and check the log file `/tmp/mux_simulator_8080.log` for detailed logging.
6. After troubleshooting is done, stop the manually started mux_simulator.py script (for example: Ctrl+C).
7. Start the mux-simulator service again.
```
sudo systemctl start mux-simulator-8080
```

## APIs
The APIs using json for data exchange.

### Typical json data format

* mux_status
```
{
  "active_port": "enp59s0f1.3532",
  "active_side": "upper_tor",
  "bridge": "mbr-vms21-3-0",
  "flap_counter": 0,
  "flows": {
    "enp59s0f1.3532": [
      {
        "action": "output",
        "out_port": "muxy-vms21-3-0"
      }
    ],
    "muxy-vms21-3-0": [
      {
        "action": "output",
        "out_port": "enp59s0f1.3532"
      },
      {
        "action": "output",
        "out_port": "enp59s0f1.3588"
      }
    ]
  },
  "healthy": true,
  "port_index": 0,
  "ports": {
    "lower_tor": "enp59s0f1.3588",
    "nic": "muxy-vms21-3-0",
    "upper_tor": "enp59s0f1.3532"
  },
  "standby_port": "enp59s0f1.3588",
  "standby_side": "lower_tor",
  "vm_set": "vms21-3"
}
```

* all_mux_status
```
{
    "mbr-vms21-3-0": <mux_status>,
    "mbr-vms21-3-1": <mux_status>,
    "mbr-vms21-3-2": <mux_status>,
    ...
}
```

* err_msg: Responded in case of anything wrong.
```
{
    "err_msg": <msg>
}

In case of the mux_simulator.py script is started with "-v" option, an extra "traceback" field will be included in the json response for troubleshooting.
```

### GET `/mux/<vm_set>/<port_index>`

Get status of mux bridge specified by `vm_set` and `port_index`.

* `vm_set`: Value of column `group_name` in `testbed.csv` of current testbed.
* `port_index`: Index of DUT front panel port. Starting from `0`.

Response: `mux_status`

### POST `/mux/<vm_set>/<port_index>`

Toggle active/standby side of mux bridge specified by `vm_set` and `port_index`.

Format of json data required in POST:
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

Get status of all mux bridges belong to `vm_set`.

Response: `all_mux_status`

### POST `/mux/<vm_set>`

Format of json data required in POST:
```
{
    "active_side": "upper_tor|lower_tor|toggle|random"
}
```
Set active side for all bridges of specified vm_set.

Response: `all_mux_status`

### POST `/mux/<vm_set>/<port_index>/<action>`

Set flow action to `output` or `drop` for specified interfaces on mux bridge specified by `vm_set` and `port_index`.

* `action`: one of: `output`, `drop`, and `reset`

#### When `action` is `output` or `drop`

Format of json data required in POST:
```
{
    "out_sides": ["nic", "upper_tor", "lower_tor"],
}
```

* `out_sides` is a list. It can contain single or multiple items from: `nic`, `upper_tor`, `lower_tor`.

This API is to set specified out ports to `output` or `drop` when action is `output` or `drop`.

Response: `mux_status`

#### When `action` is `reset`

No json data required in POST. This API is to recover the flows of current mux bridge to known good state:
* Upstream flow: forward all packets received by `nic` to both `upper_tor` and `lower_tor`
* Downstream flow: forward packets received by current active tor interface to `nic`. In case current active port is unknown, randomly choose an active interface from `upper_tor` and `lower_tor`. Then setup the downstream flow.

Response: `mux_status`

### POST `/mux/<vm_set>/reset`

Recover flows of all mux bridges belong to `vm_set` to known good state.

No json data required in POST. This API is to recover flows of all the mux bridges belong to the `vm_set` to known good state:
* Upstream flow: forward all packets received by `nic` to both `upper_tor` and `lower_tor`
* Downstream flow: forward packets received by current active tor interface to `nic`. In case current active port is unknown, randomly choose an active interface from `upper_tor` and `lower_tor`. Then setup the downstream flow.

Response: `all_mux_status`

### GET `/mux/<vm_set>/port_index>/flap_counter`

Get flap counter of bridge specified by `vm_set` and `port_index`.

Response:
```
{
  <mux_bridge_name>: <flap_counter>
}
```

Example:
```
{
  "mbr-vms21-3-0": 3
}
```

### GET `/mux/<vm_set>/flap_counter`

Get flap counter of all bridges belong to `vm_set`.

Response:
```
{
  <mux_bridge_name>: <flap_counter>,
  <mux_bridge_name>: <flap_counter>,
  ...
}
```

Example:
```
{
  "mbr-vms21-3-0": 0,
  "mbr-vms21-3-1": 0,
  "mbr-vms21-3-10": 1,
  "mbr-vms21-3-11": 0,
  ...
}
```

### POST `/mux/<vm_set>/clear_flap_counter`

Clear flap counter of all bridges or specific bridge.

Format of json data required in POST:

* Clear flap counter of all bridges:
```
{
    "port_to_clear": "all"
}
```
* Clear flap counter of specific bridge
```
{
    "port_to_clear": "<port_index>|<port_index>|..."
}
```
For example, post the URL with below data is to clear flap counter of port 0, 3, 5, and 10.
```
{
    "port_to_clear": "0|3|5|10"
}
```

### POST `/mux/<vm_set>/reload`

Force the mux simulator to collect status of the bridges and re-create the mux objects again. The effect is same as restarting the mux simulator service.

### POST `/mux/<vm_set>/log`

Post this URL is able to log supplied message in the mux simulator server's log file for debugging purpose.

Format of json data required in POST:
```
{"message": "<any string>"}
```
