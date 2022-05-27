# Introduction of SONiC docker-ptf migration

# why migrate docker-ptf


As of January 1, 2020, Python 2 is no longer supported by the Python core team, that's why we have to migrate our code from Python2 to python3. 

`docker-ptf` is our first goal, because it's a separated docker container and only scripts under `ansible/role/test/files/ptftests` in `sonic-mgmt` repo run in `docker-ptf`. 

The dependency is not very complicated and it's much easier to start with it.

# How to migrate Python3 for PTF

In order to migrate docker-ptf smoothly and incrementally, we plan to do it step by step, not migrate all related scripts to python immediately, which would cause scale and major failures and impact the nightly test for master image.

Migration includes 4 stages:

## Stage 1: Prepare Python3 virtual environment in docker-ptf
Add Python3 virtual environment in docker-ptf, we will keep Python2 in this stage for incremental migration.

[PR](https://github.com/Azure/sonic-buildimage/pull/10599) to address this.

`/root/env-python3/bin/ptf` is installed and will be used for `ptftests` Python3 scripts.

`ptf` version is `0.9.3`,  `scapy 2.4.5` is also installed into virtual environment.

This stage was completed.


## Stage 2: Migrate `ptftests` scripts one by one, feature by feature

There are 36 scripts under `ansible/role/test/files/ptftests` in `sonic-mgmt` repo, including nearly 20 features.
There are 11 scripts under `ansible/role/test/files/acstests` as well.


**1. use `2to3` to covert `ptftests` script automatically**

2to3 is a tool which can covert script from Python2 to Python3 automatically.

The command looks like this:
`2to3 --write --nobackups ansible/role/test/files/ptftests/your_script`

Here is the [doc](https://docs.python.org/3/library/2to3.html) for 2to3.
 

If it is not available on your host, you need to first install the following packages:


```
apt install 2to3
apt install python3-lib2to3
apt install python3-toolz
```

For windows just install 2to3 package:

`pip install 2to3`

Then you can check changes with `git diff`

**2. move your modified `ptftest` script to `ansible/role/test/files/ptftests/py3`**

`ansible/role/test/files/ptftests/py3` is a new added subfolder for Python3 scripts.

`ptf` command will load all scripts under `--test-dir` before running test. It will fail if some modules can't be imported.

For Python3 scripts, they will call `/root/env-python3/bin/ptf` command, `--test-dir` is `ptftests/py3`, it only loads all script under `ptftests/py3`, don't check the scripts under `ptftests`.

But for left Python2 scripts, they will still call `ptf` command, `--test-dir` is `ptftests`, it will load all scripts under `ptftests` even scripts under subfolder `py3`.
So make sure it doesn't have incompatible issue when running `ptf` command.

Suggest to run some old Python2 scripts which call `ptf` command after you finish the migration of your scripts. This can check incompatible module issue and avoid the failure of Python2 scripts.

For example, there is no `scapy.contrib.macsec` module for Python2, it's safe to add if condition here to avoid failure:

```
MACSEC_SUPPORTED = False
if hasattr(scapy, "VERSION") and tuple(map(int, scapy.VERSION.split('.'))) >= (2, 4, 5):
    MACSEC_SUPPORTED = True
if MACSEC_SUPPORTED:
    import scapy.contrib.macsec as scapy_macsec
```

If your scripts involves the following library scripts, please create a **soft link** under `py3` for them after modification. Other remained scripts of Python2 will still use them. They will be used for both sides during the period of migration.
 - `lmp.py`
 - `fib.py` 
 - `fib_test.py`
 - `device_connection.py`

**Important: These library scripts should be both Python2 and Python3 compatible.**


Please check [this PR](https://github.com/Azure/sonic-mgmt/pull/5490) for reference.

**3. Update `tests` script to call virtual env ptf**

Add `is_python3=True` parameter for `ptf_runner` in your test script. Such as:

```
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcpv6_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']),
                           "server_ip": str(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'][0]),
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_link_local": str(dhcp_relay['uplink_interface_link_local']),
                           "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr'])},
                   log_file="/tmp/dhcpv6_relay_test.DHCPTest.log", is_python3=True)
```



It will run `/root/env-python3/bin/ptf` instead of `ptf` which is used for Python2 now.
And it will also call your modified ptftests scripts under subfolder `py3`.

That's the difference of usage between Python2 and Python3 script.

Please take [DHCP Relay PR](https://github.com/Azure/sonic-mgmt/pull/5534)  and [dir bcast RP](https://github.com/Azure/sonic-mgmt/pull/5540)for reference.



**4. Run test cases with correct docker-ptf image to do verification**

`2to3` only does some common format or syntax changes, it's not enough. 

For Python3, scripts use `ptf 0.9.3` and `scapy 2.4.5`, some packet format could be different, we have to retest scripts manually before submit PR.

- Check `docker-ptf` image
Login to `docker-ptf` container to check if it's correct image. If there is `env-python3` under `/root`, it means you are using the correct image.

```
azure@STR-ACS-SERV-07:~$ docker exec -it ptf_vms7-11 bash
root@72cf0e0442c3:~# cd /root
root@72cf0e0442c3:~# ls
debs  env-python3  gnxi  python-saithrift_0.9.4_amd64.deb
root@72cf0e0442c3:~#
```
Otherwise, it will throw exception to ask you to update `docker-ptf` image.


- Submit PR
Please add **[python3]** in your RP title.

## Stage 3: Migrate other functionaly scripts which run in docker-ptf
Some functional scripts are also copied and ran in docker-ptf, such as:
- `scripts/arp_responder.py`
- `scripts/garp_service.py`
- `scripts/icmp_responder.py`
- `scripts/dual_tor_sniffer.py`
- `scripts/nat_ptf_echo.py`
- `bgp/bgp_monitor_dump.py`
- `http/start_http_server.py`
- `http/stop_http_server.py`
- `ansible/library/exabgp.py`
- `arp/files/ferret.py`

During migration of these scripts, make sure to call `/root/env-python3/bin/python3` to run them.

## Stage 4: Migrate docker-ptf to pure Python3 environment
When stage 3 is done, this could be the final stage:
- Update docker-ptf's Dockerfile, use bullseye and will no install Python2, just keep Python3 environment.
- Move all ptftests scripts from `py3` subfolder to `ptftests` fodler.
- Remove `is_python3` parameter in ptf_runner, remove `/root/env-python3/bin/ptf` part, just call `ptf` command.
- Remove `is_python3=True` for all tests scripts.
- Remove those checkers for Python version in `ptftests` scripts.




