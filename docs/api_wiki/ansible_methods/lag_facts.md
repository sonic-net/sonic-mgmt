# lag_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve Ling Aggregation Group information from a device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    lag_facts = duthost.lag_facts(host=duthost.hostname)
```

## Arguments
- `host` - hostname for desired host
    - Required: `True`
    - Type: `String`

## Expected Output
Returns dictionary with facts on LAG. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `lag_facts` - Dictionary with info on configured link aggregation groups
        - `names` - list of name of configured LAGs
        - `lags` - Dictionary that provides info on LAG configs
            - `{LAG_NAME}` - Dictionary that provides info on provided LAg
                - `po_config`
                    - `device` - name of device (usually same as provided for `LAG_NAME`
                    - `hwaddr` - hardware address
                    - `runner`
                        - `active` - whether active or not
                        - `min_ports` - minimum number of ports
                        - `tx_hash` -?
                        - `name` - protocol name
                    - `ports`
                        - `{PORT_NAME}`
                            - `lacp_key`
                            - `link_watch`
                                - `name`
                - `po_namespace_id`
                - `po_intf_stat` - interface status
                - `po_stats`
                    - `runner`
                        - `active`
                        - `select_policy`
                        - `fallback`
                        - `fast_rate`
                        - `sys_prio`
                    - `setup`
                        - `daemonized`
                        - `zmq_enabled`
                        - `kernel_team_mode_name`
                        - `pid`
                        - `dbus_enabled`
                        - `pid_file`
                        - `runner_name`
                    - `ports`
                        - `{PORT_NAME}`
                            - `link_watches`
                                - `list`
                                    - `{LINK_WATCH_NAME}`
                                        - `up`
                                        - `down_count`
                                        - `name`
                                        - `delay_down`
                                        - `delay_up`
                                    - `up`
                            - `runner`
                                - `state`
                                - `actor_lacpdu_info`
                                    - `port_priority`
                                    - `state`
                                    - `system_priority`
                                    - `key`
                                    - `system`
                                    - `port`
                                - `key`
                                - `prio`
                                - `aggregator`
                                    - `selected`
                                    - `id`
                                - `selected`
                                - `partner_lacpdu_info`
                                    - `port_priority`
                                    - `state`
                                    - `system_priority`
                                    - `key`
                                    - `system`
                                    - `port`
                            - `link`
                                - `duplex`
                                - `speed`
                                - `up`
                            - `ifinfo`
                                - `ifindex`
                                - `dev_addr`
                                - `ifname`
                                - `dev_addr_len`
                    - `team_device`
                        - `ifinfo`
                            - `ifindex`
                            - `dev_addr`
                            - `ifname`
                            - `dev_addr_len`
