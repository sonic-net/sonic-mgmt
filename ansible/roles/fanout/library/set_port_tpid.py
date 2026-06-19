#!/usr/bin/env python
"""Set the outer TPID for the fanout access ports."""
import traceback

from ansible.module_utils.basic import AnsibleModule


def get_bcrm_port_info(module):
    return_code, stdout, _ = module.run_command("bcmcmd 'knetctrl netif show'", use_unsafe_shell=True)
    if return_code:
        raise RuntimeError("Failed to get interface details via command 'knetctrl netif show'")
    bcrm_port_info = {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface ID"):
            _, port_attrs = line.split(":")
            info = {}
            for attr in port_attrs.split():
                if "=" in attr:
                    key, val = attr.split("=")
                    info[key.strip()] = val.strip()
            bcrm_port_info[info["name"]] = info

    return_code, stdout, _ = module.run_command("bcmcmd 'ps'", use_unsafe_shell=True)
    if return_code:
        raise RuntimeError("Failed to get port status via command 'ps'")
    bcrm_port_name_to_id = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "(" in line and ")" in line:
            port_name_id, _ = line.split(")")
            port_name, port_id = port_name_id.strip().split("(")
            bcrm_port_name_to_id[port_name.strip()] = port_id.strip()

    for intf_name, port_info in bcrm_port_info.items():
        port_info['port_id'] = bcrm_port_name_to_id[port_info['port']]

    return bcrm_port_info


def set_outer_tpid(module, fanout_port_info, fanout_port_vlans, fanout_port_config):
    modi_cmd_tmpl = "bcmcmd 'modi port %s 1 OUTER_TPID_ENABLE=0'"
    for port_name in fanout_port_vlans:
        if fanout_port_vlans[port_name]["mode"] == "Access":
            port_id = fanout_port_info[port_name]["port_id"]
            cmd = modi_cmd_tmpl % port_id
            return_code, _, _ = module.run_command(cmd, use_unsafe_shell=True)
            if return_code:
                raise RuntimeError("Failed to set outer tpid for port %s" % port_name)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            fanout_port_vlans=dict(required=True, type=dict),
            fanout_port_config=dict(required=True, type=dict)
        )
    )

    fanout_port_vlans = module.params["fanout_port_vlans"]
    fanout_port_config = module.params["fanout_port_config"]

    try:
        fanout_port_info = get_bcrm_port_info(module)
        set_outer_tpid(module, fanout_port_info, fanout_port_vlans, fanout_port_config)
    except Exception as detail:
        module.fail_json(msg="ERROR: %s, TRACEBACK: %s" % (repr(detail), traceback.format_exc()))
    module.exit_json(changed=True)


if __name__ == '__main__':
    main()
