#!/usr/bin/env python
"""Set the outer TPID for the fanout access ports."""
import traceback

from ansible.module_utils.basic import AnsibleModule


def get_netif_show(module):
    return_code, stdout, _ = module.run_command("bcmcmd 'knetctrl netif show'", use_unsafe_shell=True)
    if return_code:
        raise RuntimeError("Failed to get interface details via command 'knetctrl netif show'")
    port_info = {}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            port, port_attrs = line.split(":")
            port_id = port.split()[-1]
            attributes = {"port_id": port_id}
            for port_attr in port_attrs.split():
                if "=" in port_attr:
                    key, val = port_attr.split("=")
                    attributes[key.strip()] = val.strip()
            port_info[attributes["name"]] = attributes

    return port_info
            
def set_outer_tpid(module, fanout_port_info, fanout_port_vlans, fanout_port_config):
    modi_cmd_tmpl = "bcmcmd 'modi port %s 1 OUTER_TPID_ENABLE=0'"
    for port_alias in fanout_port_vlans:
        if fanout_port_vlans[port_alias]["mode"] == "Access":
            port_name = fanout_port_config[port_alias]["name"]
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
        fanout_port_info = get_netif_show(module)
        set_outer_tpid(module, fanout_port_info, fanout_port_vlans, fanout_port_config)
    except Exception as detail:
        module.fail_json(msg="ERROR: %s, TRACEBACK: %s" % (repr(detail), traceback.format_exc()))
    module.exit_json(changed=True)

if __name__ == '__main__':
    main()
