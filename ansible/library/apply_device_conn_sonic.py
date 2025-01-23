#!/usr/bin/env python

from ansible.module_utils.basic import AnsibleModule
import traceback
import subprocess
import shlex


def get_port_lists():
    cmd = "show interfaces description | grep Ethernet | awk '{print $1}'"
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ps.communicate()[0].decode('utf-8')
    port_list = [line for line in output.split('\n') if line.strip()]
    return port_list


def get_platform():
    cmd = "redis-cli --raw -n 4 hget 'DEVICE_METADATA|localhost' 'platform'"
    ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ps.communicate()[0].decode('utf-8')
    return output.strip()


def set_autoneg(port, value):
    if value == "on":
        value = "enabled"
    elif value == "off":
        value = "disabled"
    else:
        raise Exception("Invalid autoneg value: %s" % value)
    cmd = "config interface autoneg %s %s" % (port, value)
    ps = subprocess.Popen(shlex.split(cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (_, stderr) = ps.communicate()
    if ps.returncode != 0:
        if stderr:
            stderr = stderr.decode('utf-8')
        raise Exception("Failed to set autoneg for port %s: %s" % (port, stderr))


def apply_device_conn(module, platform, port_list, device_conn):
    # Apply Autoneg
    default_autoneg_value = None
    if "nvidia_sn5600" in platform:
        default_autoneg_value = "on"
    for port in port_list:
        autoneg_value = default_autoneg_value
        if port in device_conn:
            attribute = device_conn[port]
            if "autoneg" in attribute:
                autoneg_value = attribute["autoneg"]
        if autoneg_value:
            module.warn("Set autoneg for port %s to %s" % (port, autoneg_value))
            set_autoneg(port, autoneg_value)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=False),
            device_conn=dict(required=True, type=dict)
        )
    )

    platform = get_platform()
    port_list = get_port_lists()
    device_conn = module.params['device_conn']

    apply_device_conn(module, platform, port_list, device_conn)

    try:
        pass
    except Exception as detail:
        module.fail_json(msg="ERROR: %s, TRACEBACK: %s" %
                         (repr(detail), traceback.format_exc()))
    module.exit_json(
        ansible_facts=dict()
    )


if __name__ == "__main__":
    main()
