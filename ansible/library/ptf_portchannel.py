#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import jinja2  # nosemgrep: direct-use-of-jinja2
import traceback
import re
import os
import time
DOCUMENTATION = '''
module:  ptf_portchannel

short_description: manage portchannel interface in PTF container
description: start/stop portchannel interface in PTF container with certain configurations

Options:
    - option-name: cmd
      description: An action string as [start|stop]
      required: True
    - option-name: portchannel_config
      description: A dict to indicate the portchannel configuration. E.G. {"PortChannel101": {"intfs": [0, 4]}}
      required: True
    - option-name: mode
      description: |
        Backend used to implement the portchannel inside the PTF container.
        - 'bond': native Linux bonding driver in 802.3ad (LACP) mode.
        - 'teamd' (default): legacy teamd-based implementation managed via supervisord.
      choices: ['teamd', 'bond']
      default: 'teamd'
      required: False
    - option-name: lacp_servers
      description: |
        List of simulated LACP servers. Each entry creates an 802.3ad bond over PTF ports (root netns).
        Keys: bond (required), members (PTF port indexes, required), lacp_rate (slow|fast), miimon,
        min_links, xmit_hash_policy, and optionally bond_mac (bond/LACP system ID), mac, ip (CIDR), gateway, netns.
        When ip is set, a macvlan carrying mac/ip is moved into a per-server netns so server-to-server traffic crosses the DUTs.
      required: False
      default: []
'''


EXAMPLES = '''
- name: Start PTF portchannel (default teamd backend)
  ptf_portchannel:
    cmd: "start"
    portchannel_config: "{{ portchannel_config }}"
    mode: "teamd"

- name: Start PTF portchannel using Linux bond backend
  ptf_portchannel:
    cmd: "start"
    portchannel_config: "{{ portchannel_config }}"
    mode: "bond"
'''


portchannel_conf_path = "/etc/portchannel"


portchannel_conf_tmpl = '''\
{
    "device": "{{ name }}",
    "runner": {
        "active": true,
        "name": "lacp",
        "min_ports": 1
    },
    "ports": {
{%- for intf in intfs %}
        "{{ intf }}": {}{{ "," if not loop.last else "" }}
{%- endfor %}
    }
}
'''


portchannel_supervisord_path = "/etc/supervisor/conf.d"


portchannel_supervisord_conf_tmpl = '''\
[program:portchannel-{{ name }}]
command=/usr/bin/teamd -r -t {{ name }} -f ''' + portchannel_conf_path + '''/{{ name }}.conf
stdout_logfile=/tmp/portchannel-{{ name }}.out.log
stderr_logfile=/tmp/portchannel-{{ name }}.err.log
redirect_stderr=false
autostart=true
autorestart=true
startsecs=1
numprocs=1
'''


def exec_command(module, cmd, ignore_error=False, msg="executing command"):
    rc, out, err = module.run_command(cmd)
    if not ignore_error and rc != 0:
        module.fail_json(msg="Failed %s: rc=%d, out=%s, err=%s" %
                         (msg, rc, out, err))
    return out


def get_portchannel_status(module, name):
    output = exec_command(
        module, cmd="supervisorctl status portchannel-%s" % name)
    m = re.search(r'^([\w|-]*)\s+(\w*).*$', output.decode("utf-8"))
    return m.group(2)


def refresh_supervisord(module):
    exec_command(module, cmd="supervisorctl reread", ignore_error=True)
    exec_command(module, cmd="supervisorctl update", ignore_error=True)


def parse_teamd_config(module, portchannel_config):
    conf = []
    for name, intfs in portchannel_config.items():
        intfs_names = []
        if not intfs["intfs"]:
            continue
        for intf in intfs["intfs"]:
            intfs_names.append("eth" + str(intf))
        conf.append({"name": name, "intfs": intfs_names})
    return conf


def create_teamd_conf(module, teamd_config):
    t = jinja2.Template(portchannel_conf_tmpl)
    for conf in teamd_config:
        with open(os.path.join(portchannel_conf_path, "{}.conf".format(conf["name"])), 'w') as fd:
            fd.write(t.render(conf))  # nosemgrep: direct-use-of-jinja2


def remove_teamd_conf(module, teamd_config):
    for conf in teamd_config:
        try:
            os.remove(os.path.join(portchannel_conf_path,
                      "{}.conf".format(conf["name"])))
        except Exception:
            pass


def create_supervisor_conf(module, teamd_config):
    t = jinja2.Template(portchannel_supervisord_conf_tmpl)
    for conf in teamd_config:
        with open(os.path.join(portchannel_supervisord_path, "portchannel-{}.conf".format(conf["name"])), 'w') as fd:
            fd.write(t.render(conf))  # nosemgrep: direct-use-of-jinja2
    refresh_supervisord(module)


def remove_supervisor_conf(module, teamd_config):
    for conf in teamd_config:
        try:
            os.remove(os.path.join(portchannel_supervisord_path,
                      "portchannel-{}.conf".format(conf["name"])))
        except Exception:
            pass
    refresh_supervisord(module)


def enable_portchannel(module, teamd_config):
    for conf in teamd_config:
        for intf in conf["intfs"]:
            exec_command(module, "ip link set dev {} down".format(intf))
        exec_command(
            module, "supervisorctl start portchannel-{}".format(conf["name"]))
        for count in range(0, 60):
            time.sleep(1)
            status = get_portchannel_status(module, conf["name"])
            if u'RUNNING' == status:
                break
        assert u'RUNNING' == status
        exec_command(module, "ip link set dev {} up".format(conf["name"]))


def disable_portchannel(module, teamd_config):
    for conf in teamd_config:
        exec_command(
            module, cmd="supervisorctl stop portchannel-{}".format(conf["name"]), ignore_error=True)


def create_bond(module, portchannel_config):
    """Create bond interfaces with LACP mode and enslave member ports."""
    for conf in portchannel_config:
        name = conf["name"]
        # Remove stale bond if it exists for idempotency
        exec_command(module, "ip link del {}".format(name), ignore_error=True)
        exec_command(module, "ip link add {} type bond mode 802.3ad".format(name))
        for intf in conf["intfs"]:
            exec_command(module, "ip link set dev {} down".format(intf))
            exec_command(module, "ip link set dev {} master {}".format(intf, name))
            # Bring slave back up so LACP PDUs can flow and the 802.3ad
            # aggregator can form.
            exec_command(module, "ip link set dev {} up".format(intf))
        exec_command(module, "ip link set dev {} up".format(name))


def remove_bond(module, portchannel_config):
    """Remove bond interfaces and restore member ports."""
    for conf in portchannel_config:
        name = conf["name"]
        exec_command(module, "ip link set dev {} down".format(name), ignore_error=True)
        exec_command(module, "ip link del {}".format(name), ignore_error=True)
        for intf in conf["intfs"]:
            exec_command(module, "ip link set dev {} up".format(intf), ignore_error=True)


def server_netns(server):
    return server.get("netns") or "srv_{}".format(server["bond"])


def create_lacp_servers(module, servers):
    for server in servers:
        bond = server["bond"]
        exec_command(module, "ip link del {}".format(bond), ignore_error=True)
        cmd = "ip link add {} type bond mode 802.3ad lacp_rate {} miimon {} min_links {} xmit_hash_policy {}".format(
            bond, server.get("lacp_rate", "fast"), server.get("miimon", 100),
            server.get("min_links", 1), server.get("xmit_hash_policy", "layer3+4"))
        exec_command(module, cmd)
        # Set before enslaving so the bond (the LACP system ID) keeps this MAC and members adopt it
        if server.get("bond_mac"):
            exec_command(module, "ip link set dev {} address {}".format(bond, server["bond_mac"]))
        for idx in server["members"]:
            intf = "eth{}".format(idx)
            exec_command(module, "ip link set dev {} down".format(intf))
            exec_command(module, "ip link set dev {} master {}".format(intf, bond))
            exec_command(module, "ip link set dev {} up".format(intf))
        exec_command(module, "ip link set dev {} up".format(bond))

        if not server.get("ip"):
            if server.get("mac"):
                exec_command(module, "ip link set dev {} address {}".format(bond, server["mac"]))
            continue

        # Bond stays in the root netns; the server identity lives in a macvlan inside its own netns
        ns = server_netns(server)
        vlan = "mv_{}".format(bond)
        exec_command(module, "ip netns del {}".format(ns), ignore_error=True)
        exec_command(module, "ip netns add {}".format(ns))
        exec_command(module, "ip link add link {} name {} type macvlan mode bridge".format(bond, vlan))
        if server.get("mac"):
            exec_command(module, "ip link set dev {} address {}".format(vlan, server["mac"]))
        exec_command(module, "ip link set dev {} netns {}".format(vlan, ns))
        ns_exec = "ip netns exec {} ".format(ns)
        exec_command(module, ns_exec + "ip link set dev lo up")
        exec_command(module, ns_exec + "ip link set dev {} up".format(vlan))
        exec_command(module, ns_exec + "ip addr add {} dev {}".format(server["ip"], vlan))
        if server.get("gateway"):
            exec_command(module, ns_exec + "ip route add default via {}".format(server["gateway"]))


def remove_lacp_servers(module, servers):
    for server in servers:
        if server.get("ip"):
            exec_command(module, "ip netns del {}".format(server_netns(server)), ignore_error=True)
        exec_command(module, "ip link set dev {} down".format(server["bond"]), ignore_error=True)
        exec_command(module, "ip link del {}".format(server["bond"]), ignore_error=True)
        for idx in server["members"]:
            exec_command(module, "ip link set dev eth{} up".format(idx), ignore_error=True)


def setup_portchannel_conf():
    try:
        os.mkdir(portchannel_conf_path, 0o755)
    except OSError:
        pass


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(required=True, choices=['start', 'stop'], type='str'),
            portchannel_config=dict(required=True, type='dict'),
            mode=dict(required=False, choices=['teamd', 'bond'], default='teamd', type='str'),
            lacp_servers=dict(required=False, type='list', elements='dict', default=[]),
        ),
        supports_check_mode=False)
    cmd = module.params['cmd']
    mode = module.params['mode']
    portchannel_config = module.params['portchannel_config']
    lacp_servers = module.params['lacp_servers']
    parsed_config = parse_teamd_config(module, portchannel_config)

    setup_portchannel_conf()

    try:
        if cmd == 'start':
            create_lacp_servers(module, lacp_servers)
        else:
            remove_lacp_servers(module, lacp_servers)
        if mode == 'bond':
            if cmd == 'start':
                create_bond(module, parsed_config)
            elif cmd == 'stop':
                remove_bond(module, parsed_config)
        else:
            if cmd == 'start':
                create_teamd_conf(module, parsed_config)
                create_supervisor_conf(module, parsed_config)
                enable_portchannel(module, parsed_config)
            elif cmd == 'stop':
                disable_portchannel(module, parsed_config)
                remove_supervisor_conf(module, parsed_config)
                remove_teamd_conf(module, parsed_config)
    except Exception:
        module.fail_json(msg=traceback.format_exc())

    module.exit_json()


if __name__ == '__main__':
    main()
