#!/usr/bin/env python

DOCUMENTATION = '''
module:  ptf_portchannel

short_description: manage portchannel interface in PTF container
description: start/stop portchannel interface in PTF container with certain configurations

Options:
    - option-name: cmd
      description: An action string as [start|stop]
      required: True
    - option-name: portchannel_config
      description: A dict to indicate the portchannel configuration. E.G. {"PortChannel101": { "intfs": [0, 4] } }
      required: True
'''


EXAMPLES = '''
- name: Start PTF portchannel
  ptf_portchannel:
    cmd: "start"
    portchannel_config: "{{ portchannel_config }}"
'''


import os
import re
import traceback

import jinja2
from ansible.module_utils.basic import *


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
command=/usr/bin/teamd -r -t {{ name }} -f '''+ portchannel_conf_path + '''/{{ name }}.conf
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
    output = exec_command(module, cmd="supervisorctl status portchannel-%s" % name)
    m = re.search('^([\w|-]*)\s+(\w*).*$', output.decode("utf-8"))
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
            fd.write(t.render(conf))


def remove_teamd_conf(module, teamd_config):
    for conf in teamd_config:
        try:
            os.remove(os.path.join(portchannel_conf_path, "{}.conf".format(conf["name"])))
        except Exception:
            pass


def create_supervisor_conf(module, teamd_config):
    t = jinja2.Template(portchannel_supervisord_conf_tmpl)
    for conf in teamd_config:
        with open(os.path.join(portchannel_supervisord_path, "portchannel-{}.conf".format(conf["name"])), 'w') as fd:
            fd.write(t.render(conf))
    refresh_supervisord(module)


def remove_supervisor_conf(module, teamd_config):
    for conf in teamd_config:
        try:
            os.remove(os.path.join(portchannel_supervisord_path, "portchannel-{}.conf".format(conf["name"])))
        except Exception:
            pass
    refresh_supervisord(module)


def enable_portchannel(module, teamd_config):
    for conf in teamd_config:
        for intf in conf["intfs"]:
            exec_command(module, "ip link set dev {} down".format(intf))
        exec_command(module, "supervisorctl start portchannel-{}".format(conf["name"]))
        for count in range(0, 60):
            time.sleep(1)
            status = get_portchannel_status(module, conf["name"])
            if u'RUNNING' == status:
                break
        assert u'RUNNING' == status
        exec_command(module, "ip link set dev {} up".format(conf["name"]))



def disable_portchannel(module, teamd_config):
    for conf in teamd_config:
        exec_command(module, cmd="supervisorctl stop portchannel-{}".format(conf["name"]), ignore_error=True)


def setup_portchannel_conf():
    try:
        os.mkdir(portchannel_conf_path, 0755)
    except OSError:
        pass


def main():
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(required=True, choices=['start', 'stop'], type='str'),
            portchannel_config=dict(required=True, type='dict'),
        ),
        supports_check_mode=False)

    cmd = module.params['cmd']
    portchannel_config = module.params['portchannel_config']
    teamd_config = parse_teamd_config(module, portchannel_config)

    setup_portchannel_conf()

    try:
        if cmd == 'start':
            create_teamd_conf(module, teamd_config)
            create_supervisor_conf(module, teamd_config)
            enable_portchannel(module, teamd_config)
        elif cmd == 'stop':
            disable_portchannel(module, teamd_config)
            remove_supervisor_conf(module, teamd_config)
            remove_teamd_conf(module, teamd_config)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

    module.exit_json()


if __name__ == '__main__':
    main()
