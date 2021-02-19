#!/usr/bin/env python

import re

DOCUMENTATION = '''
module:  exabgp
version_added:  "1.0"

short_description: manage exabgp instance
description: start/stop exabgp instance with certain configurations

Options:
    - option-name: name
      description: exabgp instance name
      required: True
    - option-name: state
      description: instance state. [started|stopped|present|absent]
      required: True

'''

EXAMPLES = '''
- name: start exabgp
  exabgp:
    name: t1
    state: started
    router_id: 10.0.0.0
    local_ip: 10.0.0.0
    peer_ip: 10.0.0.1
    local_asn: 65534
    peer_asn: 65535
    port: 5000

- name: stop exabgp
  exabgp:
    name: t1
    state: stopped
'''

import sys
import jinja2
from ansible.module_utils.basic import *

DEFAULT_DUMP_SCRIPT = "/usr/share/exabgp/dump.py"
DEFAULT_BGP_LISTEN_PORT = 179

dump_py = '''\
#!/usr/bin/env python

from sys import stdin
import json
import os
import sys

while True:
    try:
        line = stdin.readline()
        obj = json.loads(line)
        f = open("/tmp/exabgp-" + obj["neighbor"]["address"]["local"], "a")
        print >> f, line,
        f.close()
    except:
        continue
'''

http_api_py = '''\
from flask import Flask, request
import sys

#Disable banner msg from app.run, or the output might be caught by exabgp and run as command
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None

app = Flask(__name__)

# Setup a command route to listen for prefix advertisements
@app.route('/', methods=['POST'])
def run_command():
    if request.form.has_key('commands'):
        cmds = request.form['commands'].split(';')
    else:
        cmds = [ request.form['command'] ]
    for cmd in cmds:
        sys.stdout.write("%s\\n" % cmd)
    sys.stdout.flush()
    return "OK\\n"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=sys.argv[1])
'''

exabgp_conf_tmpl = '''\
group exabgp {
    process dump {
        encoder json;
        receive {
            parsed;
            update;
        }
        run /usr/bin/python {{ dump_script }};
    }

    process http-api {
        run /usr/bin/python /usr/share/exabgp/http_api.py {{ port }};
    }

    neighbor {{ peer_ip }} {
        router-id {{ router_id }};
        local-address {{ local_ip }};
        peer-as {{ peer_asn }};
        local-as {{ local_asn }};
        auto-flush {{ auto_flush }};
        group-updates {{ group_updates }};
        {%- if passive %}
        passive;
        listen {{ listen_port }};
        {%- endif %}
    }
}
'''

exabgp_supervisord_conf_tmpl = '''\
[program:exabgp-{{ name }}]
command=/usr/local/bin/exabgp /etc/exabgp/{{ name }}.conf
stdout_logfile=/tmp/exabgp-{{ name }}.out.log
stderr_logfile=/tmp/exabgp-{{ name }}.err.log
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

def get_exabgp_status(module, name):
    output = exec_command(module, cmd="supervisorctl status exabgp-%s" % name)
    m = re.search('^([\w|-]*)\s+(\w*).*$', output.decode("utf-8"))
    return m.group(2)

def refresh_supervisord(module):
    exec_command(module, cmd="supervisorctl reread", ignore_error=True)
    exec_command(module, cmd="supervisorctl update", ignore_error=True)

def start_exabgp(module, name):
    refresh_supervisord(module)
    exec_command(module, cmd="supervisorctl start exabgp-%s" % name)

    for count in range(0, 60):
        time.sleep(1)
        status = get_exabgp_status(module, name)
        if u'RUNNING' == status:
            break
    assert u'RUNNING' == status

def restart_exabgp(module, name):
    refresh_supervisord(module)
    exec_command(module, cmd="supervisorctl restart exabgp-%s" % name)

    for count in range(0, 60):
        time.sleep(1)
        status = get_exabgp_status(module, name)
        if u'RUNNING' == status:
            break
    assert u'RUNNING' == status

def stop_exabgp(module, name):
    exec_command(module, cmd="supervisorctl stop exabgp-%s" % name, ignore_error=True)

def setup_exabgp_conf(name, router_id, local_ip, peer_ip, local_asn, peer_asn, port, auto_flush=True, group_updates=True, dump_script=DEFAULT_DUMP_SCRIPT, passive=False):
    try:
        os.mkdir("/etc/exabgp", 0755)
    except OSError:
        pass

    t = jinja2.Template(exabgp_conf_tmpl)
    data = t.render(name=name, \
                    router_id=router_id, \
                    local_ip=local_ip, \
                    peer_ip=peer_ip, \
                    local_asn=local_asn, \
                    peer_asn=peer_asn, \
                    port=port, \
                    auto_flush=auto_flush, \
                    group_updates=group_updates, \
                    dump_script=dump_script, passive=passive,
                    listen_port=DEFAULT_BGP_LISTEN_PORT)
    with open("/etc/exabgp/%s.conf" % name, 'w') as out_file:
        out_file.write(data)

def remove_exabgp_conf(name):
    try:
        os.remove("/etc/exabgp/%s.conf" % name)
    except Exception:
        pass


def setup_exabgp_supervisord_conf(name):
    t = jinja2.Template(exabgp_supervisord_conf_tmpl)
    data = t.render(name=name)
    with open("/etc/supervisor/conf.d/exabgp-%s.conf" % name, 'w') as out_file:
        out_file.write(data)

def remove_exabgp_supervisord_conf(name):
    try:
        os.remove("/etc/supervisor/conf.d/exabgp-%s.conf" % name)
    except Exception:
        pass

def setup_exabgp_processor(use_default_dump_script):
    try:
        os.mkdir("/usr/share/exabgp", 0755)
    except OSError:
        pass
    if use_default_dump_script:
        with open(DEFAULT_DUMP_SCRIPT, 'w') as out_file:
            out_file.write(dump_py)
    with open("/usr/share/exabgp/http_api.py", 'w') as out_file:
        out_file.write(http_api_py)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True, type='str'),
            state=dict(required=True, choices=['started', 'restarted', 'stopped', 'present', 'absent', 'status'], type='str'),
            router_id=dict(required=False, type='str'),
            local_ip=dict(required=False, type='str'),
            peer_ip=dict(required=False, type='str'),
            local_asn=dict(required=False, type='int'),
            peer_asn=dict(required=False, type='int'),
            port=dict(required=False, type='int', default=5000),
            dump_script=dict(required=False, type='str', default=DEFAULT_DUMP_SCRIPT),
            passive=dict(required=False, type='bool', default=False)
        ),
        supports_check_mode=False)

    name  = module.params['name']
    state = module.params['state']
    router_id = module.params['router_id']
    local_ip  = module.params['local_ip']
    peer_ip   = module.params['peer_ip']
    local_asn = module.params['local_asn']
    peer_asn  = module.params['peer_asn']
    port      = module.params['port']
    dump_script = module.params['dump_script']
    passive = module.params['passive']

    setup_exabgp_processor(dump_script==DEFAULT_DUMP_SCRIPT)

    result = {}
    try:
        if state == 'started':
            setup_exabgp_conf(name, router_id, local_ip, peer_ip, local_asn, peer_asn, port, dump_script=dump_script, passive=passive)
            setup_exabgp_supervisord_conf(name)
            start_exabgp(module, name)
        elif state == 'restarted':
            setup_exabgp_conf(name, router_id, local_ip, peer_ip, local_asn, peer_asn, port, dump_script=dump_script, passive=passive)
            setup_exabgp_supervisord_conf(name)
            restart_exabgp(module, name)
        elif state == 'present':
            setup_exabgp_conf(name, router_id, local_ip, peer_ip, local_asn, peer_asn, port, dump_script=dump_script, passive=passive)
            setup_exabgp_supervisord_conf(name)
            refresh_supervisord(module)
        elif state == 'stopped':
            stop_exabgp(module, name)
        elif state == 'absent':
            stop_exabgp(module, name)
            remove_exabgp_supervisord_conf(name)
            remove_exabgp_conf(name)
            refresh_supervisord(module)
        elif state == 'status':
            status = get_exabgp_status(module, name)
            result = {'status' : status}
    except:
        err = str(sys.exc_info())
        module.fail_json(msg="Error: %s" % err)

    module.exit_json(**result)

if __name__ == '__main__':
    main()
