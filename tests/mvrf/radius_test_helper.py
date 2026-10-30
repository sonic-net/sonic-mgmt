"""Private PTF FreeRADIUS/SSH helper. Never edits system RADIUS configuration.

The controller copies this file into a root-only, per-case PTF directory.
FreeRADIUS 3.x, its dictionaries/modules, and Paramiko must already be installed.
No package installation, service restart, production user, or shared port is
used. Output deliberately excludes passwords, shared keys and raw logs.
"""
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time


# This code runs on the DUT beside the existing private gap snapshot. Resource
# registration precedes authentication, so the gap watchdog can clean users too.
DUT_RADIUS_SCRIPT = r'''
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent

def local_users():
    return {r.split(':')[0]: r.split(':') for r in Path('/etc/passwd').read_text().splitlines()}

def run(argv):
    with (root / 'radius-operations.log').open('a') as output:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, timeout=30)
    if result.returncode:
        raise RuntimeError('Owned RADIUS user cleanup failed')

def cleanup():
    state = json.loads((root / 'snapshot.json').read_text())
    for name in state.get('radius_users', []):
        if not re.fullmatch(r'mvrfr_[0-9a-f]{12}_[a-z0-9]+', name):
            raise RuntimeError('Unexpected owned username')
        row = local_users().get(name)
        home = Path('/home') / name
        cache = Path('/var/cache/radius/user') / name
        if row:
            if row[5] != str(home) or int(row[2]) <= 1000 or home.is_symlink():
                raise RuntimeError('Refusing unsafe user cleanup')
            run(['userdel', '--remove', name])
        # These exact paths were absent when this unique user was registered.
        for path in (home, cache):
            if path.is_symlink():
                raise RuntimeError('Refusing symlink cleanup')
            if path.exists():
                shutil.rmtree(str(path))
        if name in local_users():
            raise RuntimeError('Owned RADIUS user remained after cleanup')
        groups = {r.split(':')[0]: r.split(':') for r in Path('/etc/group').read_text().splitlines()}
        if name in groups:
            if len(groups[name]) != 4 or groups[name][3]:
                raise RuntimeError('Owned private group gained other members; refusing removal')
            run(['groupdel', name])

def action(mode, args):
    if mode == 'cleanup':
        cleanup()
        return {}
    if mode == 'package':
        result = subprocess.run(['dpkg-query', '-W', '-f=${Status}\n${Version}', 'libpam-radius-auth'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            return {'installed': False}
        rows = result.stdout.splitlines()
        listing = subprocess.run(['dpkg', '-L', 'libpam-radius-auth'],
                                 capture_output=True, text=True, timeout=10)
        modules = [Path(p) for p in listing.stdout.splitlines()
                   if p.startswith('/usr/lib/') or p.startswith('/lib/')]
        modules = [p for p in modules if p.name == 'pam_radius_auth.so' and p.is_file()]
        return {'installed': rows[0] == 'install ok installed', 'version': rows[-1],
                'modules': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                             'requires_message_authenticator': b'require_message_authenticator' in p.read_bytes()}
                            for p in modules]}
    if mode == 'pam-file':
        address = str(ipaddress.IPv4Address(args[0]))
        path = Path('/etc/pam_radius_auth.d') / (address + '_1812.conf')
        return {'exists': path.is_file(),
                'digest': hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None}
    if mode == 'identity':
        name = args[0]
        if not re.fullmatch(r'mvrfr_[0-9a-f]{12}_[a-z0-9]+', name):
            raise RuntimeError('Unexpected test identity')
        row = local_users().get(name)
        path = Path('/var/cache/radius/user') / name / 'Management-Privilege-Level'
        shadow = {r.split(':')[0]: r.split(':')[1] for r in Path('/etc/shadow').read_text().splitlines()}
        return {'exists': row is not None, 'level': int(path.read_text().strip()) if path.is_file() else None,
                'local_password_locked': shadow.get(name, '').startswith(('!', '*'))}
    config = json.loads((root / 'radius-input.json').read_text())
    if mode == 'ready':
        from swsscommon.swsscommon import ConfigDBConnector
        db = ConfigDBConnector()
        db.connect()
        row = db.get_entry('RADIUS_SERVER', config['server']) or {}
        path = Path('/etc/pam_radius_auth.d') / (config['server'] + '_' + str(config['port']) + '.conf')
        pam = Path('/etc/pam.d/common-auth-sonic')
        if not path.is_file() or not pam.is_file():
            return {'ready': False}
        fields = [line.split() for line in path.read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith('#')]
        expected = row.get('vrf')
        endpoints = ('[{}]:{}'.format(config['server'], config['port']),
                     '{}:{}'.format(config['server'], config['port']))
        matching = any(len(f) >= 3 and f[0] in endpoints
                       and f[1] == config['secret'] and (f[-1] == expected if expected else len(f) == 3)
                       for f in fields)
        auth = db.get_entry('AAA', 'authentication') or {}
        return {'ready': matching and str(path) in pam.read_text()
                and auth.get('login') == 'radius,local'
                and str(auth.get('failthrough')).lower() == 'true'
                and 'radius' in Path('/etc/nsswitch.conf').read_text()}
    if mode == 'register':
        names = [u['name'] for u in config['users'].values()]
        existing = local_users()
        groups = {r.split(':')[0] for r in Path('/etc/group').read_text().splitlines()}
        for name in names:
            if not re.fullmatch(r'mvrfr_[0-9a-f]{12}_[a-z0-9]+', name):
                raise RuntimeError('Unexpected test username')
            if (name in existing or name in groups or os.path.lexists('/home/' + name)
                    or os.path.lexists('/var/cache/radius/user/' + name)):
                raise RuntimeError('Test identity already exists; refusing mutation')
        state = json.loads((root / 'snapshot.json').read_text())
        state['radius_users'] = names
        temporary = root / 'snapshot.json.tmp'
        temporary.write_text(json.dumps(state, sort_keys=True))
        os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(root / 'snapshot.json'))
        return {}
    if mode == 'configure':
        from swsscommon.swsscommon import ConfigDBConnector
        db = ConfigDBConnector()
        db.connect()
        # Fixture input only. Migration assertions never call this a second time.
        for key in db.get_table('RADIUS_SERVER'):
            db.set_entry('RADIUS_SERVER', key, None)
        for key in db.get_table('RADIUS'):
            db.set_entry('RADIUS', key, None)
        row = {'passkey': config['secret'], 'auth_port': str(config['port']),
               'auth_type': 'pap', 'timeout': '3', 'retransmit': '1', 'priority': '1'}
        if args[0] == 'mgmt':
            row['vrf'] = 'mgmt'
        elif args[0] != 'default':
            raise RuntimeError('Unexpected fixture VRF')
        db.set_entry('RADIUS_SERVER', config['server'], row)
        db.set_entry('AAA', 'authorization', {'login': 'local'})
        db.set_entry('AAA', 'accounting', {'login': 'disable'})
        # Local fallback protects the controller; test passwords are random and
        # no local password is set for any test identity. Require server evidence.
        db.set_entry('AAA', 'authentication', {'login': 'radius,local', 'failthrough': 'True'})
        return {}
    raise RuntimeError('Unknown RADIUS helper action')

if __name__ == '__main__':
    os.umask(0o077)
    try:
        print(json.dumps(action(sys.argv[1], sys.argv[2:])))
    except Exception as error:
        print('RADIUS DUT helper failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
'''


def radius_config(root, config, port, libdir):
    """Use PAP password verification, not unconditional Access-Accept."""
    address = str(ipaddress.IPv4Address(config['server']))
    client = str(ipaddress.IPv4Address(config['dut']))
    root = str(root)
    if not re.fullmatch(r'/tmp/mvrf-radius\.[A-Za-z0-9]+', root):
        raise ValueError('Unexpected private server directory')
    if not re.fullmatch(r'[0-9a-f]{48}', config['secret']):
        raise ValueError('Invalid generated secret')
    users = []
    for index, (profile, user) in enumerate(sorted(config['users'].items())):
        if not re.fullmatch(r'mvrfr_[0-9a-f]{12}_[a-z0-9]+', user['name']):
            raise ValueError('Unexpected test username')
        if not re.fullmatch(r'[0-9a-f]{48}', user['password']):
            raise ValueError('Invalid generated password')
        level = int(user['level'])
        if level not in (1, 15):
            raise ValueError('Unexpected test privilege')
        attribute = ('Cisco-AVPair := "shell:priv-lvl={}"'.format(level)
                     if profile.startswith('cisco') else 'Management-Privilege-Level := {}'.format(level))
        users.append('''{branch} (&User-Name == "{name}") {{
            update control {{
                Cleartext-Password := "{password}"
            }}
            update reply {{
                {attribute}
            }}
        }}'''.format(branch='if' if index == 0 else 'elsif', attribute=attribute, **user))
    # Each row contains only identity/routing/outcome attributes, never passwords.
    return '''name = radiusd
prefix = /usr
raddbdir = {root}
confdir = {root}
run_dir = {root}
logdir = {root}
libdir = {libdir}
pidfile = {root}/radiusd.pid
max_request_time = 10
cleanup_delay = 2
max_requests = 256
hostname_lookups = no
log {{
    destination = files
    file = {root}/radius.log
    auth = no
    auth_badpass = no
    auth_goodpass = no
}}
security {{
    allow_core_dumps = no
}}
client dut {{
    ipaddr = {client}/32
    secret = {secret}
}}
modules {{
    always reject {{
        rcode = reject
    }}
    pap {{
        normalise = yes
    }}
    linelog safe_auth {{
        filename = {root}/events
        permissions = 0600
        format = "%{{User-Name}}|%{{NAS-IP-Address}}|%{{reply:Packet-Type}}|%{{Packet-Src-IP-Address}}"
    }}
}}
server mvrf {{
    listen {{
        type = auth
        ipaddr = {address}
        port = {port}
    }}
    authorize {{
        {users}
        else {{
            reject
        }}
        pap
    }}
    authenticate {{
        Auth-Type PAP {{
            pap
        }}
    }}
    post-auth {{
        update reply {{
            Message-Authenticator := 0x00000000000000000000000000000000
        }}
        safe_auth
        Post-Auth-Type REJECT {{
            update reply {{
                Message-Authenticator := 0x00000000000000000000000000000000
            }}
            safe_auth
        }}
    }}
}}
'''.format(root=root, libdir=libdir, client=client, address=address,
           port=port, users='\n        '.join(users), secret=config['secret'])


def prerequisites():
    import importlib.util
    binary = shutil.which('freeradius') or shutil.which('radiusd')
    libraries = [p for pattern in ('/usr/lib/freeradius/rlm_pap.so',
                                   '/usr/lib/*/freeradius/rlm_pap.so') for p in glob.glob(pattern)]
    if not binary or not libraries or not Path('/usr/share/freeradius/dictionary').is_file():
        return {'prerequisite': 'PTF needs FreeRADIUS 3.x server, PAP/linelog/always modules and dictionaries'}
    version = subprocess.run([binary, '-v'], capture_output=True, text=True, timeout=10)
    if not re.search(r'Version\s+3\.', version.stdout + version.stderr):
        return {'prerequisite': 'This isolated fixture requires FreeRADIUS 3.x'}
    libdir = str(Path(libraries[0]).parent)
    for module in ('rlm_linelog.so', 'rlm_always.so'):
        if not Path(libdir, module).is_file():
            return {'prerequisite': 'PTF needs FreeRADIUS module ' + module}
    if importlib.util.find_spec('paramiko') is None:
        return {'prerequisite': 'PTF needs Python 3 Paramiko'}
    return {'binary': binary, 'libdir': libdir}


def owns_listener(pid, address, port):
    """Require the actual server PID to own this bound socket, not another daemon."""
    inode = set()
    for fd in Path('/proc/{}/fd'.format(pid)).glob('*'):
        try:
            match = re.fullmatch(r'socket:\[(\d+)\]', os.readlink(str(fd)))
            if match:
                inode.add(match.group(1))
        except FileNotFoundError:
            pass
    local = '{:08X}:{:04X}'.format(int.from_bytes(socket.inet_aton(address), 'little'), port)
    return any(len(row) > 9 and row[1] == local and row[9] in inode
               for row in (line.split() for line in Path('/proc/net/udp').read_text().splitlines()[1:]))


def serve(root):
    settings = json.loads((root / 'server.json').read_text())
    with (root / 'server.log').open('a') as output:
        process = subprocess.Popen([settings['binary'], '-f', '-s', '-d', str(root),
                                    '-D', '/usr/share/freeradius'],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        (root / 'child.pid').write_text(str(process.pid))
        try:
            # Independent limit: a lost controller must not leave a test server forever.
            process.wait(timeout=settings['lifetime'])
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def start(root, config):
    found = prerequisites()
    if 'prerequisite' in found:
        return found
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((config['server'], 0))
        port = probe.getsockname()[1]
    (root / 'radiusd.conf').write_text(radius_config(root, config, port, found['libdir']))
    (root / 'dictionary').write_text('# No private dictionary additions.\n')
    lifetime = int(config.get('lifetime', 1200))
    if not 60 <= lifetime <= 21600:
        raise ValueError('Server lifetime must be bounded')
    settings = dict(found, port=port, lifetime=lifetime)
    (root / 'server.json').write_text(json.dumps(settings))
    with (root / 'syntax.log').open('w') as output:
        check = subprocess.run([found['binary'], '-C', '-d', str(root), '-D', '/usr/share/freeradius'],
                               stdout=output, stderr=subprocess.STDOUT, timeout=20)
    if check.returncode:
        raise RuntimeError('Private FreeRADIUS syntax check failed; inspect private syntax.log')
    with (root / 'launcher.log').open('a') as output:
        process = subprocess.Popen([sys.executable, str(root / 'probe.py'), 'serve'],
                                   start_new_session=True, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
    (root / 'launcher.pid').write_text(str(process.pid))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and process.poll() is None:
        if (root / 'child.pid').exists() and owns_listener(
                int((root / 'child.pid').read_text()), config['server'], port):
            return {'port': port}
        time.sleep(.2)
    raise RuntimeError('Private FreeRADIUS did not bind its socket; inspect private server.log')


def stop(root):
    pidfile = root / 'launcher.pid'
    if not pidfile.exists():
        return {}
    pid = int(pidfile.read_text())
    proc = Path('/proc/{}'.format(pid))
    if not proc.exists():
        return {}
    args = (proc / 'cmdline').read_bytes().split(b'\0')
    if str(root / 'probe.py').encode() not in args or b'serve' not in args or os.getpgid(pid) != pid:
        raise RuntimeError('Refusing to stop a process not owned by this fixture')
    os.killpg(pid, signal.SIGTERM)
    child = Path('/proc') / (root / 'child.pid').read_text().strip() if (root / 'child.pid').exists() else None
    for _ in range(50):
        parent_done = not proc.exists() or (proc / 'stat').read_text().split()[2] == 'Z'
        child_done = child is None or not child.exists() or (child / 'stat').read_text().split()[2] == 'Z'
        if parent_done and child_done:
            return {}
        time.sleep(.1)
    raise RuntimeError('Owned FreeRADIUS launcher did not stop; retaining private files')


def accepted_events(text, username, source):
    rows = []
    for line in text.splitlines():
        fields = line.split('|')
        if len(fields) == 4 and fields[0] == username and fields[2] == 'Access-Accept' and fields[3] == source:
            rows.append({'nas_ip': fields[1], 'source': fields[3]})
    return rows


def login(root, config, profile):
    import paramiko
    user = config['users'][profile]
    events_path = root / 'events'
    offset = events_path.stat().st_size if events_path.exists() else 0

    class ExpectedHostKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            if [key.get_name(), key.get_base64()] not in config['host_keys']:
                raise RuntimeError('DUT SSH host key mismatch')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(ExpectedHostKey())
    try:
        client.connect(config['dut'], username=user['name'], password=user['password'],
                       look_for_keys=False, allow_agent=False, timeout=15,
                       auth_timeout=30, banner_timeout=15)
        _, stdout, stderr = client.exec_command(
            'python3 -c \'import json,os; print(json.dumps({"uid":os.getuid(),'
            '"groups":sorted(g for g in os.getgroups() if g != os.getgid())}))\'', timeout=15)
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError('RADIUS-authenticated SSH command failed')
        identity = json.loads(stdout.read().decode())
    finally:
        client.close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if events_path.exists():
            with events_path.open() as log:
                log.seek(offset)
                accepted = accepted_events(log.read(), user['name'], config['dut'])
            if accepted:
                return dict(identity, accepts=accepted)
        time.sleep(.2)
    raise RuntimeError('SSH login had no matching fresh RADIUS Access-Accept record')


def main():
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    action = sys.argv[1]
    try:
        if action == 'serve':
            serve(root)
            return
        if action == 'available':
            value = prerequisites()
        elif action == 'stop':
            value = stop(root)
        else:
            config = json.loads((root / 'input.json').read_text())
            value = start(root, config) if action == 'start' else login(root, config, action)
        print(json.dumps({'ok': True, 'result': value}))
    except Exception as error:
        # No traceback may echo the configuration or test passwords to pytest.
        print(json.dumps({'ok': False, 'error': type(error).__name__}))
        sys.exit(1)


if __name__ == '__main__':
    main()
