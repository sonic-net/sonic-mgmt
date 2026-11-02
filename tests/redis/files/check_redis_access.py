#!/usr/bin/env python3
"""Check local Redis access on a DUT. Run as root; output contains no password."""
import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import uuid

import redis

POLICY = Path('/run/redis-auth/local.json')
SECRET = Path('/run/redis-auth/local-system/writer.secret')
CONFIG = Path('/var/run/redis/sonic-db/database_config.json')
INTENT = Path('/etc/sonic/redis-auth.json')
ASIC_CONF = None  # Tests can supply a fixture; production uses host-aware lookup.
VALUE = b'redis-access-original'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def discover_databases():
    """Enumerate expected namespaces independently of the generated auth policy."""
    count = 1
    path = ASIC_CONF
    if path is None:
        from sonic_py_common import device_info
        discovered = device_info.get_asic_conf_file_path()
        path = Path(discovered) if discovered else None
    if path is not None and os.path.lexists(path):
        values = dict(line.strip().split('=', 1) for line in path.read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith('#'))
        count = int(values['NUM_ASIC'])
    require(count > 0, 'Invalid ASIC count')
    ids = [''] + ([str(index) for index in range(count)] if count > 1 else [])
    expected = [{'include': '../../redis/sonic-db/database_config.json'}]
    expected += [{'namespace': 'asic' + number,
                  'include': '../../redis' + number + '/sonic-db/database_config.json'}
                 for number in ids if number]
    global_path = CONFIG.parent / 'database_global.json'
    if count > 1 or global_path.exists():
        require(json.loads(global_path.read_text())['INCLUDES'] == expected,
                'Database namespace includes disagree with the platform ASIC count')
    maps, local = {}, {}
    for number in ids:
        path = CONFIG if not number else CONFIG.parents[2] / ('redis' + number) / 'sonic-db/database_config.json'
        metadata = json.loads(path.read_text())
        namespace = 'asic' + number if number else ''
        require(bool(metadata['INSTANCES']), 'Empty local database map')
        for name, instance in metadata['INSTANCES'].items():
            require(name != 'remote_redis' and not instance.get('database_type'), 'Remote database is outside this check')
            require(Path(instance['unix_socket_path']).parent == path.parents[1], 'Socket belongs to another namespace')
            require(number or instance['hostname'] in ('127.0.0.1', '::1', 'localhost'), 'Nonlocal host database')
            identity = namespace + '/' + name if namespace else name
            local[identity] = dict(instance, namespace=namespace, container='database' + number)
        maps[namespace] = metadata
    require(len({item['unix_socket_path'] for item in local.values()}) == len(local), 'Duplicate local socket')
    return maps, local


# Execute inside each database container so /proc/net and Redis PIDs describe the
# correct network/PID namespace. Count actual servers, not just config records.
CENSUS = r"""
import json
from pathlib import Path
root = Path('/proc')
tcp, unix = {}, {}
for protocol in ('tcp', 'tcp6'):
    for line in (root / 'net' / protocol).read_text().splitlines()[1:]:
        fields = line.split()
        if fields[3] == '0A':
            tcp[fields[9]] = int(fields[1].rsplit(':', 1)[1], 16)
for line in (root / 'net/unix').read_text().splitlines()[1:]:
    fields = line.split()
    if len(fields) == 8 and fields[3] == '00010000':
        unix[fields[6]] = fields[7]
result = []
for path in root.glob('[0-9]*'):
    try:
        if (path / 'comm').read_text().strip() != 'redis-server':
            continue
        inodes = set()
        for fd in (path / 'fd').iterdir():
            try:
                target = fd.readlink().as_posix()
            except FileNotFoundError:
                continue
            if target.startswith('socket:['):
                inodes.add(target[8:-1])
        result.append(dict(pid=int(path.name), sockets=sorted(unix[item] for item in inodes if item in unix),
                           tcp_ports=sorted(tcp[item] for item in inodes if item in tcp)))
    except FileNotFoundError:
        continue
print(json.dumps(result))
"""


def verify_census(local):
    containers = {item['container'] for item in local.values()}
    checked = 0
    for container in sorted(containers):
        result = execute(['docker', 'exec', '--user', 'redis', container, 'python3', '-c', CENSUS])
        require(result[0] == 0, 'Could not enumerate Redis processes in ' + container)
        actual = json.loads(result[1])
        expected = {item['unix_socket_path']: item for item in local.values() if item['container'] == container}
        require(len(actual) == len(expected), 'Redis process count differs from configured inventory in ' + container)
        seen = set()
        for process in actual:
            require(len(process['sockets']) == 1, 'Redis has missing or unexpected listening Unix sockets')
            socket = process['sockets'][0]
            require(socket in expected and socket not in seen, 'Uninventoried Redis process in ' + container)
            ports = process['tcp_ports']
            expected_port = expected[socket]['port']
            require((not ports) if expected_port == 0 else (ports and set(ports) == {expected_port}),
                    'Actual Redis TCP listeners disagree with the database map')
            seen.add(socket)
            checked += 1
    return checked


def protection_scope(local, selected, *, allow_tcp_exceptions=False, intent=None):
    """Require full protection unless the run explicitly accepts configured exceptions."""
    exceptions = set()
    if allow_tcp_exceptions:
        require(isinstance(intent, dict) and intent.get('mode') == 'enforce',
                'Mixed-mode validation requires the common enforcement setting')
        names = intent.get('tcp_exceptions')
        require(isinstance(names, list) and names and all(isinstance(name, str) for name in names),
                'Mixed-mode validation requires explicit TCP exception names')
        exceptions = set(names)
        require(len(exceptions) == len(names) and exceptions <= {name.split('/')[-1] for name in local}, 'Invalid TCP exceptions')
    expected = {item['unix_socket_path'] for name, item in local.items() if name.split('/')[-1] not in exceptions}
    require(expected and set(selected) == expected,
            'Prepared policy does not protect exactly the required local Redis processes')
    require(all(item['port'] > 0 if name.split('/')[-1] in exceptions else item['port'] == 0
                for name, item in local.items()), 'Redis TCP listeners disagree with the protection setting')
    return exceptions


def execute(args, data=None, ordinary=False):
    options = {}
    if ordinary:
        user = pwd.getpwnam('nobody')
        options = dict(user=user.pw_uid, group=user.pw_gid, extra_groups=[])
    result = subprocess.run(args, input=data, capture_output=True, timeout=20, close_fds=True, **options)
    return result.returncode, result.stdout, result.stderr


def denied(call):
    try:
        call()
    except redis.exceptions.NoPermissionError:
        return
    except redis.exceptions.ResponseError as error:
        require('NOPERM' in str(error) or 'ACL failure in script' in str(error),
                'Write failed for a reason other than Redis permissions: ' + str(error))
        return
    raise AssertionError('An ordinary Redis user completed a write')


def reader_checks(plan):
    require(os.geteuid() != 0, 'Reader subprocess still has root access')
    require(os.getegid() == pwd.getpwnam('nobody').pw_gid and not os.getgroups(),
            'Reader subprocess must have only its private primary group')
    require(not os.access(SECRET, os.R_OK), 'Ordinary user can read the writer password')
    from swsscommon import swsscommon
    checked = 0
    for process in plan:
        value = process['value'].encode()
        client = redis.Redis(unix_socket_path=process['socket'], single_connection_client=True)
        try:
            read_script = client.register_script('return redis.call("GET", KEYS[1])')
            for database in range(process['count']):
                client.execute_command('SELECT', database)
                key = process['key']
                require(client.get(key) == value, 'Ordinary GET failed')
                require(client.exists(key) == 1, 'Ordinary EXISTS failed')
                require(client.hgetall(key + ':hash') == {b'field': value}, 'Ordinary HGETALL failed')
                require(key.encode() in client.keys(key), 'Ordinary KEYS failed')
                require(key.encode() in list(client.scan_iter(match=key)), 'Ordinary SCAN failed')
                with client.pipeline(transaction=True) as pipe:
                    pipe.execute_command('SELECT', database)
                    pipe.get(key)
                    require(pipe.execute()[-1] == value, 'Read transaction failed')
                require(client.eval('return redis.call("GET", KEYS[1])', 1, key) == value,
                        'Read EVAL failed')
                require(read_script(keys=[key]) == value, 'Read EVALSHA failed')
                denied(lambda: client.set(key, 'forbidden'))
                denied(lambda: client.hset(key + ':hash', 'field', 'forbidden'))
                denied(lambda: client.eval('return redis.call("SET", KEYS[1], ARGV[1])',
                                           1, key, 'forbidden'))
                with client.pipeline(transaction=True) as pipe:
                    pipe.execute_command('SELECT', database)
                    pipe.set(key, 'forbidden')
                    denied(pipe.execute)
                native = swsscommon.DBConnector(database, process['socket'], 1000)
                require(native.exists(key), 'Ordinary native connector read failed')
                try:
                    native.set(key, 'forbidden')
                except RuntimeError as error:
                    require('NOPERM' in str(error), 'Native write failed for a reason other than Redis permissions')
                else:
                    raise AssertionError('Ordinary native connector wrote to Redis')
                require(client.get(key) == value and client.hget(key + ':hash', 'field') == value,
                        'A denied write changed data')
                checked += 1
        finally:
            client.close()
    return checked


def resp(*args):
    encoded = [arg.encode() for arg in args]
    return b'*%d\r\n' % len(encoded) + b''.join(b'$%d\r\n' % len(arg) + arg + b'\r\n' for arg in encoded)


def cli_checks(metadata, processes, controls, prefix, preflight, namespace=''):
    def check_raw_write(result, client, key, expected, protected, description):
        if protected:
            require(b'NOPERM' in result[1] + result[2] and client.get(key) is None,
                    'Unauthenticated raw CLI write was not denied: ' + description)
        else:
            require(result[0] == 0 and b'NOPERM' not in result[1] + result[2]
                    and client.get(key) == expected,
                    'Legacy raw CLI write failed: ' + description)

    checked = 0
    ns_args = ['-n', namespace] if namespace else []
    for name, database in metadata['DATABASES'].items():
        process = processes[database['instance']]
        client = controls[database['instance']]
        client.execute_command('SELECT', database['id'])
        value = process['value'].encode()
        transport = ['-s'] if process['protected'] else []
        args = ['sonic-db-cli'] + ns_args + transport + [name]
        result = execute(args + ['SET', prefix + ':cli', value.decode(), 'EX', '300'])
        require(result[0] == 0 and client.get(prefix + ':cli') == value, 'Admin sonic-db-cli write failed: ' + name)
        result = execute(['sonic-db-cli'] + ns_args + transport + ['-j', name, 'HGETALL', prefix + ':hash'])
        require(result[0] == 0 and json.loads(result[1]) == {'field': value.decode()},
                'Structured JSON display failed: ' + name)
        endpoint = (['-s', process['socket']] if process['protected'] else
                    ['-h', process['host'], '-p', str(process['port'])])
        # The host wrapper enters only the host database container. Execute the
        # stock CLI where the selected namespace's socket is actually mounted.
        raw = ['docker', 'exec', '-i', process['container'], 'redis-cli'] + endpoint + ['-n', str(database['id'])]
        result = execute(raw + ['GET', prefix])
        require(result[0] == 0 and result[1].strip() == value, 'Admin raw CLI read failed: ' + name)
        if not preflight and process['protected']:
            result = execute(args + ['GET', prefix], ordinary=True)
            require(result[0] == 0 and result[1].strip() == value, 'Ordinary structured CLI read failed: ' + name)
            result = execute(['sonic-db-cli'] + ns_args + ['-s', '-j', name, 'HGETALL', prefix + ':hash'], ordinary=True)
            require(result[0] == 0 and json.loads(result[1]) == {'field': value.decode()},
                    'Ordinary structured JSON display failed: ' + name)
            result = execute(args + ['SET', prefix, 'forbidden'], ordinary=True)
            require(b'NOPERM' in result[1] + result[2] and client.get(prefix) == value,
                    'Structured CLI did not prove Redis write denial: ' + name)
            ordinary_raw = ['docker', 'exec', '--user', '65534:65534', process['container'],
                            'redis-cli', '-s', process['socket'], '-n', str(database['id'])]
            result = execute(ordinary_raw + ['GET', prefix])
            require(result[0] == 0 and result[1].strip() == value, 'Ordinary raw CLI read failed: ' + name)
            result = execute(ordinary_raw + ['SET', prefix, 'forbidden'])
            require(b'NOPERM' in result[1] + result[2] and client.get(prefix) == value,
                    'Raw CLI did not prove Redis write denial: ' + name)
        checked += 1
    for name, process in processes.items():
        value = process['value'].encode()
        client = controls[name]
        client.execute_command('SELECT', 0)
        endpoint = (['-s', process['socket']] if process['protected'] else
                    ['-h', process['host'], '-p', str(process['port'])])
        raw = ['docker', 'exec', '-i', process['container'], 'redis-cli'] + endpoint + ['-n', '0']
        result = execute(raw, data=('SET ' + prefix + ':stdin stdin-value\nGET ' + prefix + ':stdin\n').encode())
        check_raw_write(result, client, prefix + ':stdin', b'stdin-value',
                        process['protected'], 'stdin: ' + name)
        if not process['protected']:
            require(b'stdin-value' in result[1], 'Legacy raw CLI stdin read failed: ' + name)
        payload = b'binary \x00\xff\nvalue'
        result = execute(raw + ['-x', 'SET', prefix + ':binary'], data=payload)
        check_raw_write(result, client, prefix + ':binary', payload,
                        process['protected'], 'binary stdin: ' + name)
        result = execute(raw + ['--pipe'], data=resp('SET', prefix + ':pipe', 'pipe-value'))
        check_raw_write(result, client, prefix + ':pipe', b'pipe-value',
                        process['protected'], 'pipeline: ' + name)
        if not preflight and process['protected']:
            ordinary_raw = ['docker', 'exec', '-i', '--user', '65534:65534', process['container'],
                            'redis-cli', '-s', process['socket'], '-n', '0', '--pipe']
            result = execute(ordinary_raw, data=resp('SET', prefix, 'forbidden'))
            require(b'NOPERM' in result[1] + result[2] and client.get(prefix) == value,
                    'Raw pipeline did not prove Redis write denial: ' + name)
    return checked


def main(preflight, allow_tcp_exceptions=False):
    require(os.geteuid() == 0, 'Run the acceptance check as root')
    maps, local = discover_databases()
    census = verify_census(local)
    policies = json.loads(POLICY.read_text()) if POLICY.exists() else []
    if isinstance(policies, dict):
        policies = [policies]
    selected = {item['unix_socket']: item for item in policies}
    require(len(selected) == len(policies), 'Duplicate protected socket records')
    exceptions = set()
    if not preflight:
        require(bool(selected), 'Redis write protection is not enabled')
        intent = json.loads(INTENT.read_text()) if allow_tcp_exceptions else None
        exceptions = protection_scope(local, selected, allow_tcp_exceptions=allow_tcp_exceptions, intent=intent)
    secret = SECRET.read_bytes() if selected else None
    from swsscommon import swsscommon
    prefix = '__sonic_redis_access_test__:' + uuid.uuid4().hex
    processes, controls = {}, {}
    seeded = 0
    try:
        for name, instance in local.items():
            value = (VALUE.decode() + ':' + name).encode()
            socket = instance['unix_socket_path']
            policy = selected.get(socket)
            endpoint = ({'unix_socket_path': socket} if policy else
                        {'host': instance['hostname'], 'port': instance['port']})
            client = redis.Redis(**endpoint, single_connection_client=True,
                                 username=policy['username'] if policy else None,
                                 password=secret if policy else None)
            controls[name] = client
            count = int(client.config_get('databases')['databases'])
            require(count > 0, 'Redis reports no logical databases')
            processes[name] = dict(name=name, socket=socket, count=count, key=prefix,
                                   protected=policy is not None, host=instance['hostname'], port=instance['port'],
                                   namespace=instance['namespace'], container=instance['container'], value=value.decode())
            for database in range(count):
                client.execute_command('SELECT', database)
                client.set(prefix, value, ex=300)
                client.hset(prefix + ':hash', 'field', value)
                client.expire(prefix + ':hash', 300)
                native = (swsscommon.DBConnector(database, socket, 1000) if policy else
                          swsscommon.DBConnector(database, instance['hostname'], instance['port'], 1000))
                require(native.set(prefix, value.decode()), 'Admin native write failed')
                client.expire(prefix, 300)
                seeded += 1
        ordinary = 0
        ordinary_identity = None
        if not preflight:
            protected = [process for process in processes.values() if process['protected']]
            args = [sys.executable, str(Path(__file__).resolve()), '--reader', json.dumps(protected)]
            result = execute(args, ordinary=True)
            require(result[0] == 0, 'Ordinary checks failed: ' + (result[1] + result[2]).decode(errors='replace'))
            reader_report = json.loads(result[1])
            ordinary = reader_report['databases_checked']
            ordinary_identity = {key: reader_report[key] for key in ('uid', 'gid', 'supplementary_groups')}
        named = 0
        for namespace, metadata in maps.items():
            prefix_id = namespace + '/' if namespace else ''
            ns_processes = {name: processes[prefix_id + name] for name in metadata['INSTANCES']}
            ns_controls = {name: controls[prefix_id + name] for name in metadata['INSTANCES']}
            named += cli_checks(metadata, ns_processes, ns_controls, prefix, preflight, namespace)
        for name, process in processes.items():
            for database in range(process['count']):
                controls[name].execute_command('SELECT', database)
                require(controls[name].get(prefix) == process['value'].encode(), 'Probe value changed after denied writes')
        return dict(success=True, mode='preflight' if preflight else ('mixed' if exceptions else 'enforced'),
                    security_verified=not preflight and not exceptions,
                    protected_processes_verified=not preflight,
                    unprotected_processes=sorted(exceptions), admin_databases_checked=seeded,
                    protected_databases=sum(item['count'] for item in processes.values() if item['protected']),
                    ordinary_databases_checked=ordinary, ordinary_identity=ordinary_identity,
                    named_databases_checked=named,
                    namespaces=sorted(maps), actual_redis_processes_checked=census,
                    processes=[dict(name=item['name'], namespace=item['namespace'], count=item['count'], protected=item['protected'])
                               for item in processes.values()])
    finally:
        for name, client in controls.items():
            try:
                for database in range(processes.get(name, {}).get('count', 0)):
                    client.execute_command('SELECT', database)
                    client.delete(*(prefix + suffix for suffix in ('', ':hash', ':stdin', ':binary', ':pipe', ':cli')))
            finally:
                client.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--preflight', action='store_true', help='Check admin clients before enabling write protection')
    modes.add_argument('--allow-tcp-exceptions', action='store_true',
                       help='Validate protected processes and report configured TCP exceptions as unprotected')
    parser.add_argument('--reader', help=argparse.SUPPRESS)
    options = parser.parse_args()
    try:
        report = ({'databases_checked': reader_checks(json.loads(options.reader)),
                   'uid': os.geteuid(), 'gid': os.getegid(), 'supplementary_groups': os.getgroups()}
                  if options.reader else main(options.preflight, options.allow_tcp_exceptions))
        print(json.dumps(report, sort_keys=True))
    except Exception as error:
        print(json.dumps(dict(success=False, error=str(error)), sort_keys=True))
        sys.exit(1)
