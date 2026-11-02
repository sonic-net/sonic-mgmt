"""Read-only, fail-closed fast path for the four certificate cleanup fixtures.

This is deliberately not a replacement for their recovery or module finalizers.
Only the pinned staging layout below is understood; unknown images recover.
No device file, database value, command output or exception is logged here.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shlex
import ssl
import stat
import tempfile
import time
from types import MappingProxyType

from tests.redfish.redfish_utils import (
    CA_CERT_NAME, CLIENT_CERT_NAME, CLIENT_KEY_NAME, CLIENT_CN,
    DELIVERED_CA_CRT, DELIVERED_SERVER_CRT, DELIVERED_SERVER_KEY,
    PRIVILEGED_PATH, REDFISH_CERTS_TABLE, REDFISH_CONFIG_TABLE,
    SERVER_CERT_NAME, SERVER_KEY_NAME,
)

# sonic-buildimage ff1d809c3b79bc43881aa7be858bf731dece68fd,
# dockers/docker-sonic-redfish/stage-credentials.sh. Checked on the device on
# EVERY inspection, not inferred from image name or a cached in_sync bit.
STAGING_SCRIPT_SHA256 = "69fefdcb115db8caa307ff1ec9a6fdd008f888358346e7adf0b060b9c2fd4306"

# Run inside the container (host-mounted delivery/marker paths). Capture all
# subprocess output privately. The only output is a fixed boolean.
INSPECT = r'''
import hashlib, json, os, re, stat, subprocess, sys
from swsscommon import swsscommon

# Bound database connection/read stalls as well as subprocess timeouts.
import signal
signal.alarm(25)

def run(*args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if p.returncode != 0:
        raise ValueError("command failed")
    return p.stdout

def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_mode & 0o022 or s.st_uid != 0:
            raise ValueError("unsafe file")
        with os.fdopen(fd, 'rb', closefd=False) as f:
            data = f.read(1048577)
        if not data or len(data) > 1048576:
            raise ValueError("invalid size")
        return data
    finally:
        os.close(fd)

def row(db, key):
    c = swsscommon.SonicV2Connector()
    c.connect(db)
    return c.get_all(db, key) or {}

try:
    expected = json.loads(sys.argv[1])
    config = row('CONFIG_DB', 'REDFISH|config')
    # An unrecognized implementation disables the no-op path, but must not
    # prevent the established recovery from being verified by actual bytes,
    # status equality and live authenticated access.
    if expected['require_script']:
        if hashlib.sha256(read('/usr/bin/stage-credentials.sh')).hexdigest() != expected['script']:
            raise ValueError("unknown staging implementation")
    certs = row('CONFIG_DB', 'REDFISH|certs')
    if config.get('port') != expected['port']:
        raise ValueError("port drift")
    for key, value in expected['config'].items():
        if certs.get(key) != value:
            raise ValueError("configuration drift")
    paths = [certs[k] for k in ('server_crt', 'server_key', 'ca_crt')]
    content = [read(p) for p in paths]
    if [hashlib.sha256(b).hexdigest() for b in content] != expected['files']:
        raise ValueError("delivery drift")
    fp = hashlib.sha256(b''.join(content)).hexdigest()
    if fp != expected['fingerprint']:
        raise ValueError("source drift")
    status = row('STATE_DB', 'REDFISH_CERT_STATUS|global')
    for key, value in {'source_fingerprint': fp, 'applied_fingerprint': fp,
                       'in_sync': 'true', 'mtls_enforced': 'true', 'last_error': ''}.items():
        if key not in status or status[key] != value:
            raise ValueError("status drift")
    if read('/var/lib/bmcweb/.staged-credentials.stamp') != (fp + '\n').encode():
        raise ValueError("stamp drift")
    marker = read('/var/lib/bmcweb/provisioned')
    if (b'Do not delete' not in marker or
            not re.search(rb'^provisioned_at=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$', marker, re.M)):
        raise ValueError("marker drift")
    if read('/etc/ssl/certs/https/server.pem') != content[0] + content[1]:
        raise ValueError("staged pair drift")
    auth = '/etc/ssl/certs/authority/'
    if read(auth + 'CA-cert.pem') != content[2]:
        raise ValueError("trust drift")
    ca_hash = run('openssl', 'x509', '-hash', '-noout', '-in', auth + 'CA-cert.pem').decode().strip()
    if not re.fullmatch('[0-9a-f]{8}', ca_hash):
        raise ValueError("invalid CA hash")
    entries = set(os.listdir(auth))
    if not {'CA-cert.pem', ca_hash + '.0'} <= entries:
        raise ValueError("missing trust entry")
    # stage_certs replaces CA-cert.pem and adds the current hash alias, but
    # retains earlier subject-hash aliases. They are safe ONLY when each is
    # a direct symlink to the same already byte-verified CA (no foreign CA).
    for entry in entries - {'CA-cert.pem'}:
        if not re.fullmatch(r'[0-9a-f]{8}\.0', entry):
            raise ValueError("unexpected trust anchor")
        if os.readlink(auth + entry) != 'CA-cert.pem':
            raise ValueError("trust link drift")
    for program in ('credentials-watcher', 'bmcweb', 'sonic-dbus-bridge'):
        fields = run('supervisorctl', 'status', program).decode().split()
        if len(fields) < 2 or fields[:2] != [program, 'RUNNING']:
            raise ValueError("unhealthy program")
    print('true')
except Exception:
    # Never emit values, subprocess stderr, tracebacks, or private-key digests.
    print('false')
    sys.exit(1)
'''


def _inspect(duthost, expected):
    command = "docker exec redfish python3 -c {} {}".format(
        shlex.quote(INSPECT), shlex.quote(json.dumps(expected)))
    result = duthost.shell(command + " 2>/dev/null", module_ignore_errors=True, verbose=False)
    if result.get("rc") != 0 or result.get("failed") or result.get("stderr"):
        raise ValueError("Redfish cleanup inspection unavailable")
    return json.loads(result["stdout"])


def freeze_expected(certs, destination, raw_port):
    """Freeze generated artifacts once, BEFORE a test can rotate their sources.

    raw_port comes from the existing pre-provisioning owned-config snapshot:
    no additional container capability/setup gate and no dirty-case capture.
    Canonical local artifacts are reconciled to this generation at cleanup,
    so later guard and unchanged-content cases see the same bytes as the DUT.
    """
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    names = (SERVER_CERT_NAME, SERVER_KEY_NAME, CA_CERT_NAME, CLIENT_CERT_NAME, CLIENT_KEY_NAME)
    data = [(Path(certs["dir"]) / name).read_bytes() for name in names]
    for name, content in zip(names, data):
        path = destination / name
        with path.open("xb") as handle:
            path.chmod(0o600)
            handle.write(content)
    config = {"server_crt": DELIVERED_SERVER_CRT, "server_key": DELIVERED_SERVER_KEY,
              "ca_crt": DELIVERED_CA_CRT, "client_crt_cname": CLIENT_CN}
    # Store immutable JSON, not a mutable baseline a teardown could refresh.
    remote = json.dumps({"script": STAGING_SCRIPT_SHA256, "config": config, "port": raw_port,
                         "files": [hashlib.sha256(b).hexdigest() for b in data[:3]],
                         "fingerprint": hashlib.sha256(b"".join(data[:3])).hexdigest()})
    return MappingProxyType({"remote": remote, "dir": destination, "port": certs["port"],
                             "canonical": Path(certs["dir"]).resolve(),
                             "digests": tuple(hashlib.sha256(b).digest() for b in data),
                             "server_der": ssl.PEM_cert_to_DER_cert(data[0].decode())})


def _local_intact(expected):
    names = (SERVER_CERT_NAME, SERVER_KEY_NAME, CA_CERT_NAME, CLIENT_CERT_NAME, CLIENT_KEY_NAME)
    for name, digest in zip(names, expected["digests"]):
        path = expected["dir"] / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or
                hashlib.sha256(path.read_bytes()).digest() != digest):
            return False
    return True


def restore_local_generation(expected, metrics):
    """Reconcile only fixture-owned canonical files, never learn from the DUT.

    Rotation intentionally overwrites these names during the body. Atomic local
    replacement after cleanup keeps subsequent body references coherent, while
    refusing symlink/foreign-owner substitutions and modified frozen sources.
    """
    if not _local_intact(expected):
        raise ValueError("Frozen Redfish generation changed")
    directory = expected["canonical"]
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("Unsafe Redfish artifact directory")
    names = (SERVER_CERT_NAME, SERVER_KEY_NAME, CA_CERT_NAME, CLIENT_CERT_NAME, CLIENT_KEY_NAME)
    for name, digest in zip(names, expected["digests"]):
        target = directory / name
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("Unsafe Redfish artifact target")
        if hashlib.sha256(target.read_bytes()).digest() == digest:
            continue
        with tempfile.NamedTemporaryFile(dir=str(directory), delete=False) as handle:
            temporary = Path(handle.name)
            try:
                handle.write((expected["dir"] / name).read_bytes())
                handle.close()
                os.replace(str(temporary), str(target))
                metrics["local_replacements"] += 1
            finally:
                if temporary.exists():
                    temporary.unlink()


def privileged_ready(host, expected):
    """Fresh verified mTLS connection; exact wire certificate and privileged 200.

    HTTPConnection does not follow redirects or pool connections. Never read or
    log the response payload. Use the same socket for certificate and auth.
    """
    context = ssl.create_default_context(cafile=str(expected["dir"] / CA_CERT_NAME))
    context.load_cert_chain(str(expected["dir"] / CLIENT_CERT_NAME),
                            str(expected["dir"] / CLIENT_KEY_NAME))
    connection = http.client.HTTPSConnection(host, expected["port"], context=context, timeout=10)
    try:
        connection.connect()
        if connection.sock.getpeercert(binary_form=True) != expected["server_der"]:
            return False
        connection.request("GET", PRIVILEGED_PATH)
        response = connection.getresponse()
        try:
            return response.status == 200
        finally:
            response.close()
    finally:
        connection.close()


def expected_ready(duthost, expected, metrics, require_script=True):
    started = time.monotonic()
    metrics["checks"] += 1
    try:
        if not _local_intact(expected):
            return False
        metrics["inspection_calls"] += 1
        remote = json.loads(expected["remote"])
        remote["require_script"] = require_script
        if _inspect(duthost, remote) is not True:
            return False
        metrics["auth_calls"] += 1
        return privileged_ready(duthost.mgmt_ip, expected)
    except Exception:
        # UNKNOWN is recovery, not clean. Do not interpolate exceptions: a
        # transport/HTTP failure may carry remote output or credential paths.
        return False
    finally:
        metrics["check_seconds"] += time.monotonic() - started


def restore_expected_config(duthost, expected):
    """Restore only owned fields, preserving explicit443 versus absent port."""
    remote = json.loads(expected["remote"])
    fields = [(REDFISH_CERTS_TABLE, k, v) for k, v in remote["config"].items()]
    fields.append((REDFISH_CONFIG_TABLE, "port", remote["port"]))
    for table, field, value in fields:
        args = ["sonic-db-cli", "CONFIG_DB", "hdel" if value is None else "hset", table, field]
        if value is not None:
            args.append(value)
        result = duthost.shell(" ".join(shlex.quote(a) for a in args), module_ignore_errors=True, verbose=False)
        if result.get("rc") != 0 or result.get("failed"):
            raise AssertionError("Redfish cleanup configuration restore failed")
