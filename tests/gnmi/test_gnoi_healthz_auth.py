"""Qualify Healthz TLS roles without acknowledging any retained event.

Run during an exclusive Healthz write window so catalog snapshots can detect
mutations. The existing TLS fixture owns certificate/configuration rollback.
"""

import copy
import json
import re
import shlex
import uuid

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_utils import add_gnmi_client_common_name


pytestmark = [pytest.mark.topology("any")]
SERVICE = "gnoi.healthz.Healthz/"
CLIENT_NAME = "test.client.gnmi.sonic"
CATALOG = "/var/lib/sonic/healthz/catalog.sqlite3"


def _catalog(duthost):
    script = (
        "import json,sqlite3; "
        "db=sqlite3.connect('file:{}?mode=ro',uri=True); "
        "print(json.dumps({{t:list(db.execute('SELECT * FROM '+t+' ORDER BY '+k)) "
        "for t,k in [('events','seq'),('sources','producer,source_key'),"
        "('aggregates','component'),('metadata','name'),('sqlite_sequence','name')]}},"
        "sort_keys=True))"
    ).format(CATALOG)
    result = duthost.shell("sudo python3 -c " + shlex.quote(script), module_ignore_errors=True)
    assert result["rc"] == 0, "Cannot snapshot Healthz catalog: " + result.get("stderr", "")
    return json.loads(result["stdout"])


def _call(client, method, request):
    command = client._build_grpcurl_cmd(extra_args=["-d", "@"], service_method=SERVICE + method)
    return client.ptfhost.command(argv=command, stdin=json.dumps(request), module_ignore_errors=True)


def _expect(result, code):
    output = result.get("stderr", "") + result.get("stdout", "")
    if code is None:
        assert result["rc"] == 0, output
    else:
        assert result["rc"] != 0 and re.search(r"Code:\s*" + code + r"\b", output), output


def _role(duthost):
    return duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "GNMI_CLIENT_CERT|' + CLIENT_NAME + '" "role@"',
    )["stdout"].strip()


def _set_role(duthost, role):
    add_gnmi_client_common_name(duthost, CLIENT_NAME, role)
    assert _role(duthost) == role, "Client role did not change to " + role


def test_healthz_tls_roles(healthz_tls):
    """Read roles reach reads; mutations require readwrite; noaccess denies all."""
    client, duthost = healthz_tls.grpc, healthz_tls.duthost
    baseline = _catalog(duthost)
    token = uuid.uuid4().hex
    path = {"elem": [{"name": "components"},
                     {"name": "component", "key": {"name": "healthz-auth-missing-" + token}}]}
    requests = {
        "Get": {"path": path},
        "List": {"path": path, "includeAcknowledged": True},
        "Artifact": {"id": "healthz-" + token + ".tar.gz"},
        "Acknowledge": {"path": path, "id": "hz-" + token},
        "Check": {"path": path},
    }
    allowed = {"Get": "NotFound", "List": None, "Artifact": "NotFound",
               "Acknowledge": "NotFound", "Check": "Unimplemented"}

    anonymous = copy.copy(client)
    anonymous.client_cert = anonymous.client_key = None
    result = _call(anonymous, "Get", requests["Get"])
    output = result.get("stderr", "") + result.get("stdout", "")
    assert result["rc"] != 0 and re.search(r"tls|handshake|certificate required", output, re.I), output
    assert not re.search(r"Code:\s*(PermissionDenied|Unauthenticated)\b", output), output

    original = _role(duthost)
    assert original, "TLS fixture did not register the expected client common name"
    try:
        for role in ("gnoi_readwrite", "gnoi_readonly", "gnoi_noaccess"):
            _set_role(duthost, role)
            for method, request in requests.items():
                denied = role == "gnoi_noaccess" or (
                    role == "gnoi_readonly" and method in ("Acknowledge", "Check")
                )
                _expect(_call(client, method, request), "PermissionDenied" if denied else allowed[method])
            assert _catalog(duthost) == baseline, "Healthz catalog mutated while checking " + role
    finally:
        _set_role(duthost, original)
