# Redfish Test Suite — Complete Explanation for Beginners

This document explains every file, every line of code, and every concept
involved in the Redfish test suite for the SONiC BMC device.

---

## Background: What Is All This?

### What is SONiC?
SONiC (Software for Open Networking in the Cloud) is an open-source network
operating system originally built by Microsoft. It runs on physical network
switches. Think of it like Linux, but for switches.

### What is a BMC?
BMC stands for Baseboard Management Controller. It is a tiny computer
embedded inside a server or network device. Its job is to let you manage
the hardware remotely — even if the main operating system is down. You can
reboot it, check temperatures, update firmware, etc., all through the BMC.

### What is Redfish?
Redfish is a standard REST API (like a web API) defined by an industry body
called DMTF. It runs on the BMC and lets you talk to the BMC over HTTP.
Instead of SSHing into the BMC, you just send HTTP requests to URLs like
`https://<bmc-ip>/redfish/v1`.

### What is sonic-mgmt?
sonic-mgmt is the official test framework for SONiC. It is a large Python
project that uses:
- **pytest** — the Python testing library (collects and runs test functions)
- **Ansible** — an IT automation tool that connects to devices over SSH
- **conftest.py files** — pytest's way of sharing setup code across tests

When you run a test, sonic-mgmt:
1. Reads your testbed configuration (which devices exist, their IPs, topology)
2. SSHes into the devices using Ansible
3. Runs your test functions
4. Reports pass/fail

### What is mTLS?
TLS is the encryption used in HTTPS. Normal HTTPS only proves the *server*
is who it claims to be (via a server certificate). Mutual TLS (mTLS) goes
further — the *client* also presents a certificate to prove its identity.
Our BMC is configured with `TLSStrict: true`, meaning it will reject any
HTTP connection that does not present a valid client certificate.

---

## The Directory Structure

```
sonic-mgmt/
├── ansible/                         # Ansible configuration
│   ├── lab                          # Inventory: list of all devices
│   ├── testbed.yaml                 # Testbed definitions
│   ├── files/
│   │   └── sonic_lab_devices.csv    # Device CSV loaded by framework
│   └── group_vars/
│       └── all/
│           └── creds.yml            # Usernames and passwords
│
└── tests/                           # All test code lives here
    ├── conftest.py                  # ROOT conftest — shared setup for ALL tests
    └── redfish/                     # Our new test module
        ├── __init__.py              # Makes this a Python package
        ├── conftest.py              # Shared fixtures for redfish tests only
        └── test_redfish_service_root.py   # The actual test cases
```

---

## Concept: pytest Fixtures

Before reading the code, you must understand **pytest fixtures**.

A fixture is a function decorated with `@pytest.fixture`. It provides
something (a value, a connection, a response) to test functions that
declare it as a parameter.

Example:
```python
@pytest.fixture
def my_number():
    return 42

def test_something(my_number):   # pytest sees "my_number" and calls the fixture
    assert my_number == 42
```

Fixtures can have **scope**:
- `scope="function"` — runs once per test function (default)
- `scope="module"`   — runs once per test file, shared across all tests in it
- `scope="session"`  — runs once for the entire test run

`autouse=True` means the fixture runs automatically for every test in its
scope, without tests having to declare it as a parameter.

---

## File 1: `tests/redfish/__init__.py`

```python
# (empty file)
```

**Why does this exist?**

Python needs a file called `__init__.py` to treat a directory as a
"package" (importable module). Without it, pytest cannot properly discover
and import test files inside `tests/redfish/`. It is intentionally empty —
its mere existence is what matters.

---

## File 2: `tests/redfish/conftest.py`

This file defines fixtures that are **shared across all test files inside
`tests/redfish/`**. pytest automatically loads conftest.py files and makes
their fixtures available to tests in the same directory and subdirectories.

```python
import logging
import pytest

from tests.common.helpers.assertions import pytest_require as pyrequire
```

- `logging` — Python's standard logging library. Used to print info messages
  during test runs (visible with `-v` flag).
- `pytest` — the testing framework.
- `pytest_require` — a sonic-mgmt helper. It is like `pytest.skip()` but
  with a cleaner message. If the condition is False, it skips the test with
  the given reason.

```python
logger = logging.getLogger(__name__)
REDFISH_ROOT = "/redfish/v1"
```

- `logger` — creates a logger named after this file (e.g., `tests.redfish.conftest`).
- `REDFISH_ROOT` — constant string. The base path of the Redfish API.

---

### Fixture: `is_bmc_present`

```python
@pytest.fixture(scope="module", autouse=True)
def is_bmc_present(request):
    if request.config.getoption("--bmc_ip"):
        return
    duthosts = request.getfixturevalue("duthosts")
    hostname = request.getfixturevalue("enum_rand_one_per_hwsku_hostname")
    duthost = duthosts[hostname]
    pyrequire(duthost.is_bmc(),
              "DUT is not a BMC device (dut_type != NetworkBmc), skipping Redfish tests")
```

**Purpose:** Skip the entire test module if the target device is not a BMC.

**Line by line:**

`@pytest.fixture(scope="module", autouse=True)`
- `scope="module"` — runs once per test file, not once per test.
- `autouse=True` — runs automatically. Tests do not need to declare it.

`def is_bmc_present(request):`
- `request` is a special built-in pytest object. It gives you access to
  the current test's context, command-line options, and other fixtures.

`if request.config.getoption("--bmc_ip"): return`
- If the user passed `--bmc_ip` on the command line, we trust them —
  they are explicitly pointing at a BMC IP. Skip the device check and
  just return. This allows running tests without a full testbed setup.

`duthosts = request.getfixturevalue("duthosts")`
- `getfixturevalue()` is how you *conditionally* use another fixture.
  Normally, if you put `duthosts` as a function parameter, pytest would
  always try to create it — even when `--bmc_ip` is given. Using
  `getfixturevalue()` inside an `if` block means it only runs when needed.
- `duthosts` is a sonic-mgmt fixture that holds SSH connections to all
  DUT (Device Under Test) devices in the testbed.

`hostname = request.getfixturevalue("enum_rand_one_per_hwsku_hostname")`
- Another sonic-mgmt fixture. It picks one random hostname from the
  testbed for the current hardware SKU being tested. We use this to
  get one specific device to check.

`duthost = duthosts[hostname]`
- Gets the specific device object for that hostname.

`pyrequire(duthost.is_bmc(), "...")`
- Calls `is_bmc()` on the device — this SSHes in and checks if
  `dut_type == NetworkBmc`. If it is not a BMC, the test module is
  skipped with the given message.

---

### Fixture: `bmc_ip`

```python
@pytest.fixture(scope="module")
def bmc_ip(request, tbinfo):
    cli_ip = request.config.getoption("--bmc_ip")
    if cli_ip:
        return cli_ip
    ip = tbinfo.get("bmc_ip")
    pyrequire(ip, "bmc_ip field missing from testbed.yaml entry for this testbed")
    return ip
```

**Purpose:** Returns the IP address of the BMC.

`tbinfo` — a sonic-mgmt fixture. It reads the testbed.yaml file and
returns a dictionary for the current testbed. For example, for `gold416`:
```python
{
    "conf-name": "gold416",
    "topo": {"name": "bmc-dual-mgmt", ...},
    "bmc_ip": "10.250.66.246",
    ...
}
```

`request.config.getoption("--bmc_ip")` — reads the `--bmc_ip` CLI argument.

The logic:
1. If `--bmc_ip` was given on CLI → use that (useful for quick manual runs).
2. Otherwise → read `bmc_ip` from testbed.yaml (the standard approach for
   automated test pipelines).

---

### Fixture: `bmc_creds`

```python
@pytest.fixture(scope="module")
def bmc_creds(request, creds):
    return {
        "user": request.config.getoption("--bmc_user") or creds.get("sonicadmin_user"),
        "password": request.config.getoption("--bmc_password") or creds.get("sonicadmin_password"),
    }
```

**Purpose:** Returns the BMC login credentials as a dictionary.

`creds` — a sonic-mgmt fixture that reads `ansible/group_vars/all/creds.yml`
and returns it as a Python dictionary.

The `or` operator gives priority to CLI arguments. If `--bmc_user` is not
provided, it falls back to `sonicadmin_user` from creds.yml.

Result looks like:
```python
{"user": "admin", "password": "YourPaSsWoRd"}
```

---

### Fixture: `bmc_client_cert`

```python
@pytest.fixture(scope="module")
def bmc_client_cert(request):
    cert_path = request.config.getoption("--bmc_cert")
    key_path = request.config.getoption("--bmc_key")
    if cert_path and key_path:
        return (cert_path, key_path)
    return None
```

**Purpose:** Returns the mTLS client certificate paths, or None.

The `requests` Python library (used to make HTTP calls) accepts a `cert`
parameter. If you pass a tuple `(cert_path, key_path)`, it presents that
certificate during the TLS handshake. If you pass `None`, no client cert
is sent (works for BMCs without mTLS).

---

### Fixture: `redfish_base_url`

```python
@pytest.fixture(scope="module")
def redfish_base_url(bmc_ip):
    return "https://{}{}".format(bmc_ip, REDFISH_ROOT)
```

**Purpose:** Convenience fixture. Returns `https://10.250.66.246/redfish/v1`.
Other test files can use this instead of constructing the URL themselves.

---

## File 3: `tests/redfish/test_redfish_service_root.py`

This is the actual test file. It tests the `GET /redfish/v1` endpoint.

```python
import logging
import pytest
import requests
import urllib3

from tests.common.helpers.assertions import pytest_assert
```

- `requests` — the standard Python HTTP library. Much easier than
  `urllib`. Used to make GET requests to the BMC.
- `urllib3` — the lower-level library that `requests` uses internally.
- `pytest_assert` — sonic-mgmt helper. Like Python's `assert` but with
  better error messages in pytest output.

```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

When you use `verify=False` (skip TLS certificate verification), `requests`
prints a warning for every HTTPS call. This line silences those warnings.
We use `verify=False` because BMC certificates are self-signed (not issued
by a public CA like Let's Encrypt), so normal verification would fail.

```python
pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]
```

`pytestmark` is a pytest special variable. Marks applied here affect every
test in the file.

- `disable_loganalyzer` — sonic-mgmt has a plugin that analyzes syslog
  on DUT devices for errors. BMC tests don't need that, so we disable it.
- `topology(...)` — sonic-mgmt uses this to only run tests on matching
  testbed topologies. `bmc-dual-mgmt` means the SONiC management IP and
  BMC Redfish IP are on separate networks. `bmc-shared-mgmt` means they
  share the same network.

```python
REQUIRED_FIELDS = [
    "@odata.type",
    "@odata.id",
    "RedfishVersion",
    "UUID",
    "Links",
]

REQUIRED_LINKS_FIELDS = ["Sessions"]
```

Constants defining what fields the DMTF Redfish spec says MUST be in the
`/redfish/v1` response. The actual BMC response looks like:
```json
{
    "@odata.type": "#ServiceRoot.v1_15_0.ServiceRoot",
    "@odata.id": "/redfish/v1",
    "RedfishVersion": "1.17.0",
    "UUID": "3f621700-09dd-41cd-96bc-ec40d08eb257",
    "Links": {
        "Sessions": {"@odata.id": "/redfish/v1/SessionService/Sessions"}
    }
}
```

---

### Fixture: `redfish_v1_response`

```python
@pytest.fixture(scope="module")
def redfish_v1_response(bmc_ip, bmc_creds, bmc_client_cert):
    url = "https://{}/redfish/v1".format(bmc_ip)
    logger.info("GET {}".format(url))

    response = requests.get(
        url,
        auth=(bmc_creds["user"], bmc_creds["password"]),
        cert=bmc_client_cert,
        verify=False,
        timeout=30,
    )

    logger.info("HTTP status: {}".format(response.status_code))
    logger.info("Response body: {}".format(response.text))

    return response
```

**Purpose:** Make the HTTP GET request ONCE and share the response with
all 6 test functions.

`scope="module"` is key here. Without it, each of the 6 tests would make
its own HTTP request — 6 network calls for the same data. With module scope,
one call is made and all tests reuse the same `response` object.

`requests.get(url, ...)` parameters:
- `auth=(user, password)` — sends HTTP Basic Authentication header.
  The BMC checks these credentials.
- `cert=bmc_client_cert` — the mTLS client certificate. If `None`,
  no client cert is sent.
- `verify=False` — skip server certificate verification (BMC uses
  self-signed certs).
- `timeout=30` — fail after 30 seconds if the BMC doesn't respond.

The `response` object has:
- `response.status_code` — the HTTP status code (200, 404, 500, etc.)
- `response.text` — the raw response body as a string
- `response.json()` — parses the body as JSON and returns a Python dict

---

### Class: `TestRedfishServiceRoot`

Grouping tests in a class is optional in pytest but helps organize them.
All methods that start with `test_` are discovered and run by pytest.

Every method takes `self` (because it's a class method) and
`redfish_v1_response` (the fixture defined above).

---

### Test 1: `test_service_root_http_200`

```python
def test_service_root_http_200(self, redfish_v1_response):
    pytest_assert(
        redfish_v1_response.status_code == 200,
        "Expected HTTP 200 from /redfish/v1, got: {}".format(redfish_v1_response.status_code)
    )
```

**What it checks:** The BMC responded with HTTP 200 OK.

Common failure codes you might see instead:
- `401` — wrong username/password
- `403` — authenticated but not authorized
- `404` — URL doesn't exist on this BMC
- `503` — BMC service is not running

---

### Test 2: `test_service_root_valid_json`

```python
def test_service_root_valid_json(self, redfish_v1_response):
    try:
        body = redfish_v1_response.json()
        pytest_assert(body is not None, "Response body is None")
    except ValueError:
        pytest_assert(False, "Response body is not valid JSON: {}".format(redfish_v1_response.text))
```

**What it checks:** The response body can be parsed as JSON.

`response.json()` raises `ValueError` if the body is not valid JSON (e.g.,
if the BMC returned an HTML error page). The `try/except` catches that and
fails the test with the raw body so you can see what went wrong.

---

### Test 3: `test_service_root_required_fields`

```python
def test_service_root_required_fields(self, redfish_v1_response):
    pytest_assert(
        redfish_v1_response.status_code == 200,
        "Cannot validate fields, HTTP status: {}".format(redfish_v1_response.status_code)
    )
    body = redfish_v1_response.json()
    for field in REQUIRED_FIELDS:
        pytest_assert(
            field in body,
            "Required field '{}' missing from /redfish/v1 response".format(field)
        )
```

**What it checks:** All DMTF-required fields are present in the JSON response.

The `for` loop iterates over `REQUIRED_FIELDS` and checks each one is a key
in the response dictionary. If any field is missing, the test fails and
tells you exactly which field was absent.

---

### Test 4: `test_service_root_redfish_version`

```python
def test_service_root_redfish_version(self, redfish_v1_response):
    body = redfish_v1_response.json()
    version = body.get("RedfishVersion", "")
    pytest_assert(
        isinstance(version, str) and len(version) > 0,
        "RedfishVersion must be a non-empty string, got: {!r}".format(version)
    )
    logger.info("BMC RedfishVersion: {}".format(version))
```

**What it checks:** `RedfishVersion` is a non-empty string.

`body.get("RedfishVersion", "")` — safely gets the value, defaulting to
empty string if the key doesn't exist (avoids a KeyError crash).

`isinstance(version, str)` — ensures it's a string, not a number or null.
`len(version) > 0` — ensures it's not an empty string `""`.

The `logger.info` at the end prints the actual version to the test output
(visible with `-v`). In our case this logged: `BMC RedfishVersion: 1.17.0`.

---

### Test 5: `test_service_root_odata_id`

```python
def test_service_root_odata_id(self, redfish_v1_response):
    body = redfish_v1_response.json()
    odata_id = body.get("@odata.id", "")
    pytest_assert(
        odata_id.rstrip("/") == "/redfish/v1",
        "@odata.id must be '/redfish/v1', got: {!r}".format(odata_id)
    )
```

**What it checks:** The `@odata.id` field is `/redfish/v1`.

`@odata.id` is the resource's canonical URL path. The Redfish spec says the
service root must identify itself as `/redfish/v1`.

`odata_id.rstrip("/")` — strips any trailing slash. Some BMCs return
`/redfish/v1/` (with slash), some return `/redfish/v1` (without). The
`.rstrip("/")` normalizes both to `/redfish/v1` before comparing.

---

### Test 6: `test_service_root_links_sessions`

```python
def test_service_root_links_sessions(self, redfish_v1_response):
    body = redfish_v1_response.json()
    links = body.get("Links", {})
    pytest_assert(
        isinstance(links, dict),
        "Links must be a JSON object, got: {!r}".format(type(links))
    )
    for field in REQUIRED_LINKS_FIELDS:
        pytest_assert(
            field in links,
            "Links.{} is missing from /redfish/v1 response".format(field)
        )
```

**What it checks:** `Links` is an object and contains a `Sessions` key.

The Redfish spec requires `Links.Sessions` to point to the session service
URL. This is how clients know where to create/delete login sessions.

`body.get("Links", {})` — if `Links` is missing, defaults to empty dict
so the isinstance check fails cleanly rather than crashing.

---

## File 4: `tests/conftest.py` (root — modified)

This is the most important conftest in the entire project. It runs for
every single test across all of sonic-mgmt. We added two things:

### Addition 1: CLI Options

```python
parser.addoption("--bmc_ip",       action="store", default=None, ...)
parser.addoption("--bmc_user",     action="store", default=None, ...)
parser.addoption("--bmc_password", action="store", default=None, ...)
parser.addoption("--bmc_cert",     action="store", default=None, ...)
parser.addoption("--bmc_key",      action="store", default=None, ...)
```

**Why must these be in the root conftest?**

pytest processes `pytest_addoption` hooks very early during startup, before
it loads conftest files from subdirectories. If you put `addoption` in
`tests/redfish/conftest.py`, pytest will raise "unrecognized arguments"
because it sees `--bmc_ip` on the command line before it ever reads the
redfish conftest. Only the root `tests/conftest.py` is guaranteed to be
loaded in time.

### Addition 2: BMC Topology Guards

```python
# Inside ptfhosts fixture:
if 'bmc' in tbinfo['topo']['name']:
    return None

# Inside fanouthosts fixture:
if 'bmc' in tbinfo['topo']['name']:
    return fanout_hosts   # empty dict, no fanout switches

# Inside vmhosts fixture:
if 'bmc' in tbinfo['topo']['name']:
    return None
```

**Why are these needed?**

A normal SONiC testbed has:
- PTF container — a special Linux host for sending/receiving test packets
- Fanout switches — the upstream switches the DUT is connected to
- VM hosts — virtual machines simulating neighboring routers

A BMC testbed has NONE of these. Without these guards, the framework tries
to set up connections to non-existent resources and crashes with KeyErrors
because `ptf`, `server`, `vm_base` fields are all null in testbed.yaml.

---

## File 5: `ansible/testbed.yaml` (modified)

```yaml
- conf-name: gold416
  group-name: gold416
  topo: bmc-dual-mgmt
  ptf_image_name: docker-ptf
  ptf:
  ptf_ip:
  ptf_ipv6:
  server:
  vm_base:
  dut:
    - gold416
  inv_name: lab
  auto_recover: 'False'
  bmc_ip: 10.250.66.246
  comment: Nexthop NH-4010-F BMC testbed
```

This is the testbed definition. The framework reads this file to know what
the testbed looks like.

- `conf-name: gold416` — the name used with `--testbed=gold416` on CLI
- `topo: bmc-dual-mgmt` — tells the framework which topology this is.
  The topology name is matched by `pytestmark` in the test file.
- `ptf:`, `server:`, `vm_base:` — intentionally empty (null). BMC testbeds
  have no PTF container, no server entry, no VMs.
- `dut: [gold416]` — the hostname of the device being tested
- `inv_name: lab` — which Ansible inventory file to look in (`ansible/lab`)
- `bmc_ip: 10.250.66.246` — custom field we added. The `bmc_ip` fixture
  reads this via `tbinfo.get("bmc_ip")`.

---

## File 6: `ansible/lab` (modified)

This is the Ansible inventory file. It lists all physical devices and their
connection details.

```yaml
sonic_nh_4010_f:
  vars:
    hwsku: Nexthop-NH-4010-F
    iface_speed: 100000
  hosts:
    gold416:
      ansible_host: 10.61.1.179      # SONiC SSH IP (not the BMC Redfish IP)
      model: NH-4010-F
      serial: NH-FJS25460016
      ansible_user: admin
      ansible_password: YourPaSsWoRd
      ansible_ssh_user: admin
      ansible_ssh_pass: YourPaSsWoRd
      ansible_altpassword: YourPaSsWoRd
```

**Why is the IP here `10.61.1.179` and not `10.250.66.246`?**

These are two different IPs for two different interfaces on the same device:
- `10.61.1.179` — the SONiC operating system's management IP. Used for SSH
  into the switch itself (to run `show` commands, etc.).
- `10.250.66.246` — the BMC's Redfish API IP. Used for HTTP calls to the
  BMC. This goes into `testbed.yaml`'s `bmc_ip` field, not the inventory.

The inventory only needs the SONiC SSH IP. The framework SSHes here to
run Ansible tasks. Our tests don't SSH anywhere — they make HTTP calls
directly to `10.250.66.246` from the test runner.

`ansible_altpassword` — sonic-mgmt's `creds_on_dut()` function requires
this field to exist (it tries the alternate password if the primary fails).

---

## File 7: `ansible/files/sonic_lab_devices.csv`

```
gold416,10.61.1.179/24,NH-4010-F,DevSonic,,sonic
```

Fields: `hostname, mgmt_ip, hwsku, device_type, card_type, os`

The `sonic_basic_facts` Ansible module (in `ansible/library/`) reads this
CSV to build a map of all devices. If `gold416` is missing from this file,
the framework crashes with `KeyError: 'gold416'` during initialization even
before any test runs.

---

## File 8: `ansible/group_vars/all/creds.yml`

```yaml
sonicadmin_user: "admin"
sonicadmin_password: "YourPaSsWoRd"
```

The `creds` fixture in sonic-mgmt automatically reads this file and returns
it as a dictionary. Our `bmc_creds` fixture uses these as the fallback
credentials when `--bmc_user`/`--bmc_password` are not passed on CLI.

---

## File 9: `Makefile` (modified)

```makefile
ANSIBLE_DIR := /home/shreyansh/sonic-mgmt/ansible
TESTS_DIR   := /home/shreyansh/sonic-mgmt/tests
```

The Makefile is a convenience wrapper that builds the long `docker exec`
command for you. The original had `/data/sonic-mgmt` (the path inside the
Docker container in the standard setup), but our container mounts the repo
at `/home/shreyansh/sonic-mgmt`, so we updated the paths.

---

## How It All Fits Together

When you run the test command:

```
docker exec \
  -e ANSIBLE_LIBRARY=/home/shreyansh/sonic-mgmt/ansible/library \
  -w /home/shreyansh/sonic-mgmt/tests sonic-mgmt \
  /opt/venv/bin/pytest redfish/test_redfish_service_root.py \
  --bmc_ip=10.250.66.246 \
  --bmc_user=admin \
  --bmc_password=YourPaSsWoRd \
  --bmc_cert=/home/shreyansh/scripts/client-cert.pem \
  --bmc_key=/home/shreyansh/scripts/client-key.pem \
  --ignore-conditional-mark \
  --testbed=gold416 \
  --testbed_file=../ansible/testbed.yaml \
  --host-pattern=gold416 \
  --inventory=../ansible/lab \
  --skip_sanity \
  -v
```

Here is what happens step by step:

1. `docker exec sonic-mgmt` — enters the running `sonic-mgmt` Docker container
2. `-e ANSIBLE_LIBRARY=...` — tells Ansible where custom modules are
3. `-w .../tests` — sets working directory so pytest finds `pytest.ini`
4. pytest starts, loads `tests/conftest.py` first (root conftest)
5. pytest sees `--bmc_ip`, `--bmc_cert`, etc. — recognized because we
   added them to root conftest's `pytest_addoption`
6. pytest loads `tests/redfish/conftest.py`
7. `is_bmc_present` fixture runs — sees `--bmc_ip` is set, returns early
   (skips the DUT SSH check)
8. `bmc_ip` fixture returns `10.250.66.246` (from CLI)
9. `bmc_creds` fixture returns `{"user": "admin", "password": "YourPaSsWoRd"}`
10. `bmc_client_cert` fixture returns `("/home/shreyansh/scripts/client-cert.pem",
    "/home/shreyansh/scripts/client-key.pem")`
11. `redfish_v1_response` fixture makes ONE HTTP GET to `https://10.250.66.246/redfish/v1`
    with Basic Auth + mTLS client cert + `verify=False`
12. pytest runs all 6 test functions, passing the same response object to each
13. All 6 assertions pass
14. pytest prints `6 passed`

---

## The mTLS Setup (Certificates)

The BMC at `10.250.66.246` enforces mTLS. This means:

1. **Server certificate** — the BMC presents its cert during TLS handshake.
   We use `verify=False` to skip checking it (it's self-signed).

2. **Client certificate** — WE must present a cert to the BMC. The BMC
   checks that our cert was signed by its trusted CA.

The certificates were generated by `generate_https_certificate.sh` and
installed on the BMC. The relevant files:

```
/home/shreyansh/scripts/
├── CA-cert.pem         # Certificate Authority — the root of trust
├── CA-key.pem          # CA private key (used to sign other certs)
├── client-cert.pem     # Our client certificate (presented to BMC)
├── client-key.pem      # Our client private key
├── server-cert.pem     # BMC's server certificate
└── server-key.pem      # BMC's server private key
```

`requests.get(..., cert=(client-cert.pem, client-key.pem))` sends our
client certificate during the TLS handshake. The BMC verifies it was
signed by the CA it trusts, and if so, allows the connection.

---

## Common Issues and Their Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `unrecognized arguments: --bmc_ip` | `addoption` not in root conftest | Moved to `tests/conftest.py` |
| `There is no conditions files` | pytest not run from `tests/` directory | Use `-w /home/shreyansh/sonic-mgmt/tests` |
| `testbed and testbed_file are required` | Missing `--testbed` and `--testbed_file` | Pass both on CLI |
| `DUTs ['localhost'] does not belong to testbed` | `--host-pattern` defaulted to localhost | Pass `--host-pattern=gold416` |
| `KeyError: 'gold416'` | Device missing from Ansible inventory | Added to `ansible/lab` and CSV |
| `sonic_basic_facts not found` | Custom Ansible modules not in path | Pass `-e ANSIBLE_LIBRARY=...` |
| `KeyError: None` in ptfhosts | BMC testbed has no PTF, fixture crashed | Added `bmc` topology guard |
| `SSLV3_ALERT_BAD_CERTIFICATE` | BMC enforces mTLS, no client cert | Added `--bmc_cert`/`--bmc_key` |
| `certificate is not yet valid` | BMC clock was stuck in Sep 2025 | Fixed BMC clock: `sudo date -s "..."` |
