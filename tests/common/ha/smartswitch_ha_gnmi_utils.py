import json
import logging
import time
import uuid
from functools import lru_cache

import pytest
from dash.proto_utils import json_to_proto
logger = logging.getLogger(__name__)

HA_SET_FILE = "/data/tests/common/ha/dash_ha_set_config_table.json"
HA_SCOPE_FILE = "/data/tests/common/ha/dash_ha_scope_config_table.json"


# ============================================================================
#                               GNMI ENVIRONMENT
# ============================================================================

@lru_cache(maxsize=None)
class GNMIEnvironment:

    def __init__(self, duthost):
        self.duthost = duthost

        # Working dir for generated certs
        self.work_dir = f"/tmp/gnmi_{uuid.uuid4()}/"
        # Certificate destination inside DUT
        self.gnmi_cert_path = "/etc/sonic/telemetry/"
        # CONSOLIDATED certificate naming
        self.ca_cert = "gnmi_ca.pem"
        self.ca_key = "gnmi_ca.key"
        self.server_cert = "gnmi_server.crt"
        self.server_key = "gnmi_server.key"
        self.client_cert = "gnmi_client.crt"
        self.client_key = "gnmi_client.key"

        self.gnmi_server_start_wait_time = 20
        self.enable_zmq = True

        # GNMI client on PTF
        self.python_bin = "/root/env-python3/bin/python"
        self.client_path = "/root/gnxi/gnmi_cli_py/py_gnmicli.py"

        # Detect GNMI container & port
        if duthost.shell("docker ps | grep -w gnmi", module_ignore_errors=True)['rc'] == 0:
            self.gnmi_container = "gnmi"
            self.gnmi_program = "gnmi-native"
            self.gnmi_port = 50052
        else:
            pytest.fail("GNMI container not running on DUT")

    def get_gnmi_target(self):
        ip = getattr(self.duthost, "mgmt_ip", None)
        if not ip:
            raise RuntimeError("Missing mgmt_ip on duthost")
        return ip, self.gnmi_port


# ============================================================================
#                     FILE READ HELPERS
# ============================================================================

def load_json(path):
    with open(path) as f:
        return json.load(f)


# ============================================================================
#                   GENERATE CERTIFICATES WITH SAN
# ============================================================================

def generate_gnmi_cert(localhost, duthost):

    env = GNMIEnvironment(duthost)
    localhost.shell(f"mkdir -p {env.work_dir}")

    server_ip = duthost.mgmt_ip
    server_cn = "gnmi-server"

    ext_file = f"{env.work_dir}ext.cnf"

    # SAN = mandatory for gRPC-TLS
    san_cfg = f"""
[req]
distinguished_name=req
req_extensions=req_ext

[req_ext]
subjectAltName=DNS:{server_cn},IP:{server_ip}
"""
    localhost.shell(f"echo \"{san_cfg}\" > {ext_file}")

    # --------------------------
    # CA Key + Cert
    # --------------------------
    localhost.shell(f"openssl genrsa -out {env.work_dir}{env.ca_key} 2048")
    localhost.shell(
        f"openssl req -x509 -new -nodes "
        f"-key {env.work_dir}{env.ca_key} "
        f"-subj '/CN=sonic-gnmi-ca' "
        f"-days 1825 "
        f"-out {env.work_dir}{env.ca_cert}"
    )

    # --------------------------
    # Server Key + CSR
    # --------------------------
    localhost.shell(f"openssl genrsa -out {env.work_dir}{env.server_key} 2048")
    localhost.shell(
        f"openssl req -new "
        f"-key {env.work_dir}{env.server_key} "
        f"-subj '/CN={server_cn}' "
        f"-out {env.work_dir}server.csr "
        f"-config {ext_file}"
    )

    # --------------------------
    # Server Cert with SAN
    # --------------------------
    localhost.shell(
        f"openssl x509 -req "
        f"-in {env.work_dir}server.csr "
        f"-CA {env.work_dir}{env.ca_cert} "
        f"-CAkey {env.work_dir}{env.ca_key} "
        f"-CAcreateserial "
        f"-out {env.work_dir}{env.server_cert} "
        f"-days 825 -sha256 "
        f"-extensions req_ext -extfile {ext_file}"
    )

    # --------------------------
    # Client Key + Cert
    # --------------------------
    localhost.shell(f"openssl genrsa -out {env.work_dir}{env.client_key} 2048")
    localhost.shell(
        f"openssl req -new "
        f"-key {env.work_dir}{env.client_key} "
        f"-subj '/CN=gnmi-client' "
        f"-out {env.work_dir}client.csr"
    )
    localhost.shell(
        f"openssl x509 -req "
        f"-in {env.work_dir}client.csr "
        f"-CA {env.work_dir}{env.ca_cert} "
        f"-CAkey {env.work_dir}{env.ca_key} "
        f"-CAcreateserial "
        f"-out {env.work_dir}{env.client_cert} "
        f"-days 825 -sha256"
    )


# ============================================================================
#              PUSH CERTS + RESTART GNMI SERVER (YOUR ORIGINAL METHOD)
# ============================================================================

def apply_gnmi_cert(duthost, ptfhost):
    """
    Install GNMI certificates, update CONFIG_DB to use them,
    and restart GNMI server correctly in read-write mode.
    """

    env = GNMIEnvironment(duthost)

    #
    # ------------------------------------------------------------
    # 1. Copy certificates to DUT + PTF
    # ------------------------------------------------------------
    #
    for f in [env.ca_cert, env.server_cert, env.server_key]:
        duthost.copy(src=env.work_dir + f, dest=env.gnmi_cert_path)

    ptfhost.copy(src=env.work_dir + env.ca_cert,     dest="/root/gnmi_ca.pem")
    ptfhost.copy(src=env.work_dir + env.client_cert, dest="/root/gnmi_client.crt")
    ptfhost.copy(src=env.work_dir + env.client_key,  dest="/root/gnmi_client.key")

    #
    # ------------------------------------------------------------
    # 2. PATCH CONFIG_DB SO TELEMETRY USES OUR CERTS
    # ------------------------------------------------------------
    #
    duthost.shell(f"""
        redis-cli -n 4 hset "GNMI|certs" ca_crt     "/etc/sonic/telemetry/{env.ca_cert}";
        redis-cli -n 4 hset "GNMI|certs" server_crt "/etc/sonic/telemetry/{env.server_cert}";
        redis-cli -n 4 hset "GNMI|certs" server_key "/etc/sonic/telemetry/{env.server_key}";
        redis-cli -n 4 hset "GNMI|gnmi"  log_level  "10";
        redis-cli -n 4 hset "GNMI|gnmi"  client_auth "true";
        config save -y;
    """)

    logger.info("CONFIG_DB updated with GNMI cert paths & saved")

    #
    # ------------------------------------------------------------
    # 3. Stop any running telemetry inside container
    # ------------------------------------------------------------
    #
    duthost.shell(
        f"docker exec {env.gnmi_container} pkill telemetry || true",
        module_ignore_errors=True
    )

    #
    # ------------------------------------------------------------
    # 4. Build telemetry cmd using updated cert paths
    # ------------------------------------------------------------
    #
    telemetry_args = [
        "/usr/sbin/telemetry",
        f"--port {env.gnmi_port}",
        f"--server_crt {env.gnmi_cert_path}{env.server_cert}",
        f"--server_key {env.gnmi_cert_path}{env.server_key}",
        f"--ca_crt {env.gnmi_cert_path}{env.ca_cert}",
        "-gnmi_native_write=true",
        "-logtostderr",
        "-v=99"
    ]

    if env.enable_zmq:
        telemetry_args.append("-zmq_port=8100")

    telemetry_cmd = " ".join(telemetry_args)

    #
    # ------------------------------------------------------------
    # 5. Launch telemetry with corrected certificates
    # ------------------------------------------------------------
    #
    start_cmd = (
        f"docker exec {env.gnmi_container} bash -c "
        f"'nohup {telemetry_cmd} >/root/gnmi.log 2>&1 &'"
    )

    duthost.shell(start_cmd)
    logger.info(" GNMI server restarted with updated TLS certificates")

    time.sleep(env.gnmi_server_start_wait_time)


# ============================================================================
#               APPLY HA-SET + HA-SCOPE VIA GNMI
# ============================================================================
def apply_ha_config_from_files(duthost, ptfhost):

    set_updates = []

    set_json = load_json(HA_SET_FILE)
    set_table = set_json.get("DASH_HA_SET_CONFIG_TABLE", {})

    for haset_id, obj in set_table.items():

        # Convert JSON → protobuf bytes
        pb_bytes = json_to_proto("DASH_HA_SET_CONFIG_TABLE", obj)

        # GNMI expects raw protobuf bytes, NOT hex
        xpath = f"/sonic-net:APPL_DB/DASH_HA_SET_CONFIG_TABLE/{haset_id}/pb"

        set_updates.append((xpath, pb_bytes))

    # Single GNMI SET request
    if set_updates:
        gnmi_set_pb_multi(duthost, ptfhost, set_updates)

    # ============================================================
    # 2. COLLECT ALL HA-SCOPE UPDATES → ONE UPDATE LIST
    # ============================================================
    scope_updates = []

    scope_json = load_json(HA_SCOPE_FILE)
    scope_table = scope_json.get("DASH_HA_SCOPE_CONFIG_TABLE", {})

    for composite_key, obj in scope_table.items():

        pb_bytes = json_to_proto("DASH_HA_SCOPE_CONFIG_TABLE", obj)

        # Convert "scope0|vdpu0_0" to "scope0:vdpu0_0"
        scope_key = composite_key.replace("|", ":").replace("\\", "")

        xpath = f"/sonic-net:APPL_DB/DASH_HA_SCOPE_CONFIG_TABLE/{scope_key}/pb"

        scope_updates.append((xpath, pb_bytes))

    # ---- ONE gNMI CALL for HA-SCOPE ----
    if scope_updates:
        logger.info(f"Sending {len(scope_updates)} HA-SCOPE entries in ONE gNMI call")
        gnmi_set_pb_multi(duthost, ptfhost, scope_updates)

    logger.info("Completed HA-SET + HA-SCOPE configuration using 2 gNMI calls")


def gnmi_set_pb_multi(duthost, ptfhost, update_list):
    """
    update_list = [
        (xpath, pb_bytes),
        (xpath, pb_bytes),
        ...
    ]
    Performs ONE gNMI SET RPC with multiple -x / -bytes-file pairs
    """

    env = GNMIEnvironment(duthost)
    ip, port = env.get_gnmi_target()

    # start building the command
    cmd = (
        f"{env.python_bin} {env.client_path} "
        f"-t {ip} -p {port} "
        f"-rcert /root/gnmi_ca.pem "
        f"-pkey /root/gnmi_client.key "
        f"-cchain /root/gnmi_client.crt "
        f"-m set-update "
        f"--encoding 1 "
    )

    # append each update
    for (xpath, pb_bytes) in update_list:
        filename = f"update_{uuid.uuid4().hex}.bin"
        local = f"/tmp/{filename}"
        remote = f"/root/{filename}"

        with open(local, "wb") as f:
            f.write(pb_bytes)

        ptfhost.copy(src=local, dest=remote)

        # Use clean xpath; assume CLI supports raw bytes from file
        gnmi_xpath = xpath
        cmd += f"-x {gnmi_xpath} -val {remote} "

    logger.info("GNMI MULTI-UPDATE CMD: %s", cmd)
    out = ptfhost.shell(cmd, module_ignore_errors=True)
    if out.get("rc", 1) != 0:
        raise RuntimeError(f"GNMI MULTI-SET FAILED: {out}")
