import json
import logging
import time
import uuid
from functools import lru_cache

import pytest

logger = logging.getLogger(__name__)

#
# ----------------------------
#  GNMI ENVIRONMENT
# ----------------------------
#


@lru_cache(maxsize=None)
class GNMIEnvironment:
    def __init__(self, duthost):
        self.work_dir = "/tmp/" + str(uuid.uuid4()) + "/"
        self.gnmi_cert_path = "/etc/sonic/telemetry/"
        self.gnmi_ca_cert = "gnmiCA.pem"
        self.gnmi_ca_key = "gnmiCA.key"
        self.gnmi_server_cert = "gnmiserver.crt"
        self.gnmi_server_key = "gnmiserver.key"
        self.gnmi_client_cert = "gnmiclient.crt"
        self.gnmi_client_key = "gnmiclient.key"
        self.gnmi_server_start_wait_time = 30
        self.enable_zmq = True

        # Detect container
        if duthost.shell("docker ps | grep -w gnmi", module_ignore_errors=True)['rc'] == 0:
            self.gnmi_container = "gnmi"
            self.gnmi_program = "gnmi-native"
            self.gnmi_port = 50052
            return
        else:
            pytest.fail("GNMI container not running")

#
# ----------------------------
#  CERTIFICATE GENERATION
# ----------------------------
#


def create_ext_conf(ip, filename):
    txt = f"""
[ req_ext ]
subjectAltName = @alt_names
[alt_names]
IP = {ip}
"""
    with open(filename, "w") as f:
        f.write(txt)


def generate_gnmi_cert(localhost, duthost):
    env = GNMIEnvironment(duthost)
    localhost.shell(f"mkdir -p {env.work_dir}")

    server_cn = "ndastreamingservertest"
    server_ip = duthost.mgmt_ip
    ext_file = f"{env.work_dir}ext.cnf"

    #
    # 1. Create SAN extension config
    #
    san_cfg = f"""
[req]
distinguished_name=req
req_extensions=req_ext

[req_ext]
subjectAltName=DNS:{server_cn},IP:{server_ip}
"""
    localhost.shell(f"echo \"{san_cfg}\" > {ext_file}")

    #
    # 2. Generate CA
    #
    localhost.shell(f"openssl genrsa -out {env.work_dir}{env.gnmi_ca_key} 2048")
    localhost.shell(
        f"openssl req -x509 -new -nodes "
        f"-key {env.work_dir}{env.gnmi_ca_key} "
        f"-subj '/CN=sonic-gnmi-ca' "
        f"-days 1825 "
        f"-out {env.work_dir}{env.gnmi_ca_cert}"
    )

    #
    # 3. Server private key + CSR with correct CN
    #
    localhost.shell(f"openssl genrsa -out {env.work_dir}{env.gnmi_server_key} 2048")

    localhost.shell(
        f"openssl req -new "
        f"-key {env.work_dir}{env.gnmi_server_key} "
        f"-subj '/CN={server_cn}' "
        f"-out {env.work_dir}gnmiserver.csr "
        f"-config {ext_file}"
    )

    #
    # 4. Sign server cert with SAN
    #
    localhost.shell(
        f"openssl x509 -req "
        f"-in {env.work_dir}gnmiserver.csr "
        f"-CA {env.work_dir}{env.gnmi_ca_cert} "
        f"-CAkey {env.work_dir}{env.gnmi_ca_key} "
        f"-CAcreateserial "
        f"-out {env.work_dir}{env.gnmi_server_cert} "
        f"-days 825 -sha256 "
        f"-extensions req_ext -extfile {ext_file}"
    )

    #
    # 5. Client key + cert (unchanged)
    #
    localhost.shell(f"openssl genrsa -out {env.work_dir}{env.gnmi_client_key} 2048")
    localhost.shell(
        f"openssl req -new "
        f"-key {env.work_dir}{env.gnmi_client_key} "
        f"-subj '/CN=gnmi-client' "
        f"-out {env.work_dir}gnmiclient.csr"
    )
    localhost.shell(
        f"openssl x509 -req "
        f"-in {env.work_dir}gnmiclient.csr "
        f"-CA {env.work_dir}{env.gnmi_ca_cert} "
        f"-CAkey {env.work_dir}{env.gnmi_ca_key} "
        f"-CAcreateserial "
        f"-out {env.work_dir}{env.gnmi_client_cert} "
        f"-days 825 -sha256"
    )


#
# ----------------------------
#  APPLY CERTS TO DUT & PTF
# ----------------------------
#

def apply_gnmi_cert(duthost, ptfhost):
    env = GNMIEnvironment(duthost)

    # Push certs to DUT
    for f in [env.gnmi_ca_cert, env.gnmi_server_cert, env.gnmi_server_key]:
        duthost.copy(src=env.work_dir + f, dest=env.gnmi_cert_path)

    # Push certs to PTF
    for f in [env.gnmi_ca_cert, env.gnmi_client_cert, env.gnmi_client_key]:
        ptfhost.copy(src=env.work_dir + f, dest="/root/")

    # Restart GNMI server
    duthost.shell(f"docker exec {env.gnmi_container} supervisorctl stop {env.gnmi_program}")
    duthost.shell(f"docker exec {env.gnmi_container} pkill telemetry", module_ignore_errors=True)

    start_cmd = (
        f"docker exec {env.gnmi_container} bash -c "
        f"'nohup /usr/sbin/telemetry --port {env.gnmi_port} "
        f"--server_crt {env.gnmi_cert_path}{env.gnmi_server_cert} "
        f"--server_key {env.gnmi_cert_path}{env.gnmi_server_key} "
        f"--ca_crt {env.gnmi_cert_path}{env.gnmi_ca_cert} "
        f"-gnmi_native_write=true -logtostderr -v=5 >/root/gnmi.log 2>&1 &'"
    )
    duthost.shell(start_cmd)
    time.sleep(env.gnmi_server_start_wait_time)


def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list):
    import shlex

    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port

    #
    # ---- Base command ----
    #
    cmd = (
        f"/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py "
        f"--timeout 30 -t {ip} -p {port} "
        f"-rcert /root/{env.gnmi_ca_cert} "
        f"-pkey /root/{env.gnmi_client_key} "
        f"-cchain /root/{env.gnmi_client_cert} "
        f"-o ndastreamingservertest "
    )

    #
    # ---- Determine operation ----
    #
    if update_list:
        active_list = update_list
        mode = "set-update"
    elif replace_list:
        active_list = replace_list
        mode = "set-replace"
    elif delete_list:
        active_list = delete_list
        mode = "set-delete"
    else:
        return

    cmd += f"-m {mode} "

    xpath_items = []
    value_items = []

    #
    # ---- Parse entries ----
    #
    for entry in active_list:
        clean = entry.replace("sonic-db:", "").strip()

        # CASE 1: JSON string  key:"value"
        if clean.count(':"') == 1 and clean.endswith('"'):
            k, raw_val = clean.split(':"', 1)
            raw_val = raw_val[:-1]  # remove last quote
            v = f"\"{raw_val}\""    # keep quotes
            xpath_items.append(k)
            value_items.append(v)
            continue

        # CASE 2: JSON array  key:[ ... ]
        if ':[' in clean:
            k, raw_val = clean.split(':', 1)
            xpath_items.append(k)
            value_items.append(raw_val.strip())  # keep raw JSON
            continue

        # CASE 3: No value (delete case)
        if ":" not in clean:
            xpath_items.append(clean)
            value_items.append("")
            continue

        # CASE 4: fallback generic key:value
        k, raw_val = clean.split(":", 1)
        xpath_items.append(k)
        value_items.append(raw_val)

    #
    # ---- Build final command ----
    #
    xpath_str = " ".join(xpath_items).strip()
    value_str = " ".join(value_items).strip()

    # safe quoting
    xpath_str = shlex.quote(xpath_str)
    value_str = shlex.quote(value_str)

    cmd += f"--xpath {xpath_str} "
    if mode != "set-delete":
        cmd += f"--value {value_str}"

    #
    # ---- Execute ----
    #
    out = ptfhost.shell(cmd, module_ignore_errors=True)

    if out["rc"] != 0:
        raise Exception(f"GNMI UPDATE FAILED:\n{out}")

#
# ----------------------------
#  HA CONFIG APPLY
# ----------------------------
#


def ha_gnmi_apply_config(duthost, ptfhost, ha_set_json, ha_scope_json):
    """
    Apply HA-SET + HA-SCOPE configs using Option 1 GNMI format.
    """

    update_list = []

    # HA-SET
    for key, fields in ha_set_json["DASH_HA_SET_CONFIG_TABLE"].items():
        for f, v in fields.items():
            v_str = json.dumps(v) if isinstance(v, list) else f"\"{v}\""
            update_list.append(
                f"sonic-db:/APPL_DB/DASH_HA_SET_CONFIG_TABLE/{key}/{f}:{v_str}"
            )

    # HA-SCOPE
    for key, fields in ha_scope_json["DASH_HA_SCOPE_CONFIG_TABLE"].items():
        dpu, ha = key.split("|")
        for f, v in fields.items():
            v_str = json.dumps(v) if isinstance(v, list) else f"\"{v}\""
            update_list.append(
                f"sonic-db:/APPL_DB/DASH_HA_SCOPE_CONFIG_TABLE/{dpu}|{ha}/{f}:{v_str}"
            )

    # Send one-by-one
    for entry in update_list:
        gnmi_set(duthost, ptfhost, [], [entry], [])
        time.sleep(0.2)
