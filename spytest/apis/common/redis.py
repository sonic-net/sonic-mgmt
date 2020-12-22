import re
import json
from spytest import st

APPL_DB = "APPL_DB"
ASIC_DB = "ASIC_DB"
COUNTERS_DB = "COUNTERS_DB"
LOGLEVEL_DB = "LOGLEVEL_DB"
CONFIG_DB = "CONFIG_DB"
PFC_WD_DB =  "PFC_WD_DB"
FLEX_COUNTER_DB = "FLEX_COUNTER_DB"
STATE_DB = "STATE_DB"
SNMP_OVERLAY_DB = "SNMP_OVERLAY_DB"
ERROR_DB = "ERROR_DB"

########################## TODO ####################################
# read db_port_map from /var/run/redis/sonic-db/database_config.json
####################################################################
db_id_map = {
    APPL_DB: 0,
    ASIC_DB: 1,
    COUNTERS_DB: 2,
    LOGLEVEL_DB: 3,
    CONFIG_DB: 4,
    PFC_WD_DB: 5,
    FLEX_COUNTER_DB: 5,
    STATE_DB: 6,
    SNMP_OVERLAY_DB: 7,
    ERROR_DB: 8
}

# Port map used for A/A+/B/B-MR
db_default_port_map = {
    APPL_DB: 6379,
    ASIC_DB: 6379,
    COUNTERS_DB: 6379,
    LOGLEVEL_DB: 6379,
    CONFIG_DB: 6379,
    PFC_WD_DB: 6379,
    FLEX_COUNTER_DB: 6379,
    STATE_DB: 6379,
    SNMP_OVERLAY_DB: 6379,
    ERROR_DB: 6379
}

# Read /var/run/redis/sonic-db/database_config.json on DUT and populate db_port_map
db_port_map = {}

# 0 - use redis-cli
# 1 - use redis-cli -p
# 2 - use sonic-db-cli
def db_cli_init(dut):
    db_map_read(dut)
    db_cli = st.getenv("SPYTEST_REDIS_DB_CLI_TYPE", "1")
    if db_cli in ["1", "2"]: db_map_read(dut)
    if db_cli in ["0", "1", "2"]: return db_cli
    output = st.show(dut,'ls /usr/local/bin/sonic-db-cli',skip_tmpl=True)
    return "0" if re.search(r'No such file or directory',output) else "2"

def db_map_read(dut):
    global db_port_map
    db_dict = None
    db_json = st.config(dut, "cat /var/run/redis/sonic-db/database_config.json").split("\n")
    db_json.pop()
    try:
        db_dict = json.loads("".join(db_json))
        db_instances = db_dict.get("INSTANCES")
        for db_name, db_data in db_dict.get("DATABASES").items():
            db_port_map[db_name] = db_instances[db_data["instance"]].get("port")
    except Exception:
        db_port_map = db_default_port_map

def _prefix(dut, db, suffix="cli"):
    db_cli = st.get_dut_var(dut, "redis_db_cli")

    if db and db not in db_id_map:
        raise ValueError("Unknown DB name {} in ID Map".format(db))
    if db and db not in db_port_map:
        raise ValueError("Unknown DB name {} in Port Map".format(db))

    if db_cli == "2":
        return "sonic-db-{} {}".format(suffix, db or "")

    if db_cli == "1":
        cmd = "redis-{} -p {}".format(suffix, db_port_map[db])
    else:
        cmd = "redis-{}".format(suffix)

    return "{} -n {}".format(cmd, db_id_map[db]) if db else cmd

def scan(dut, db, pattern, skip_error_check=False):
    cmd="{} --scan --pattern '{}'".format(_prefix(dut, db), pattern)
    return st.config(dut, cmd, skip_error_check=skip_error_check)

def dump(dut, db, pattern, skip_error_check=False):
    cmd="{} -k '{}' -y".format(_prefix(dut, db, "dump"), pattern)
    return st.config(dut, cmd, skip_error_check=skip_error_check)

def build(dut, db, cmd):
    return "{} {}".format(_prefix(dut, db), cmd)

def config(dut, db, cmd, skip_error_check=False):
    dev_cmd = build(dut, db, cmd)
    return st.config(dut, dev_cmd, skip_error_check=skip_error_check)

def show(dut, db, cmd, skip_tmpl=False):
    dev_cmd = build(dut, db, cmd)
    return st.show(dut, dev_cmd, skip_tmpl=skip_tmpl)

