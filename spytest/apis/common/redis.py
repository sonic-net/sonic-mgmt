import re
import json
import tempfile
from spytest import st
from utilities.utils import remove_last_line_from_string

APPL_DB = "APPL_DB"
ASIC_DB = "ASIC_DB"
COUNTERS_DB = "COUNTERS_DB"
LOGLEVEL_DB = "LOGLEVEL_DB"
CONFIG_DB = "CONFIG_DB"
PFC_WD_DB = "PFC_WD_DB"
FLEX_COUNTER_DB = "FLEX_COUNTER_DB"
STATE_DB = "STATE_DB"
SNMP_OVERLAY_DB = "SNMP_OVERLAY_DB"
ERROR_DB = "ERROR_DB"

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
    APPL_DB: 63792,
    ASIC_DB: 6379,
    COUNTERS_DB: 63796,
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
    if db_cli in ["0", "1", "2"]:
        return db_cli
    output = st.show(dut, 'ls /usr/local/bin/sonic-db-cli', skip_tmpl=True)
    return "0" if re.search(r'No such file or directory', output) else "2"


def db_map_read(dut):
    global db_port_map

    if st.is_dry_run() or st.getenv("SPYTEST_REDIS_DB_USE_DEFAULT_PORTMAP", "0") != "0":
        st.warn("Using default port map", dut=dut)
        db_port_map = db_default_port_map
        return

    db_json = st.config(dut, "cat /var/run/redis/sonic-db/database_config.json")
    db_json = st.remove_prompt(dut, db_json).split("\n")
    try:
        db_dict = json.loads("".join(db_json))
        db_instances = db_dict.get("INSTANCES")
        for db_name, db_data in db_dict.get("DATABASES").items():
            db_port_map[db_name] = db_instances[db_data["instance"]].get("port")
    except Exception as exp:
        msg = ["Failed to read data base config"]
        msg.append("Using default port map")
        msg.append(str(exp))
        st.error(" - ".join(msg), dut=dut)
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
    cmd = "{} --scan --pattern '{}'".format(_prefix(dut, db), pattern)
    return st.config(dut, cmd, skip_error_check=skip_error_check)


def dump(dut, db, pattern, skip_error_check=False):
    cmd = "{} -k '{}' -y".format(_prefix(dut, db, "dump"), pattern)
    return st.config(dut, cmd, skip_error_check=skip_error_check)


def build(dut, db, cmd):
    return "{} {}".format(_prefix(dut, db), cmd)


def build_sonic_db_cli(db, cmd):
    return 'sonic-db-cli {} "{}"'.format(db, cmd)


def redis_show(dut, db, cmd):
    redis_cmd = "sonic-db-cli {} \"{}\"".format(db, cmd)
    dump = st.show(dut, redis_cmd, skip_tmpl=True)
    gen = (item for item in dump.split('\n'))
    result = {}
    for item in gen:
        result[item] = next(gen, u'')
    return result


def config(dut, db, cmd, skip_error_check=False):
    dev_cmd = build(dut, db, cmd)
    return st.config(dut, dev_cmd, skip_error_check=skip_error_check)


def show(dut, db, cmd, skip_tmpl=False):
    dev_cmd = build(dut, db, cmd)
    return st.show(dut, dev_cmd, skip_tmpl=skip_tmpl)


def hgetall(dut, db, tbl):
    dev_cmd = build(dut, db, "hgetall '{}'".format(tbl))
    output = st.show(dut, dev_cmd, skip_tmpl=True)
    st.debug(output)
    parsed = st.parse_show(dut, dev_cmd, output, "redis_cli_hgetall.tmpl")
    st.debug(parsed)
    retval = {}
    for [name, value] in parsed:
        if name:
            retval[name] = value
    return [retval]


def keys(dut, db, search):
    dev_cmd = build(dut, db, "keys {}".format(search))
    output = st.show(dut, dev_cmd, skip_tmpl=True)
    st.debug(output)
    parsed = st.parse_show(dut, dev_cmd, output, "show_redis_cli_key_search.tmpl")
    st.debug(parsed)
    retval = []
    for [name, value] in parsed:
        if name:
            retval.append(value)
    return retval


def multi(dut, db, cmd_list, skip_error_check=False):
    """multi executes a list of redis commands within MULTI/EXEC
    transaction. Either all of the commands or none are processed.
    """
    tmp_file = tempfile.NamedTemporaryFile(mode='w+t', prefix='multi_')
    tmp_file.write("multi\n" + "\n".join(cmd_list) + "\nexec")
    tmp_file.flush()
    st.upload_file_to_dut(dut, tmp_file.name, tmp_file.name)
    cmd = 'redis-cli -p {} -n {} -x < {} | tee'.format(port(db), id(db), tmp_file.name)
    return st.config(dut, cmd, skip_error_check=skip_error_check)


def id(db):
    if db and db not in db_id_map:
        raise ValueError("Unknown DB name {} in ID Map".format(db))
    return db_id_map[db]


def port(db):
    if db and db not in db_port_map:
        raise ValueError("Unknown DB name {} in Port Map".format(db))
    return db_port_map[db]


def build_std_redis_cli(dut, skip_error_check=False):
    """
    Api to build standard redis cli
    :param dut:
    :param skip_error_check:
    :return:
    """
    command = "sudo bash -c ' mkdir -p /tmp/std_redisclient; cd /tmp/std_redisclient/; " \
              "docker cp database:/usr/bin/redis-cli .; " \
              "docker cp database:/usr/lib/x86_64-linux-gnu/liblua5.1-cjson.so.0.0.0 .; " \
              "docker cp database:/usr/lib/x86_64-linux-gnu/liblua5.1-bitop.so.0.0.0 .; " \
              "docker cp database:/usr/lib/x86_64-linux-gnu/liblua5.1.so.0.0.0 .; " \
              "docker cp database:/usr/lib/x86_64-linux-gnu/libjemalloc.so.2 .; " \
              "ln -sf liblua5.1-cjson.so.0.0.0 liblua5.1-cjson.so.0;" \
              " ln -sf liblua5.1-bitop.so.0.0.0 liblua5.1-bitop.so.0; ln -sf liblua5.1.so.0.0.0 liblua5.1.so.0; '"
    st.config(dut, command, skip_error_check=skip_error_check)
    cmd = "[ ! -e /tmp/std_redisclient/redis-cli ]; echo $?"
    result = remove_last_line_from_string(st.show(dut, cmd, skip_tmpl=True))
    return int(result)


def config_redis_db(con_obj, cmd=""):
    """
    Api to configure with redis-cli using connection object
    :param con_obj:
    :param cmd:
    :return:
    """
    prompt = con_obj.find_prompt()
    result = con_obj.send_command(cmd, expect_string=prompt, max_loops=50, delay_factor=5)
    if "permission denied" in result:
        st.log("Configuration failed using redis-cli")
        return False
    else:
        st.log("Successfully configured using redis-cli")
        return True


def redis_db_authentication(dut, verify=False):
    """
    API to fetch/verify the whether redis-db authentication is enabled or not
    :param dut:
    :return:
    """
    command = "docker exec -it database cat /etc/redis/redis.conf | grep requirepass"
    result = remove_last_line_from_string(st.config(dut, command, type="click"))
    if not verify:
        return result
    else:
        match = re.findall(r"requirepass\s+\S+", result)
        st.debug(match)
        if not match:
            return False
        else:
            return True
