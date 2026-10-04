import json
import logging
from . import proto_utils
import time

from pygnmi.client import gNMIclient
from pygnmi.create_gnmi_path import gnmi_path_generator
from pygnmi.spec.v080.gnmi_pb2 import SetRequest, Update, TypedValue

TIME_BETWEEN_CHUNKS = 1


def _build_typed_value(value, encoding):
    """Build a gNMI TypedValue from a Python value for the given encoding."""
    if encoding == 'proto':
        # Caller is expected to pre-encode to bytes via proto_utils.json_to_proto
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(
                "proto encoding requires bytes value, got %s" % type(value).__name__
            )
        return TypedValue(proto_bytes=bytes(value))
    if encoding == 'json_ietf':
        return TypedValue(json_ietf_val=json.dumps(value).encode('utf-8'))
    if encoding == 'json':
        return TypedValue(json_val=json.dumps(value).encode('utf-8'))
    if encoding == 'ascii':
        return TypedValue(ascii_val=str(value).encode('utf-8'))
    if encoding == 'bytes':
        if isinstance(value, (bytes, bytearray)):
            return TypedValue(bytes_val=bytes(value))
        return TypedValue(bytes_val=json.dumps(value).encode('utf-8'))
    raise ValueError("Unsupported encoding: %s" % encoding)


def _build_updates(items, encoding):
    """Build a list of gnmi_pb2.Update messages from (path, value) tuples."""
    msgs = []
    for path, value in items:
        u_path = gnmi_path_generator(path)
        u_val = _build_typed_value(value, encoding)
        msgs.append(Update(path=u_path, val=u_val))
    return msgs


class GNMIEnvironment:
    gnmi_ip = "127.0.0.1"
    gnmi_port = 8080
    work_dir = "/"
    username = "cisco"
    password = "cisco123"
    dpu_index = 0
    num_dpus = 1
    # Optional pre-opened pygnmi client to be reused across multiple
    # gnmi_set/gnmi_get calls in the same command run. If None, each call
    # opens and closes its own short-lived client.
    gc = None


def _make_client(env):
    return gNMIclient(
        target=(env.gnmi_ip, env.gnmi_port),
        username=env.username,
        password=env.password,
        insecure=True,
        skip_verify=True,
    )


class _ClientHandle:
    """Context manager that yields env.gc if it is already connected,
    otherwise opens a fresh short-lived gNMIclient."""
    def __init__(self, env):
        self._env = env
        self._owned = None

    def __enter__(self):
        if getattr(self._env, "gc", None) is not None:
            return self._env.gc
        self._owned = _make_client(self._env)
        return self._owned.__enter__()

    def __exit__(self, exc_type, exc, tb):
        if self._owned is not None:
            return self._owned.__exit__(exc_type, exc, tb)
        return False


def gnmi_set(env, delete_list, update_list, replace_list):
    """
    Send GNMI set request using the pygnmi client.

    Args:
        env: GNMIEnvironment
        delete_list: list of gNMI path strings
        update_list: list of (path, value) tuples; value is bytes (proto) or a
            JSON-serializable Python object
        replace_list: list of (path, value) tuples; same value semantics as update_list
    """
    saw_proto = False

    for path in delete_list:
        logging.info("Deleting " + path)

    for path, value in update_list:
        if isinstance(value, (bytes, bytearray)):
            saw_proto = True
        logging.info("Updating " + path)

    for path, value in replace_list:
        if isinstance(value, (bytes, bytearray)):
            saw_proto = True
        logging.info("Replacing " + path)

    encoding = 'proto' if (saw_proto or proto_utils.ENABLE_PROTO) else 'json_ietf'

    try:
        with _ClientHandle(env) as gc:
            # pygnmi's gc.set() always json.dumps the value, which fails for
            # raw proto bytes. Bypass it by building the SetRequest manually
            # and sending it via the underlying gRPC stub. The stub attribute
            # is name-mangled inside gNMIclient.
            stub = getattr(gc, "_gNMIclient__stub", None)
            metadata = getattr(gc, "_gNMIclient__metadata", None)
            if stub is None:
                raise RuntimeError("Failed to access gNMI stub from pygnmi client")

            del_paths = [gnmi_path_generator(p) for p in delete_list]
            update_msgs = _build_updates(update_list, encoding)
            replace_msgs = _build_updates(replace_list, encoding)

            req = SetRequest(
                delete=del_paths,
                update=update_msgs,
                replace=replace_msgs,
            )
            result = stub.Set(req, metadata=metadata)
        logging.info("Command executed successfully")
        logging.debug(result)
    except Exception as e:
        logging.error(
            "GNMI set failed: type=%s repr=%s str=%s",
            type(e).__name__, repr(e), str(e),
        )
        # gRPC errors carry extra info in .code()/.details()
        for attr in ("code", "details", "debug_error_string"):
            fn = getattr(e, attr, None)
            if callable(fn):
                logging.error("GNMI set failed [%s]: %s", attr, fn())

    return


def gnmi_get(env, path_list):
    """
    Send GNMI get request using the pygnmi client.

    Args:
        env: GNMIEnvironment
        path_list: list of gNMI path strings

    Returns:
        None (results are printed)
    """
    encoding = 'proto' if proto_utils.ENABLE_PROTO else 'json_ietf'

    for path in path_list:
        # Extract the table segment, e.g. DASH_APPLIANCE_TABLE, from a path
        # like /sonic-db:DPU_APPL_DB/dpu0/DASH_APPLIANCE_TABLE[key=100].
        # The first element after splitting on '/' that contains '[' (or the
        # last non-empty element) is the table-with-key; drop the '[...]'.
        tblname = ''
        for seg in path.split('/'):
            if not seg:
                continue
            if 'DASH_' in seg and '_TABLE' in seg:
                tblname = seg.split('[', 1)[0]
                if tblname.startswith('_'):
                    tblname = tblname[1:]
                break

        print("-" * 25)
        print(path)

        try:
            with _ClientHandle(env) as gc:
                response = gc.get(path=[path], encoding=encoding)
        except Exception as e:
            msg = str(e)
            if "rpc error" in msg:
                print("GRPC error: " + msg.split("rpc error", 1)[1])
            else:
                print("command failed: " + msg)
            continue

        # pygnmi returns:
        #   {'notification': [{'update': [{'path': ..., 'val': ...}], ...}, ...]}
        val = None
        for notif in (response or {}).get('notification', []) or []:
            for upd in notif.get('update', []) or []:
                val = upd.get('val')
                break
            if val is not None:
                break

        if val is None:
            print("(empty response)")
            continue

        if encoding == 'proto' and isinstance(val, (bytes, bytearray)):
            pb_obj = proto_utils.from_pb(tblname, bytes(val))
            print(pb_obj)
        else:
            print(val)


def process_template_chunk(res, env, dest_path, batch_val, sleep_secs):

    get_list = []
    delete_list = []
    update_list = []
    replace_list = []
    base_path = "/sonic-db:DPU_APPL_DB"
    base_path = "%s/dpu%d" % (base_path, env.dpu_index)
    batch_cnt = 0

    for operation in res:
        batch_cnt += 1
        if operation["OP"] == "SET" or operation["OP"] == "REP":
            for k, v in operation.items():
                if k == "OP":
                    continue
                logging.debug("Config Json %s" % k)
                if proto_utils.ENABLE_PROTO:
                    value = proto_utils.json_to_proto(k, v)
                else:
                    value = v
                keys = k.split(":", 1)
                k = keys[0] + "[key=" + keys[1] + "]"
                path = "%s/%s" % (base_path, k)
                if operation["OP"] == "REP":
                    replace_list.append((path, value))
                else:
                    update_list.append((path, value))
        elif operation["OP"] == "DEL":
            for k, v in operation.items():
                if k == "OP":
                    continue
                keys = k.split(":", 1)
                k = keys[0] + "[key=" + keys[1] + "]"
                path = "%s/%s" % (base_path, k)
                delete_list.append(path)
        elif operation["OP"] == "GET":
            for k, v in operation.items():
                if k == "OP":
                    continue
                if ":" not in k:
                    continue
                keys = k.split(":", 1)
                k = keys[0] + "[key=" + keys[1] + "]"
                path = "%s/%s" % (base_path, k)
                get_list.append(path)
        else:
            logging.error("Invalid operation %s" % operation["OP"])
            batch_cnt -= 1

        if batch_cnt == batch_val:
            time.sleep(sleep_secs)
            if get_list:
                gnmi_get(env, get_list)
            if delete_list or update_list or replace_list:
                gnmi_set(env, delete_list, update_list, replace_list)
            batch_cnt = 0
            delete_list = []
            update_list = []
            replace_list = []
            get_list = []

    if get_list:
        gnmi_get(env, get_list)
    if delete_list or update_list or replace_list:
        gnmi_set(env, delete_list, update_list, replace_list)


def apply_gnmi_file(env, dest_path, batch_val=10, sleep_secs=0):
    """
    Apply dash configuration with gnmi client

    Args:
        env: GNMIEnvironment
        dest_path: configuration file path
        batch_val: how many commands in one batch
        sleep_secs: how many seconds to sleep between sending a batch and next

    Returns:
    """
    with open(dest_path, 'r') as file:
        res = json.load(file)

    if isinstance(res[0], dict):
        process_template_chunk(res, env, dest_path, batch_val, sleep_secs)
    else:
        for i in res:
            process_template_chunk(i, env, dest_path, batch_val, sleep_secs)
            if sleep_secs > 0:
                time.sleep(sleep_secs)
            else:
                time.sleep(TIME_BETWEEN_CHUNKS)
