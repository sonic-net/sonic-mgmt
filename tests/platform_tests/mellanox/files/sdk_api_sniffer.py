#!/usr/bin/env python
"""Enable/disable SDK API sniffer (SX-API logger) at runtime inside syncd.

Intended to be copied into the syncd container and run with the container's
python_sdk_api, same pattern as qos/files/mellanox/packets_aging.py.
"""

from __future__ import print_function

import argparse
import errno
import sys

from python_sdk_api.sx_api import (
    SX_STATUS_SUCCESS,
    SX_ACCESS_CMD_ENABLE,
    SX_ACCESS_CMD_DISABLE,
    SX_DBG_API_LOGGER_DISABLED_MODE,
    SX_DBG_API_LOGGER_LINEAR_MODE,
    SX_DBG_API_LOGGER_CYCLIC_MODE,
    SX_DBG_API_LOGGER_FILTER_NONE_MODE,
    SX_DBG_API_LOGGER_FILTER_EXCLUDE_APIS_MODE,
    sx_api_open,
    sx_api_close,
    sx_api_dbg_api_logger_get,
    sx_api_dbg_api_logger_set,
    new_sx_dbg_api_logger_params_t_p,
    delete_sx_dbg_api_logger_params_t_p,
)

MODE_NAMES = {
    SX_DBG_API_LOGGER_DISABLED_MODE: "disabled",
    SX_DBG_API_LOGGER_LINEAR_MODE: "linear",
    SX_DBG_API_LOGGER_CYCLIC_MODE: "cyclic",
}

DEFAULT_LOG_PATH = "/var/log/sdk_dbg"
DEFAULT_FILTER_FILE = "/usr/bin/sx_def_filter"
DEFAULT_CYCLIC_MAX_SIZE = 300 * 1024 * 1024
DEFAULT_CYCLIC_LOG_NUM = 10
DEFAULT_CYCLIC_WRITE_INTERVAL_MS = 1000


def open_sdk():
    rc, handle = sx_api_open(None)
    if rc != SX_STATUS_SUCCESS:
        sys.stderr.write("Failed to open api handle.\nPlease check that SDK is running.\n")
        sys.exit(errno.EACCES)
    return handle


def get_params(handle):
    params_p = new_sx_dbg_api_logger_params_t_p()
    rc = sx_api_dbg_api_logger_get(handle, params_p)
    if rc != SX_STATUS_SUCCESS:
        delete_sx_dbg_api_logger_params_t_p(params_p)
        sys.stderr.write("sx_api_dbg_api_logger_get failed, rc=%d\n" % rc)
        sys.exit(rc)
    return params_p


def set_sysfs_defaults(params_p):
    try:
        params_p.sysfs_logger_mode.sysfs_sniffer_disable = False
        params_p.sysfs_logger_mode.sysfs_sniffer_include_read_access = True
    except AttributeError:
        params_p.sysfs_sniffer_disable = False
        params_p.sysfs_sniffer_include_read_access = True


def fill_enable_params(params_p, mode_name):
    params_p.log_file_path = DEFAULT_LOG_PATH
    set_sysfs_defaults(params_p)
    if mode_name == "cyclic":
        params_p.logger_mode = SX_DBG_API_LOGGER_CYCLIC_MODE
        params_p.logger_mode_params.cyclic_params.max_log_size = DEFAULT_CYCLIC_MAX_SIZE
        params_p.logger_mode_params.cyclic_params.log_file_num = DEFAULT_CYCLIC_LOG_NUM
        params_p.write_interval = DEFAULT_CYCLIC_WRITE_INTERVAL_MS
        params_p.filter_mode = SX_DBG_API_LOGGER_FILTER_EXCLUDE_APIS_MODE
        params_p.filter_file_path = DEFAULT_FILTER_FILE
    else:
        params_p.logger_mode = SX_DBG_API_LOGGER_LINEAR_MODE
        params_p.logger_mode_params.linear_params.max_log_size = 0xffffffff
        params_p.write_interval = 0
        params_p.filter_mode = SX_DBG_API_LOGGER_FILTER_NONE_MODE
        params_p.filter_file_path = ""


def cmd_status(handle):
    params_p = get_params(handle)
    try:
        mode = int(params_p.logger_mode)
        print("MODE=%d" % mode)
        print("MODE_NAME=%s" % MODE_NAMES.get(mode, "unknown"))
    finally:
        delete_sx_dbg_api_logger_params_t_p(params_p)


def cmd_disable(handle):
    params_p = get_params(handle)
    try:
        mode = int(params_p.logger_mode)
        print("PREV_MODE=%d" % mode)
        print("PREV_MODE_NAME=%s" % MODE_NAMES.get(mode, "unknown"))
        if mode == SX_DBG_API_LOGGER_DISABLED_MODE:
            print("CHANGED=0")
            return
        rc = sx_api_dbg_api_logger_set(handle, SX_ACCESS_CMD_DISABLE, params_p)
        if rc != SX_STATUS_SUCCESS:
            sys.stderr.write("sx_api_dbg_api_logger_set DISABLE failed, rc=%d\n" % rc)
            sys.exit(rc)
        print("CHANGED=1")
    finally:
        delete_sx_dbg_api_logger_params_t_p(params_p)


def cmd_enable(handle, mode_name):
    cur = get_params(handle)
    try:
        mode = int(cur.logger_mode)
        if mode != SX_DBG_API_LOGGER_DISABLED_MODE:
            print("ALREADY_ENABLED=1")
            print("MODE=%d" % mode)
            print("MODE_NAME=%s" % MODE_NAMES.get(mode, "unknown"))
            return
    finally:
        delete_sx_dbg_api_logger_params_t_p(cur)

    params_p = new_sx_dbg_api_logger_params_t_p()
    try:
        fill_enable_params(params_p, mode_name)
        rc = sx_api_dbg_api_logger_set(handle, SX_ACCESS_CMD_ENABLE, params_p)
        if rc != SX_STATUS_SUCCESS:
            sys.stderr.write("sx_api_dbg_api_logger_set ENABLE failed, rc=%d\n" % rc)
            sys.exit(rc)
        print("CHANGED=1")
        print("MODE_NAME=%s" % mode_name)
    finally:
        delete_sx_dbg_api_logger_params_t_p(params_p)


def main():
    parser = argparse.ArgumentParser(
        description="Toggle SDK API sniffer (SX-API logger) inside syncd")
    parser.add_argument(
        "command",
        choices=["status", "disable", "enable"],
        help="status: print current mode; disable: stop sniffer; "
             "enable: start sniffer with SONiC-like defaults")
    parser.add_argument(
        "--mode",
        choices=["cyclic", "linear"],
        default="cyclic",
        help="Mode used by enable (default: cyclic)")
    args = parser.parse_args()

    handle = open_sdk()
    try:
        if args.command == "status":
            cmd_status(handle)
        elif args.command == "disable":
            cmd_disable(handle)
        else:
            cmd_enable(handle, args.mode)
    finally:
        sx_api_close(handle)


if __name__ == "__main__":
    sys.exit(main())
