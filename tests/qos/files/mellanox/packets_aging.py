#!/usr/bin/env python
'''
This file contains Python script to enable/disable packets aging in queues(buffers?).
'''

import sys
import errno
import argparse
from python_sdk_api.sx_api import (SX_STATUS_SUCCESS,
                                   SX_ACCESS_CMD_GET,
                                   SX_ACCESS_CMD_GET_FIRST,
                                   sx_api_open,
                                   sx_api_port_device_get,
                                   sx_api_lag_port_group_iter_get,
                                   sx_port_log_id_t_arr_getitem,
                                   sx_api_lag_port_group_get,
                                   sx_api_port_sll_set,
                                   sx_api_port_sll_get,
                                   sx_api_port_hll_set,
                                   sx_api_port_hll_get,
                                   new_sx_port_attributes_t_arr,
                                   new_sx_port_log_id_t_arr,
                                   new_uint32_t_p,
                                   uint32_t_p_assign,
                                   uint32_t_p_value,
                                   new_uint64_t_p,
                                   uint64_t_p_value,
                                   sx_port_attributes_t_arr_getitem)

parser = argparse.ArgumentParser(description='Toggle Mellanox-specific packet aging on egress queues')
parser.add_argument('command', choices=['enable', 'disable'], type=str, help='Enable/Disable packet aging')
args = parser.parse_args()

# Open SDK
rc, handle = sx_api_open(None)
if (rc != SX_STATUS_SUCCESS):
    sys.stderr.write("Failed to open api handle.\nPlease check that SDK is running.\n")
    sys.exit(errno.EACCES)

# Get number of LAGs
lag_id_cnt_p = new_uint32_t_p()
uint32_t_p_assign(lag_id_cnt_p, 0)
lag_id = 0
rc = sx_api_lag_port_group_iter_get(handle, SX_ACCESS_CMD_GET, 0, lag_id, None, None, lag_id_cnt_p)
if rc != SX_STATUS_SUCCESS:
    print(("sx_api_lag_port_group_iter_get failed, rc = %d" % (rc)))
    sys.exit(rc)
lag_id_cnt = uint32_t_p_value(lag_id_cnt_p)

lag_id_list_p = new_sx_port_log_id_t_arr(lag_id_cnt)
rc = sx_api_lag_port_group_iter_get(handle, SX_ACCESS_CMD_GET_FIRST, 0, lag_id, None, lag_id_list_p,
                                    lag_id_cnt_p)
if rc != SX_STATUS_SUCCESS:
    print(("sx_api_lag_port_group_iter_get failed, rc = %d" % (rc)))
    sys.exit(rc)
lag_id_cnt = uint32_t_p_value(lag_id_cnt_p)

# Get number of ports
port_attributes_list = new_sx_port_attributes_t_arr(0)
port_cnt_p = new_uint32_t_p()
uint32_t_p_assign(port_cnt_p, 0)

rc = sx_api_port_device_get(handle, 1, 0, port_attributes_list,  port_cnt_p)
if (rc != SX_STATUS_SUCCESS):
    sys.stderr.write("An error returned by sx_api_port_device_get.\n")
    sys.exit()
port_cnt = uint32_t_p_value(port_cnt_p)

sys.stderr.write("Got port count {}\n".format(port_cnt))

lag_list = []
lag_member_list = []

for i in range(0, lag_id_cnt):
    lag_id = sx_port_log_id_t_arr_getitem(lag_id_list_p, i)
    log_port_cnt_p = new_uint32_t_p()
    uint32_t_p_assign(log_port_cnt_p, port_cnt)
    log_port_list_p = new_sx_port_log_id_t_arr(port_cnt)
    rc = sx_api_lag_port_group_get(handle, 0, lag_id, log_port_list_p, log_port_cnt_p)
    if rc != SX_STATUS_SUCCESS:
        print(("sx_api_lag_port_group_get failed, rc = %d" % (rc)))
        sys.exit(rc)
    log_port_cnt = uint32_t_p_value(log_port_cnt_p)
    for j in range(0, log_port_cnt):
        log_port_id = sx_port_log_id_t_arr_getitem(log_port_list_p, j)
        lag_member_list.append(log_port_id)
    lag_list.append(lag_id)

sys.stderr.write("Got LAG ports {}\n".format(lag_list))
sys.stderr.write("Got LAG member ports {}\n".format(lag_member_list))

# Get list of ports
port_attributes_list = new_sx_port_attributes_t_arr(port_cnt)
port_cnt_p = new_uint32_t_p()
uint32_t_p_assign(port_cnt_p, port_cnt)

rc = sx_api_port_device_get(handle, 1, 0, port_attributes_list, port_cnt_p)
if (rc != SX_STATUS_SUCCESS):
    sys.stderr.write("An error returned by sx_api_port_device_get.\n")
    sys.exit()
port_cnt = uint32_t_p_value(port_cnt_p)

set_mode = False
if args.command == "enable":  # enable packets aging
    sll_time = 0x418937
    hll_time = 0x83127
    hll_stall = 7
    set_mode = True
else:
    assert args.command == "disable"  # disable packets aging
    sll_time = 0xffffffffffffffff
    hll_time = 0xffffffff
    hll_stall = 0
    set_mode = True

if set_mode:
    rc = sx_api_port_sll_set(handle, sll_time)
    if (rc != SX_STATUS_SUCCESS):
        sys.stderr.write("An error returned by sx_api_port_sll_set.\n")
        sys.exit()
else:
    sll_p = new_uint64_t_p()
    rc = sx_api_port_sll_get(handle, sll_p)
    if (rc != SX_STATUS_SUCCESS):
        sys.stderr.write("An error returned by sx_api_port_sll_get.\n")
        sys.exit()
    else:
        sll = uint64_t_p_value(sll_p)
        sys.stderr.write(("sll_max_time=0x%X\n" % sll))

logical_port_list = lag_list
for i in range(0, port_cnt):
    port_attributes = sx_port_attributes_t_arr_getitem(port_attributes_list, i)
    log_port = int(port_attributes.log_port)
    if log_port not in lag_member_list and log_port < 0xFFFFF:
        logical_port_list.append(log_port)
sys.stderr.write("All ports to set {}\n".format(logical_port_list))

for log_port in logical_port_list:
    if set_mode:
        rc = sx_api_port_hll_set(handle, log_port, hll_time, hll_stall)
        if (rc != SX_STATUS_SUCCESS):
            sys.stderr.write("An error returned by sx_api_port_hll_set.\n")
            sys.exit()
    else:
        hll_max_time_p = new_uint32_t_p()
        hll_stall_cnt_p = new_uint32_t_p()
        rc = sx_api_port_hll_get(handle, log_port, hll_max_time_p, hll_stall_cnt_p)
        if (rc != SX_STATUS_SUCCESS):
            sys.stderr.write("An error returned by sx_api_port_hll_set.\n")
            sys.exit()
        else:
            hll_max_time = uint32_t_p_value(hll_max_time_p)
            hll_stall_cnt = uint32_t_p_value(hll_stall_cnt_p)
            sys.stderr.write(("Port%d(Ethernet%d, logical:0x%X) hll_time:0x%X, hll_stall:0x%X\n" %
                              (port_attributes.port_mapping.module_port, (port_attributes.port_mapping.module_port * 4),
                               log_port, hll_max_time, hll_stall_cnt)))
