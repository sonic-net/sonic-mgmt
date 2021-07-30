#!/usr/bin/env python
'''
This file contains Python script to enable/disable packets aging in queues(buffers?).
'''

import sys, errno
import os
import argparse
from python_sdk_api.sx_api import (SX_STATUS_SUCCESS,
                                   sx_api_open,
                                   sx_api_port_device_get,
                                   sx_api_port_sll_set,
                                   sx_api_port_sll_get,
                                   sx_api_port_hll_set,
                                   new_sx_port_attributes_t_arr,
                                   new_uint32_t_p,
                                   uint32_t_p_assign,
                                   uint32_t_p_value,
                                   sx_port_attributes_t_arr_getitem)

parser = argparse.ArgumentParser(description='Toggle Mellanox-specific packet aging on egress queues')
parser.add_argument('command', choices=['enable', 'disable'], type=str, help='Enable/Disable packet aging')
args = parser.parse_args()

# Open SDK
rc, handle = sx_api_open(None)
if (rc != SX_STATUS_SUCCESS):
    print >> sys.stderr, "Failed to open api handle.\nPlease check that SDK is running."
    sys.exit(errno.EACCES)

# Get number of ports
port_attributes_list = new_sx_port_attributes_t_arr(0)
port_cnt_p = new_uint32_t_p()
uint32_t_p_assign(port_cnt_p, 0)

rc = sx_api_port_device_get(handle, 1 , 0, port_attributes_list,  port_cnt_p)
if (rc != SX_STATUS_SUCCESS):
    print >> sys.stderr, "An error returned by sx_api_port_device_get."
    sys.exit()
port_cnt = uint32_t_p_value(port_cnt_p)

print >> sys.stderr, "Got port count {}".format(port_cnt)

# Get list of ports
port_attributes_list = new_sx_port_attributes_t_arr(port_cnt)
port_cnt_p = new_uint32_t_p()
uint32_t_p_assign(port_cnt_p, port_cnt)

rc = sx_api_port_device_get(handle, 1 , 0, port_attributes_list,  port_cnt_p)
if (rc != SX_STATUS_SUCCESS):
    print >> sys.stderr, "An error returned by sx_api_port_device_get."
    sys.exit()
port_cnt = uint32_t_p_value(port_cnt_p)

set_mode = False
if args.command == "enable": # enable packets aging
    sll_time = 0x418937
    hll_time = 0x83127
    hll_stall = 7
    set_mode = True
else:
    assert args.command == "disable" # disable packets aging
    sll_time = 0xffffffffffffffff
    hll_time = 0xffffffff
    hll_stall = 0
    set_mode = True

if set_mode:
    rc = sx_api_port_sll_set(handle, sll_time)
    if (rc != SX_STATUS_SUCCESS):
        print >> sys.stderr, "An error returned by sx_api_port_sll_set."
        sys.exit()
else:
    sll_p = new_uint64_t_p()
    rc = sx_api_port_sll_get(handle, sll_p)
    if (rc != SX_STATUS_SUCCESS):
        print >> sys.stderr, "An error returned by sx_api_port_sll_get."
        sys.exit()
    else:
        sll = uint64_t_p_value(sll_p)
        print >> sys.stderr, ("sll_max_time=0x%X" % sll)

for i in range(0, port_cnt):
    port_attributes = sx_port_attributes_t_arr_getitem(port_attributes_list,i)
    log_port = int(port_attributes.log_port)
    if log_port < 0xFFFFF: # only physical ports
        if set_mode:
            rc = sx_api_port_hll_set(handle, log_port, hll_time, hll_stall)
            if (rc != SX_STATUS_SUCCESS):
                print >> sys.stderr, "An error returned by sx_api_port_hll_set."
                sys.exit()
        else:
            hll_max_time_p = new_uint32_t_p()
            hll_stall_cnt_p = new_uint32_t_p()
            rc = sx_api_port_hll_get(handle,log_port, hll_max_time_p, hll_stall_cnt_p)
            if (rc != SX_STATUS_SUCCESS):
                print >> sys.stderr, "An error returned by sx_api_port_hll_set."
                sys.exit()
            else:
                hll_max_time = uint32_t_p_value(hll_max_time_p)
                hll_stall_cnt = uint32_t_p_value(hll_stall_cnt_p)
                print >> sys.stderr, ("Port%d(Ethernet%d, logical:0x%X) hll_time:0x%X, hll_stall:0x%X" %
                    (port_attributes.port_mapping.module_port, (port_attributes.port_mapping.module_port * 4),
                        log_port, hll_max_time, hll_stall_cnt))
