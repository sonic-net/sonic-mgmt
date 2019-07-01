import sys
import os
import time
import socket
import pickle
import argparse
import datetime
import signal

sys.path.append('/usr/lib/python2.7/dist-packages/python_sdk_api/')
sys.path.append('/usr/lib/python2.7/site-packages/python_sdk_api/')
sys.path.append('/usr/local/lib/python2.7/dist-packages/python_sdk_api/')
sys.path.append('/usr/local/lib/python2.7/site-packages/python_sdk_api/')

from sx_api import *


g_ptf_host = None
g_log_fp = None


def log(message, output_on_console=False):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if output_on_console:
        print "%s : %s" % (current_time, message)
    global g_log_fp
    if g_log_fp is not None:
        g_log_fp.write("%s : %s\n" % (current_time, message))
        g_log_fp.flush()


class PtfHostConn(object):
    def __init__(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((g_ptf_host, 9877))

    def __del__(self):
        self.conn.close()

    def read(self):
        fp = self.conn.makefile('rb', 1024)
        data = pickle.load(fp)
        fp.close()
        return data

    def write(self, data):
        fp = self.conn.makefile('wb', 1024)
        pickle.dump(data, fp, pickle.HIGHEST_PROTOCOL)
        fp.close()


class IntfMonitor():
    def __init__(self):
        self.sx_hdl = None
        self.sx_rx_fd = None
        self.sx_uc = None
        self.sx_swid = 0
        self.sx_devid = 1

    def start(self):
        rc, self.sx_hdl = sx_api_open(None)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to open SX API channel, rc %d. Please check that SDK is running.", rc)
            sys.exit(rc)

        self.sx_rx_fd = new_sx_fd_t_p()
        rc = sx_api_host_ifc_open(self.sx_hdl, self.sx_rx_fd)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to open file descriptor of the current open SX API channel, rc %d." % rc)
            exit(rc)

        cmd = SX_ACCESS_CMD_REGISTER

        self.sx_uc = new_sx_user_channel_t_p()
        self.sx_uc.type = SX_USER_CHANNEL_TYPE_FD
        self.sx_uc.channel.fd = self.sx_rx_fd

        rc = sx_api_host_ifc_trap_id_register_set(self.sx_hdl, cmd, self.sx_swid, SX_TRAP_ID_PUDE, self.sx_uc)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to register SX port up/down events, rc %d." % rc)
            exit(rc)

        self.monitorLinkChange()

    def stop(self):
        cmd = SX_ACCESS_CMD_DEREGISTER

        rc = sx_api_host_ifc_trap_id_register_set(self.sx_hdl, cmd, self.sx_swid, SX_TRAP_ID_PUDE, self.sx_uc)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to deregister SX port up/down events, rc %d." % rc)
            exit(rc)

        rc = sx_api_host_ifc_close(self.sx_hdl, self.sx_rx_fd)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to close file descriptor of the current open SX API channel, rc %d." % rc)
            exit(rc)

        rc = sx_api_close(self.sx_hdl)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to close SX API channel, rc %d." % rc)
            exit(rc)

    def monitorLinkChange(self):
        while True:
            pkt_size = 2000
            pkt_size_p = new_uint32_t_p()
            uint32_t_p_assign(pkt_size_p, pkt_size)
            pkt = new_uint8_t_arr(pkt_size)
            recv_info_p = new_sx_receive_info_t_p()

            rc = sx_lib_host_ifc_recv(self.sx_rx_fd, pkt, pkt_size_p, recv_info_p)
            if rc != SX_STATUS_SUCCESS:
                log("Failed to receive SX port up/down event, rc %d." % rc)
                exit(rc)

            intf = self.getIntfName(recv_info_p.event_info.pude.log_port)

            linkStatus = None
            if recv_info_p.event_info.pude.oper_state == SX_PORT_OPER_STATUS_UP:
                linkStatus = "linkUp"
            else:
                linkStatus = "linkDown"

            self.sendLinkChangeToPtfHost(intf, linkStatus)

    def getIntfName(self, sxLogPort):
        port_cnt_p = new_uint32_t_p()
        port_attributes_list = new_sx_port_attributes_t_arr(64)
        uint32_t_p_assign(port_cnt_p, 64)

        rc = sx_api_port_device_get(self.sx_hdl, self.sx_devid, self.sx_swid, port_attributes_list, port_cnt_p)
        if rc != SX_STATUS_SUCCESS:
            log("Failed to get SX ports information, rc %d." % rc)
            exit(rc)

        name = None
        port_cnt = uint32_t_p_value(port_cnt_p)
        for i in range(0, port_cnt):
            port_attributes = sx_port_attributes_t_arr_getitem(port_attributes_list, i)
            if port_attributes.log_port != sxLogPort:
                continue
            name = 'ethernet 1/{0}'.format(port_attributes.port_mapping.module_port + 1)
            lanes = port_attributes.port_mapping.lane_bmap
            width = port_attributes.port_mapping.width
            if width == 2:
                name = '{}/{}'.format(name, 1 if lanes % 2 else 2)
            elif width == 1:
                idx = 1
                while lanes:
                    lanes <<= 2
                    idx += 1
                name = '{}/{}'.format(name, idx)
            break

        return name

    def sendLinkChangeToPtfHost(self, intf, linkStatus):
        conn = PtfHostConn()
        data = {"intf": intf, "linkStatus": linkStatus}
        log("Event: intf %s changed its state %s" % (intf, linkStatus))
        log("Send data %s" % str(data))
        conn.write(data)
        data = conn.read()
        log("Received reply: %s" % str(data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ptf_host", type=str, help="ip address of ptf host")
    args = parser.parse_args()
    global g_ptf_host
    g_ptf_host = str(args.ptf_host)

    global g_log_fp
    g_log_fp = open("/tmp/fanout_listener.log", "w")

    intfMonitor = IntfMonitor()

    try:
        intfMonitor.start()
        signal.signal(signal.SIGTERM, intfMonitor.stop())
    finally:
        intfMonitor.stop()


if __name__ == '__main__':
    main()

