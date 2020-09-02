import os
import copy
import socket
import logging
import netmiko

from .sonic_connection import SonicBaseConnection
from .sonic_connection import SonicSshConnection
from .fastpath_connection import FastpathBaseConnection
from .fastpath_connection import FastpathSshConnection
from .icos_connection import IcosBaseConnection
from .icos_connection import IcosSshConnection

def log_msg(logger, lvl, msg):
    if logger:
        logger.log(lvl, msg)
    else:
        print(msg)

class DeviceConnectionTimeout(netmiko.ssh_exception.NetMikoTimeoutException):
    pass


class DeviceAuthenticationFailure(netmiko.ssh_exception.NetMikoAuthenticationException):
    pass


def _DeviceConnection(ip_port, logger, **kwargs):
    device_type = kwargs['device_type']
    try:
        if device_type == "sonic_terminal":
            kwargs['device_type'] = "sonic_terminal_telnet"
            return SonicBaseConnection(**kwargs)
        if device_type == "sonic_sshcon":
            return SonicSshConnection(**kwargs)
        if device_type == "sonic_ssh":
            return SonicSshConnection(**kwargs)
        if device_type == "fastpath_terminal":
            kwargs['device_type'] = "fastpath_terminal_telnet"
            return FastpathBaseConnection(**kwargs)
        if device_type == "fastpath_ssh":
            return FastpathSshConnection(**kwargs)
        if device_type == "icos_terminal":
            kwargs['device_type'] = "icos_terminal_telnet"
            return IcosBaseConnection(**kwargs)
        if device_type == "icos_ssh":
            return IcosSshConnection(**kwargs)
        return netmiko.ConnectHandler(**kwargs)
    except netmiko.ssh_exception.NetMikoTimeoutException as e1:
        log_msg(logger, logging.WARNING, "Timeout({}): {}".format(ip_port, e1))
        raise DeviceConnectionTimeout(e1)
    except netmiko.ssh_exception.NetMikoAuthenticationException as e2:
        #log_msg(logger, logging.WARNING, "Failure({}): {}".format(ip_port, e2))
        raise DeviceAuthenticationFailure(e2)
    except Exception as e3:
        log_msg(logger, logging.WARNING, "Exception({}): {}".format(ip_port, e3))
        raise e3

def initDeviceConnectionDebug(file_prefix):
    logging.getLogger("paramiko").setLevel(logging.INFO)

    root = logging.getLogger('netmiko')
    if not os.getenv("SPYTEST_NETMIKO_DEBUG", None):
        root.setLevel(logging.INFO)
        return
    root.propagate = False
    fmt = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    root.setLevel(logging.DEBUG)
    logfile = "netmiko.log"

    if file_prefix:
        logfile = "{}_{}".format(file_prefix, logfile)

    handler = logging.FileHandler(logfile, 'w')
    handler.setFormatter(fmt)
    root.addHandler(handler)

def DeviceConnection(**kws):

    if os.getenv("SPYTEST_FILE_MODE", None):
        return None

    kwargs = copy.copy(kws)

    logger = kwargs.pop("logger", None)

    ip = kwargs.get('ip', "0.0.0.0")
    port = kwargs.get('port', "0")
    ip_port = "{}:{}".format(ip, port)

    auth = []
    if "addl_auth" in kwargs:
        auth.extend(kwargs["addl_auth"])
        del kwargs["addl_auth"]
    if "password" in kwargs:
        auth.append([kwargs["username"], kwargs["password"]])
    if "altpassword" in kwargs:
        auth.append([kwargs["username"], kwargs["altpassword"]])
    if "mgmt_ipmask" in kwargs:
        del kwargs["mgmt_ipmask"]
    if "mgmt_gw" in kwargs:
        del kwargs["mgmt_gw"]
    if "access_model" in kwargs:
        kwargs["device_type"] = kwargs["access_model"]
        del kwargs["access_model"]

    # use sshcon_username and sshcon_password if provided
    if "sshcon_password" in kwargs and "sshcon_username" in kwargs:
        auth = [[kwargs["sshcon_username"], kwargs["sshcon_password"]]]
        kwargs["password"] = kwargs["sshcon_password"]
        del kwargs["sshcon_username"]
        del kwargs["sshcon_password"]
        del kwargs["altpassword"]

    last_exception = ""
    run_passwd_cmd = False
    for [username, password] in auth:
        try:
            if last_exception:
                msg = "TRY ALT Authentication: {} {} {}".format(ip_port, username, password)
            else:
                msg = "TRY Authentication: {} {} {}".format(ip_port, username, password)
            log_msg(logger, logging.INFO, msg)
            kwargs["username"] = username
            if "altpassword" in kwargs and kwargs["altpassword"] == password:
                tmp_pwd = kwargs["password"]
                kwargs["password"] = kwargs["altpassword"]
                kwargs["altpassword"] = tmp_pwd
            hndl = _DeviceConnection(ip_port, logger, **kwargs)
            if "altpassword" in kwargs and run_passwd_cmd:
                hndl.change_password(kwargs["username"], kwargs["altpassword"])
                hndl.password = kwargs["altpassword"]
                hndl.altpassword = kwargs["password"]
            return hndl
        except DeviceAuthenticationFailure as e1:
            last_exception = e1
        except socket.error as e2:
            # Needed to check for the message where passwd change is done.
            if "Spytest: socket is closed abruptly" in e2:
                if "altpassword" in kwargs and not run_passwd_cmd:
                    auth.append([username, kwargs["altpassword"]])
                    run_passwd_cmd = True
            last_exception = e2
        except Exception as e3:
            raise e3
    if last_exception:
        raise last_exception

def DeviceFileUpload(net_connect, src_file, dst_file, connection_param):
    if connection_param["mgmt-ip"]:
        dev = {
            'device_type': 'sonic_ssh',
            'username': connection_param["username"],
            'password': connection_param["password"],
            'altpassword': connection_param["altpassword"],
            'ip': connection_param["mgmt-ip"],
        }
        if "altpassword" in connection_param:
            dev["altpassword"] = connection_param["altpassword"]
        net_connect = DeviceConnection(**dev)
    scp_conn = netmiko.SCPConn(net_connect)
    scp_conn.scp_transfer_file(src_file, dst_file)
    scp_conn.close()
    if connection_param["mgmt-ip"]:
        net_connect.disconnect()

def DeviceFileDownload(net_connect, src_file, dst_file, connection_param):
    if connection_param["mgmt-ip"]:
        dev = {
            'device_type': 'sonic_ssh',
            'username': connection_param["username"],
            'password': connection_param["password"],
            'altpassword': connection_param["altpassword"],
            'ip': connection_param["mgmt-ip"],
        }
        if "altpassword" in connection_param:
            dev["altpassword"] = connection_param["altpassword"]
        net_connect = DeviceConnection(**dev)
    scp_conn = netmiko.SCPConn(net_connect)
    scp_conn.scp_get_file(src_file, dst_file)
    scp_conn.close()
    if connection_param["mgmt-ip"]:
        net_connect.disconnect()

