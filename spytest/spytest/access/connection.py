import os
import copy
import socket
import logging

from .linux_connection import LinuxConnection
from .netmiko_connection import NetmikoConnection
from .paramiko_connection import ParamikoConnection

from utilities.ctrl_chars import tostring
from utilities.common import ensure_parent, list_copy
from utilities.exceptions import DeviceConnectionError
from utilities.exceptions import DeviceConnectionTimeout
from utilities.exceptions import DeviceAuthenticationFailure


def dtrace(*args, **kwargs):
    if int(os.getenv("SPYTEST_DEBUG_DEVICE_CONNECTION", "0")) > 2:
        print(args, kwargs)


def log_msg(logger, devname, lvl, msg):
    if not logger:
        print(msg)
    elif devname:
        logger.dut_log(devname, msg, lvl=lvl)
    else:
        logger.log(lvl, msg)


def log_exception(logger, devname, lvl, etype, ip_port, e):
    msg = "{}({}): {}".format(etype, ip_port, tostring(e, ""))
    log_msg(logger, devname, lvl, msg)


def _DeviceConnection(devname, ip_port, logger, **kwargs):
    device_type = kwargs['device_type']
    try:
        kwargs['logger'] = logger
        access_driver = os.getenv("SPYTEST_ACCESS_DRIVER", "netmiko")
        if access_driver == "paramiko":
            return ParamikoConnection(**kwargs)
        if device_type in ["linux", "linux_ssh", "linux_terminal"]:
            kwargs['device_type'] = "linux"
            return LinuxConnection(**kwargs)
        if device_type == "sonic_terminal":
            kwargs['device_type'] = "sonic_terminal_telnet"
            return NetmikoConnection(**kwargs)
        if device_type == "sonic_sshcon":
            return NetmikoConnection(**kwargs)
        if device_type == "sonic_ssh":
            return NetmikoConnection(**kwargs)
        if device_type == "fastpath_terminal":
            kwargs['device_type'] = "fastpath_terminal_telnet"
            return NetmikoConnection(product="fastpath", **kwargs)
        if device_type == "fastpath_ssh":
            return NetmikoConnection(product="fastpath", **kwargs)
        if device_type == "icos_terminal":
            kwargs['device_type'] = "icos_terminal_telnet"
            return NetmikoConnection(product="icos", **kwargs)
        if device_type == "icos_ssh":
            return NetmikoConnection(product="icos", **kwargs)
        if device_type == "poe_terminal":
            kwargs['device_type'] = "poe_terminal_telnet"
            return NetmikoConnection(product="poe", **kwargs)
        kwargs.pop("logger", None)
        raise DeviceConnectionError("")
    except DeviceConnectionTimeout as e:
        # log_exception(logger, devname, logging.WARNING, "Timeout", ip_port, e)
        raise e
    except DeviceAuthenticationFailure as e:
        # log_exception(logger, devname, logging.WARNING, "Failure", ip_port, e)
        raise e
    except DeviceConnectionError as e:
        log_exception(logger, devname, logging.WARNING, "Exception", ip_port, e)
        raise e


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

    if os.getenv("SPYTEST_FILE_MODE", "0") != "0":
        return None

    kwargs = copy.copy(kws)

    dtrace("DeviceConnection", **kwargs)

    logger = kwargs.pop("logger", None)

    ip = kwargs.get('ip', "0.0.0.0")
    port = kwargs.get('port', "0")
    if port != 0:
        ip_port = "{}:{}".format(ip, port)
    else:
        ip_port = "{}".format(ip)

    auth = []
    if "password" in kwargs:
        auth.append([kwargs["username"], kwargs["password"]])
    if "altpassword" in kwargs:
        auth.append([kwargs["username"], kwargs["altpassword"]])
    kwargs.pop("mgmt_ipmask", None)
    kwargs.pop("mgmt_gw", None)
    if "access_model" in kwargs:
        kwargs["device_type"] = kwargs["access_model"]
        del kwargs["access_model"]
    if "addl_auth" in kwargs:
        dtrace("Addtional Auth: {}".format(kwargs["addl_auth"]))
        auth.extend(kwargs["addl_auth"])
        del kwargs["addl_auth"]
    devname = kwargs.pop("devname", None)

    # use sshcon_username and sshcon_password if provided
    if "sshcon_password" in kwargs and "sshcon_username" in kwargs:
        auth = [[kwargs["sshcon_username"], kwargs["sshcon_password"]]]
        kwargs["password"] = kwargs["sshcon_password"]
        del kwargs["sshcon_username"]
        del kwargs["sshcon_password"]
        del kwargs["altpassword"]

    # add default password if specified
    default_pass = kwargs.pop("default_pass", None)
    if default_pass is not None:
        kwargs["change_pass"] = kwargs["password"]
        auth.append([kwargs["username"], default_pass])
    else:
        kwargs["change_pass"] = None

    last_exception, run_passwd_cmd = "", False
    for [username, password] in list_copy(auth):
        try:
            if default_pass is not None and password == default_pass:
                msg = "TRY Default Authentication: {} {} '{}'".format(ip_port, username, password)
            elif last_exception:
                msg = "TRY ALT Authentication: {} {} {}".format(ip_port, username, password)
            else:
                msg = "TRY Authentication: {} {} {}".format(ip_port, username, password)
            log_msg(logger, devname, logging.INFO, msg)
            kwargs["username"] = username
            if "altpassword" in kwargs and kwargs["altpassword"] == password:
                tmp_pwd = kwargs["password"]
                kwargs["password"] = kwargs["altpassword"]
                kwargs["altpassword"] = tmp_pwd
            else:
                kwargs["password"] = password
            hndl = _DeviceConnection(devname, ip_port, logger, **kwargs)
            if "altpassword" in kwargs and run_passwd_cmd:
                hndl.change_password(kwargs["username"], kwargs["altpassword"])
                hndl.password = kwargs["altpassword"]
                hndl.altpassword = kwargs["password"]
            return hndl
        except DeviceAuthenticationFailure as e:
            last_exception = e
        except DeviceConnectionError as e:
            last_exception = e
        except socket.error as e:
            # Needed to check for the message where passwd change is done.
            if "Spytest: socket is closed abruptly" in str(e):
                if "altpassword" in kwargs and not run_passwd_cmd:
                    auth.append([username, kwargs["altpassword"]])
                    run_passwd_cmd = True
            last_exception = e
        except Exception as e:
            raise e
    if last_exception:
        raise last_exception


def DeviceFileUpload(net_connect, src_file, dst_file, **params):
    if params["mgmt-ip"]:
        dev = {
            'device_type': 'sonic_ssh',
            'username': params["username"],
            'password': params["password"],
            'ip': params["mgmt-ip"],
            'port': 22,
        }
        if "altpassword" in params:
            dev["altpassword"] = params["altpassword"]
        net_connect = DeviceConnection(**dev)
    net_connect.put_file(src_file, dst_file)
    if params["mgmt-ip"]:
        net_connect.disconnect()


def DeviceFileDownload(net_connect, src_file, dst_file, **params):
    if params["mgmt-ip"]:
        dev = {
            'device_type': 'sonic_ssh',
            'username': params["username"],
            'password': params["password"],
            'altpassword': params["altpassword"],
            'ip': params["mgmt-ip"],
            'port': 22,
        }
        if "altpassword" in params:
            dev["altpassword"] = params["altpassword"]
        net_connect = DeviceConnection(**dev)
    ensure_parent(dst_file)
    net_connect.get_file(src_file, dst_file)
    if params["mgmt-ip"]:
        net_connect.disconnect()
