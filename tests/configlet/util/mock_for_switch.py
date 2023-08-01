#! /usr/bin/env python

import docker
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time

from tests.configlet.util.helpers import *


class DutHost:
    def __init__(self):
        with open("/etc/sonic/sonic-environment", "r") as s:
            lines = s.readlines()

        self.facts = {}
        for ln in lines:
            l = ln.split("=")
            self.facts[l[0].strip().lower()] = l[1].strip().lower()

        self.os_version = self.facts["sonic_version"]
        self.hostname = socket.gethostname()
        self.hostname = socket.gethostname()

        log_debug("mock duthost created")
        log_debug("facts: {}".format(str(self.facts)))
        log_debug("ver={} hostname={}".format(self.os_version, self.hostname))



    def shell(self, cmd, module_ignore_errors=False):
        log_debug("mocked shell: {}".format(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        ## Wait for end of command. Get return returncode ##
        rc = p.wait()
        ret = {
                "rc": rc,
                "stdout": output.decode("UTF-8"),
                "stderr": err.decode("UTF-8")
                }
        log_debug("ret:{}".format(str(ret)))
        return ret


    def copy(self, src, dest):
        os.system("cp {} {}".format(src, dest))


    def fetch(self, src, dest):
        ret = {}

        fetch_dest = os.path.join(dest, self.hostname, src[1:])
        rc = os.system("mkdir -p {}".format(os.path.dirname(fetch_dest)))
        assert rc == 0, "failed to create dir {}".format(os.path.dirname(fetch_dest))

        rc = os.system("cp {} {}".format(src, fetch_dest))
        ret["failed"] = rc != 0

        if rc == 0:
            ret["dest"] = fetch_dest

        log_debug("fetch src={} dest={} ret={}".format(
            src, dest, str(ret)))
        return ret


    def stat(self, path):
        ret = { "stat": { "exists": os.path.exists(path) } }
        log_debug("ret = {}".format(str(ret)))
        return ret


    def critical_services_fully_started(self):
        expected = set(["radv", "snmp", "lldp", "syncd", 
            "teamd", "swss", "bgp", "pmon" ])
        client = docker.from_env()
        ctrs = set()
        try:
            for c in client.containers.list(all):
                if getattr(c, "status") == "running":
                    ctrs.add(c.name)
        except docker.errors.APIError as err:
            log_error("Failed to get containers list")
            return False

        missing = set()
        if not expected.issubset(ctrs):
            for i in expected:
                if i not in ctrs:
                    missing.add(i)
            print("Missing services: {}".format(str(missing)))
            return False

        return True


    def get_bgp_neighbor_info(self, neighbor_ip):
        """
        @summary: return bgp neighbor info

        @param neighbor_ip: bgp neighbor IP
        """
        nbip = ipaddress.ip_address(neighbor_ip)
        if nbip.version == 4:
            out = self.shell("vtysh -c \"show ip bgp neighbor {} json\"".format(neighbor_ip))
        else:
            out = self.shell("vtysh -c \"show bgp ipv6 neighbor {} json\"".format(neighbor_ip))

        nbinfo = json.loads(re.sub(r"\\\"", '"', re.sub(r"\\n", "", out['stdout'])))
        log_info("bgp neighbor {} info {}".format(neighbor_ip, nbinfo))

        return nbinfo[str(neighbor_ip)]



def get_duthost():
    if os.path.exists("/etc/sonic/sonic-environment"):
        return DutHost()
    else:
        return None


def config_reload(duthost, config_source="config_db", wait=60, start_bgp=False):
    if config_source == "config_db":
        cmd = "config reload -y"
    elif config_source == "minigraph":
        cmd = "config load_minigraph -y"
    else:
        raise Exception("Unknown config source")

    log_debug("config_reload cmd: {}".format(cmd))
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "failed to run err:{}".format(str(ret["stderr"]))
    
    if start_bgp:
        duthost.shell("config bgp startup all")
        log_debug("config_reload started BGP")

    log_debug("wait for {}".format(wait))
    time.sleep(wait)
    log_debug("config_reload complete")


def wait_until(timeout, interval, delay, condition, *args, **kwargs):
    log_debug("Wait until %s is True, timeout is %s seconds, checking interval is %s, delay is %s seconds" % \
                    (condition.__name__, timeout, interval, delay))

    if delay > 0:
        log_debug("Delay for %s seconds first" % delay)
        time.sleep(delay)

    start_time = time.time()
    elapsed_time = 0
    while elapsed_time < timeout:
        log_debug("Time elapsed: %f seconds" % elapsed_time)
        try:
            check_result = condition(*args, **kwargs)
        except Exception as e:
            exc_info = sys.exc_info()
            details = traceback.format_exception(*exc_info)
            log_error(
                "Exception caught while checking {}:{}, error:{}".format(
                    condition.__name__, "".join(details), e
                )
            )
            check_result = False

        if check_result:
            log_debug("%s is True, exit early with True" % condition.__name__)
            return True
        else:
            log_debug("%s is False, wait %d seconds and check again" % (condition.__name__, interval))
            time.sleep(interval)
            elapsed_time = time.time() - start_time

    log_debug("%s is still False after %d seconds, exit with False" % (condition.__name__, timeout))
    return False

