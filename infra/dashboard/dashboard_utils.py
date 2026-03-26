import os
import re
import shutil
import json
import logging
import logging.config
import paramiko
import requests
import subprocess
import time
import smtplib
import ssl
import traceback
import urllib
import jenkins

from urllib.parse import urlencode
from urllib.request import urlopen
from functools import wraps, reduce
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple
from jinja2 import Environment, FileSystemLoader
from enum import Enum



def singleton(cls):
    """
    This fucntion is used as a decorator pattern, which limit the object only
    one instance
    """
    instances = {}

    @wraps(cls)
    def _wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return _wrapper


class SysTools(object):
    """
    The SysTools class is used to get or set current system enviroment info
    """

    @staticmethod
    def get_current_env_type():
        """
        Check the env if it is a integrated flag
        :return:
        """
        pipeline_type = os.getenv(ENV_TYPE_ENV, PipelineEnvType.PROD.name).upper()

        if pipeline_type == PipelineEnvType.DEV.name:
            log.info("Current env is development")
            return PipelineEnvType.DEV.name

        # default is production
        log.info("Current env is production")
        return PipelineEnvType.PROD.name

    @staticmethod
    def is_dev_env():
        """
        Check if dev env
        """
        return SysTools.get_current_env_type() == PipelineEnvType.DEV.name

    @staticmethod
    def get_pipe_name():
        """
        :return:
        """
        job = os.getenv("JOB_BASE_NAME", "NA").replace("/", "_")
        return job

    @staticmethod
    def get_manage_branch_collection_name():
        """
        get branch collection name
        :return:
        """
        return "BranchMgr"

    @staticmethod
    def get_env_value(env_name):
        return os.getenv(env_name, '')

    @staticmethod
    def get_key_env_info():
        """
        Get all current Cookies info, like build_id, pip_name, hash_value,
        repo name, branch name
        :return:
        """
        cookies_dic = dict()
        for env_name in EnvParamsList:
            if env_name != JOB_BASE_NAME:
                cookies_dic[env_name] = SysTools.get_env_value(env_name)
                if env_name == BUILD_URL:
                    cookies_dic[env_name]=re.sub(r'http:', 'https:', cookies_dic[env_name])
            else:
                cookies_dic[env_name] = SysTools.get_pipe_name()
        # log.debug("current env info is: %s" % cookies_dic)
        return cookies_dic

    @staticmethod
    def get_env_infos(env_params):
        cookies_dic = dict()
        values = SysTools.get_key_env_info()
        for param in env_params:
            if param in values:
                cookies_dic[param] = values[param]
            else:
                cookies_dic[param] = SysTools.get_env_value(param)

        return cookies_dic

    @staticmethod
    def run_shell_cmd(cmd_str, timeout=60):
        log.debug("run_shell_cmd:%s" % str(cmd_str))
        ret = 0
        out = None
        proc = subprocess.Popen(cmd_str, shell=True,
                                stderr=subprocess.STDOUT,
                                close_fds=True,
                                stdout=subprocess.PIPE,
                                universal_newlines=True)
        endtime = time.monotonic() + timeout
        out = ""
        while proc.poll() is None:
            line = proc.stdout.readline()
            out += line
            print(line.strip())
            if time.monotonic() > endtime:
                proc.kill()
                proc.stdout.close()
                ret = -1
                out = "%d seconds Timeout" % timeout
                return ret, out
        lines = proc.stdout.read()
        out += lines
        proc.stdout.close()
        proc.wait()
        ret = proc.returncode

        return ret, out

    @staticmethod
    def ExecuteCmdWithRetry(cmd_str, timeout=60):
        cnt = 0
        stime = 10
        while cnt < 5:
            code, output = SysTools.run_shell_cmd(cmd_str, timeout)
            if code == 0:
                break
            cnt += 1
            stime *= 2
            log.error('cmd %s fails because of %s. Will start No.%d try.' % (cmd_str, output, cnt))
            time.sleep(stime)
        if code == 0:
            return code, output
        else:
            return code, "Max retry failure for cmd: %s"%cmd_str

    @staticmethod
    def clear_http_proxy():
        if os.getenv('http_proxy'):
            del os.environ['http_proxy']

    @staticmethod
    def strtobool(value):
        if value.lower() in ['y', 'yes', 't', 'true', 'on', '1']:
            return True

        if value.lower() in ['n', 'no', 'f', 'false', 'off', '0']:
            return False

        raise ValueError()

    @staticmethod
    def post_webex_space(job_type, msg):
        log.info("============ Post to webex space ============")
        url = 'https://webexapis.com/v1/messages'
        config = FileHandler.read_cfg()
        webex_cfg = config["webex"]
        headers = {
            'Authorization': 'Bearer %s' % webex_cfg['access-token'],
            'Content-Type': 'application/json'
            }
        body = {
            "roomId": webex_cfg['spaces'][job_type]['room-id'],
            "text": msg
            }
        json_body = json.dumps(body)
        cnt = 0
        while cnt < 5:
            r = requests.post(url, headers=headers, data=json_body)
            if r.status_code == 200:
                log.debug('post %s return code %d' % (url, r.status_code))
                break
            cnt += 1
            log.error('post %s return code %d. Start No.%d retry.' % (url, r.status_code, cnt))

    @staticmethod
    def send_webex_message(username, msg):
        log.info("============ Post to webex space ============")
        url = 'https://webexapis.com/v1/messages'
        config = FileHandler.read_cfg()
        webex_cfg = config["webex"]
        headers = {
            'Authorization': 'Bearer %s' % webex_cfg['access-token'],
            'Content-Type': 'application/json'
            }
        body = {
            "toPersonEmail": f"{username}@cisco.com",
            "text": msg
            }
        json_body = json.dumps(body)
        cnt = 0
        while cnt < 5:
            r = requests.post(url, headers=headers, data=json_body)
            if r.status_code == 200:
                log.debug('post %s return code %d' % (url, r.status_code))
                break
            cnt += 1
            log.error('post %s return code %d. Start No.%d retry.' % (url, r.status_code, cnt))

    @staticmethod
    def is_remotepath_present(ip, username, remotepath, ssh_private_key=None):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if ssh_private_key:
            ssh.connect(ip, 22, username, key_filename=ssh_private_key)
        else:
            ssh.connect(ip, 22, username)

        sftp = ssh.open_sftp()
        try:
            sftp.stat(remotepath)
            log.info("remotepath %s exists" % remotepath)
        except IOError:
            ssh.close()
            return False

        ssh.close()
        return True

    @staticmethod
    def compare_version(a, b):
        """
        compare version string
        :param a: str, e.g. '1.47.11.3'
        :param b: str, e.g. '1.47.11.10', '1.50.0.4rp04'
        :return: 1 if a > b, 0 if a == b, -1 if a < b
        """
        if a == b:
            return 0
        segs_a = a.split('.')
        segs_b = b.split('.')
        for i in range(len(segs_a)):
            if i < len(segs_b):
                if segs_a[i] == segs_b[i]:
                    continue
                match_a = re.match(r"(\d*)([a-z\d]*)", segs_a[i])
                digit_a = match_a.group(1)
                str_a = match_a.group(2)
                match_b = re.match(r"(\d*)([a-z\d]*)", segs_b[i])
                digit_b = match_b.group(1)
                str_b = match_b.group(2)
                if not digit_a or not digit_b:
                    if segs_a[i] > segs_b[i]:
                        return 1
                    else:
                        return -1
                if int(digit_a) > int(digit_b):
                    return 1
                elif int(digit_a) < int(digit_b):
                    return -1
                elif str_a > str_b:
                    return 1
                else:
                    return -1
            else:
                return 1
        return -1


    @staticmethod
    def get_latest_commit_hash(url, branch):
        """
        Get latest commit hash
        :param url: repo url, e.g. git@wwwin-github.cisco.com:whitebox/cisco-wb-pkg.git
        :param branch: branch name, e.g. master
        :return: commit hash
        """
        code, output = SysTools.ExecuteCmdWithRetry("git ls-remote --heads %s heads/%s | cut -f 1" % (url, branch))
        if re.search("Max retry failure", output):
            log.debug("git command hit max retry failure, Github may have issues now.")
            return "N/A due to Github issue."
        s = output.strip()
        if '\n' in s:
            for line in s.split('\n'):
                # skip the Warning line if it exists
                if 'Warning' in line: continue
                # return the first hash
                return line
        return s

    @staticmethod
    def resolve_string(input_str):
        """
        If input_str starts with '$', interpret everything after the '$' as an environment variable name.
        Return the environment variable's value if found, otherwise None.
        If input_str does not start with '$', return input_str as is.
        """
        if input_str.startswith("$"):
            env_var_name = input_str[1:]  # everything after '$'
            return os.environ.get(env_var_name)
        else:
            return input_str