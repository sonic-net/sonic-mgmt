#!/usr/bin/python3

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import logging
import os.path
import subprocess
import sys

from configparser import ConfigParser

import ovirtsdk4 as sdk

from bcolors import bcolors


INFO = bcolors.OKGREEN
INPUT = bcolors.OKGREEN
WARN = bcolors.WARNING
FAIL = bcolors.FAIL
END = bcolors.ENDC
PREFIX = "[Generate Mapping File] "
CA_DEF = '/etc/pki/ovirt-engine/ca.pem'
USERNAME_DEF = 'admin@internal'
SITE_DEF = 'http://localhost:8080/ovirt-engine/api'
PLAY_DEF = "../examples/dr_play.yml"


class GenerateMappingFile:

    def run(self, conf_file, log_file, log_level):
        log = self._set_log(log_file, log_level)
        log.info("Start generate variable mapping file "
                 "for oVirt ansible disaster recovery")
        dr_tag = "generate_mapping"
        site, username, password, ca_file, var_file, ansible_play_file = \
            self._init_vars(conf_file, log)
        log.info("Site address: %s \n"
                 "username: %s \n"
                 "password: *******\n"
                 "ca file location: %s \n"
                 "output file location: %s \n"
                 "ansible play location: %s ",
                 site, username, ca_file, var_file, ansible_play_file)
        if not self._validate_connection(log,
                                         site,
                                         username,
                                         password,
                                         ca_file):
            self._print_error(log)
            sys.exit()
        extra_vars = "site={0} username={1} password={2} ca={3} var_file={4}".\
            format(site, username, password, ca_file, var_file)
        command = [
            "ansible-playbook", ansible_play_file,
            "-t", dr_tag,
            "-e", extra_vars,
            "-vvvvv"
        ]
        log.info("Executing command %s", ' '.join(map(str, command)))
        if log_file is not None and log_file != '':
            self._log_to_file(log_file, command)
        else:
            self._log_to_console(command, log)

        if not os.path.isfile(var_file):
            log.error("Can not find output file in '%s'.", var_file)
            self._print_error(log)
            sys.exit()
        log.info("Var file location: '%s'", var_file)
        self._print_success(log)

    def _log_to_file(self, log_file, command):
        with open(log_file, "a") as f:
            proc = subprocess.Popen(command,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True)
            for line in iter(proc.stdout.readline, ''):
                f.write(line)
            for line in iter(proc.stderr.readline, ''):
                f.write(line)
                print("%s%s%s" % (FAIL, line, END))

    def _log_to_console(self, command, log):
        proc = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)
        for line in iter(proc.stdout.readline, ''):
            log.debug(line)
        for line in iter(proc.stderr.readline, ''):
            log.error(line)

    def _set_log(self, log_file, log_level):
        logger = logging.getLogger(PREFIX)

        if log_file is not None and log_file != '':
            formatter = logging.Formatter(
                '%(asctime)s %(levelname)s %(message)s')
            hdlr = logging.FileHandler(log_file)
            hdlr.setFormatter(formatter)
        else:
            hdlr = logging.StreamHandler(sys.stdout)

        logger.addHandler(hdlr)
        logger.setLevel(log_level)
        return logger

    def _print_success(self, log):
        msg = "Finished generating variable mapping file " \
              "for oVirt ansible disaster recovery."
        log.info(msg)
        print("%s%s%s%s" % (INFO, PREFIX, msg, END))

    def _print_error(self, log):
        msg = "Failed to generate var file."
        log.error(msg)
        print("%s%s%s%s" % (FAIL, PREFIX, msg, END))

    def _connect_sdk(self, url, username, password, ca):
        connection = sdk.Connection(
            url=url,
            username=username,
            password=password,
            ca_file=ca,
        )
        return connection

    def _validate_connection(self,
                             log,
                             url,
                             username,
                             password,
                             ca):
        conn = None
        try:
            conn = self._connect_sdk(url,
                                     username,
                                     password,
                                     ca)
            dcs_service = conn.system_service().data_centers_service()
            dcs_service.list()
        except Exception as e:
            msg = "Connection to setup has failed. " \
                  "Please check your credentials: " \
                  "\n URL: " + url + \
                  "\n user: " + username + \
                  "\n CA file: " + ca
            log.error(msg)
            print("%s%s%s%s" % (FAIL, PREFIX, msg, END))
            log.error("Error: %s", e)
            if conn:
                conn.close()
            return False
        return True

    def _validate_output_file_exists(self, output_file, log):
        _dir = os.path.dirname(output_file)
        if _dir != '' and not os.path.exists(_dir):
            log.warn("Path '%s' does not exist. Creating the directory.", _dir)
            os.makedirs(_dir)
        if os.path.isfile(output_file):
            valid = {"yes": True, "y": True, "ye": True,
                     "no": False, "n": False}
            ans = input("%s%sThe output file '%s' already exists. "
                        "Would you like to override it (y,n)? %s"
                        % (WARN, PREFIX, output_file, END))
            while True:
                ans = ans.lower()
                if ans in valid:
                    if valid[ans]:
                        break
                    msg = "Failed to create output file. " \
                          "File could not be overridden."
                    log.error(msg)
                    print("%s%s%s%s" % (FAIL, PREFIX, msg, END))
                    sys.exit(0)
                ans = input("%s%sPlease respond with 'yes' or 'no': %s"
                            % (INPUT, PREFIX, END))
            try:
                os.remove(output_file)
            except OSError:
                log.error("File %s could not be replaced.", output_file)
                print("%s%sFile %s could not be replaced.%s"
                      % (FAIL, PREFIX, output_file, END))
                sys.exit(0)

    def _init_vars(self, conf_file, log):
        """ Declare constants """
        _SECTION = 'generate_vars'
        _SITE = 'site'
        _USERNAME = 'username'
        _PASSWORD = 'password'
        _CA_FILE = 'ca_file'
        # TODO: Must have full path, should add relative path support.
        _OUTPUT_FILE = 'output_file'
        _ANSIBLE_PLAY = 'ansible_play'

        settings = ConfigParser()
        settings.read(conf_file)
        if _SECTION not in settings.sections():
            settings.add_section(_SECTION)
        if not settings.has_option(_SECTION, _SITE):
            settings.set(_SECTION, _SITE, '')
        if not settings.has_option(_SECTION, _USERNAME):
            settings.set(_SECTION, _USERNAME, '')
        if not settings.has_option(_SECTION, _PASSWORD):
            settings.set(_SECTION, _PASSWORD, '')
        if not settings.has_option(_SECTION, _CA_FILE):
            settings.set(_SECTION, _CA_FILE, '')
        if not settings.has_option(_SECTION, _OUTPUT_FILE):
            settings.set(_SECTION, _OUTPUT_FILE, '')
        if not settings.has_option(_SECTION, _ANSIBLE_PLAY):
            settings.set(_SECTION, _ANSIBLE_PLAY, '')

        site = settings.get(_SECTION, _SITE,
                            vars=DefaultOption(settings,
                                               _SECTION,
                                               site=None))

        username = settings.get(_SECTION, _USERNAME,
                                vars=DefaultOption(settings,
                                                   _SECTION,
                                                   username=None))

        password = settings.get(_SECTION, _PASSWORD,
                                vars=DefaultOption(settings,
                                                   _SECTION,
                                                   password=None))

        ca_file = settings.get(_SECTION, _CA_FILE,
                               vars=DefaultOption(settings,
                                                  _SECTION,
                                                  ca_file=None))
        ca_file = os.path.expanduser(ca_file)

        output_file = settings.get(_SECTION, _OUTPUT_FILE,
                                   vars=DefaultOption(settings,
                                                      _SECTION,
                                                      output_file=None))
        output_file = os.path.expanduser(output_file)

        ansible_play_file = settings.get(_SECTION, _ANSIBLE_PLAY,
                                         vars=DefaultOption(settings,
                                                            _SECTION,
                                                            ansible_play=None))
        ansible_play_file = os.path.expanduser(ansible_play_file)

        if not site:
            site = input("%s%sSite address is not initialized. "
                         "Please provide the site URL (%s): %s"
                         % (INPUT, PREFIX, SITE_DEF, END)
                         ) or SITE_DEF
        if not username:
            username = input("%s%sUsername is not initialized. "
                             "Please provide the username (%s): %s"
                             % (INPUT, PREFIX, USERNAME_DEF, END)
                             ) or USERNAME_DEF
        while not password:
            password = input("%s%sPassword is not initialized. "
                             "Please provide the password for username %s: %s"
                             % (INPUT, PREFIX, username, END))

        while not os.path.isfile(ca_file):
            ca_file = input("%s%sCA file '%s' does not exist. "
                            "Please provide the CA file location (%s):%s "
                            % (INPUT, PREFIX, ca_file, CA_DEF, END)
                            ) or CA_DEF
            ca_file = os.path.expanduser(ca_file)

        while not output_file:
            output_file = input("%s%sOutput file location is not initialized. "
                                "Please provide the output file location "
                                "for the mapping var file (%s): %s"
                                % (INPUT, PREFIX, _OUTPUT_FILE, END)
                                ) or _OUTPUT_FILE
            output_file = os.path.expanduser(output_file)
        self._validate_output_file_exists(output_file, log)

        while not os.path.isfile(ansible_play_file):
            ansible_play_file = input("%s%sAnsible play file '%s' does not "
                                      "exist. Please provide the ansible play "
                                      "file to generate the mapping var file "
                                      "(%s): %s" % (INPUT,
                                                    PREFIX,
                                                    ansible_play_file,
                                                    PLAY_DEF,
                                                    END)
                                      ) or PLAY_DEF
            ansible_play_file = os.path.expanduser(ansible_play_file)

        return site, username, password, ca_file, output_file, ansible_play_file


class DefaultOption(dict):

    def __init__(self, config, section, **kv):
        self._config = config
        self._section = section
        dict.__init__(self, **kv)

    def items(self):
        _items = []
        for option in self:
            if not self._config.has_option(self._section, option):
                _items.append((option, self[option]))
            else:
                value_in_config = self._config.get(self._section, option)
                _items.append((option, value_in_config))
        return _items


if __name__ == "__main__":
    GenerateMappingFile().run(conf_file='dr.conf',
                              log_file='/tmp/ovirt-dr.log',
                              log_level=logging.getLevelName("DEBUG"))
