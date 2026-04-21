#!/usr/bin/python3

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import logging
import os.path
import subprocess
from subprocess import call
import sys
import time

from configparser import ConfigParser

from bcolors import bcolors

INFO = bcolors.OKGREEN
INPUT = bcolors.OKGREEN
WARN = bcolors.WARNING
FAIL = bcolors.FAIL
END = bcolors.ENDC
PREFIX = "[Failover] "
VAR_FILE_DEF = "../examples/disaster_recovery_vars.yml"
PLAY_DEF = "../examples/dr_play.yml"
report_name = "report-{}.log"


class FailOver:

    def run(self, conf_file, log_file, log_level):
        log = self._set_log(log_file, log_level)
        log.info("Start failover operation...")
        target_host, source_map, var_file, vault_file, ansible_play_file = \
            self._init_vars(conf_file)
        report = report_name.format(int(round(time.time() * 1000)))
        log.info("\ntarget_host: %s \n"
                 "source_map: %s \n"
                 "var_file: %s \n"
                 "vault_file: %s \n"
                 "ansible_play_file: %s \n"
                 "report log file: /tmp/%s\n",
                 target_host,
                 source_map,
                 var_file,
                 vault_file,
                 ansible_play_file,
                 report)

        dr_tag = "fail_over"
        extra_vars = (" dr_target_host=" + target_host
                      + " dr_source_map=" + source_map
                      + " dr_report_file=" + report)
        command = [
            "ansible-playbook", ansible_play_file,
            "-t", dr_tag,
            "-e", "@" + var_file,
            "-e", "@" + vault_file,
            "-e", extra_vars,
            "--vault-password-file", "vault_secret.sh",
            "-vvv"
        ]

        # Setting vault password.
        vault_pass = input("%s%sPlease enter vault password "
                           "(in case of plain text please press ENTER): %s"
                           % (INPUT, PREFIX, END))
        os.system("export vault_password=\"" + vault_pass + "\"")

        log.info("Executing failover command: %s", ' '.join(map(str, command)))
        if log_file is not None and log_file != '':
            self._log_to_file(log_file, command)
        else:
            self._log_to_console(command, log)

        call(["cat", "/tmp/" + report])
        print("\n%s%sFinished failover operation"
              " for oVirt ansible disaster recovery%s" % (INFO, PREFIX, END))

    def _log_to_file(self, log_file, command):
        with open(log_file, "a") as f:
            proc = subprocess.Popen(command,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True)
            for line in iter(proc.stdout.readline, ''):
                if 'TASK [' in line:
                    print("\n%s%s%s\n" % (INFO, line, END))
                f.write(line)
            for line in iter(proc.stderr.readline, ''):
                f.write(line)
                print("%s%s%s" % (WARN, line, END))
        self._handle_result(command)

    def _log_to_console(self, command, log):
        proc = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)
        for line in iter(proc.stdout.readline, ''):
            log.debug(line)
        for line in iter(proc.stderr.readline, ''):
            log.warn(line)

    def _handle_result(self, command):
        try:
            # TODO: do something with the returned output?
            subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("%sException: %s\n\n"
                  "failover operation failed, please check log file for "
                  "further details.%s"
                  % (FAIL, e, END))
            sys.exit()

    def _init_vars(self, conf_file):
        """ Declare constants """
        _SECTION = "failover_failback"
        _TARGET = "dr_target_host"
        _SOURCE = "dr_source_map"
        _VAULT = "vault"
        _VAR_FILE = "var_file"
        _ANSIBLE_PLAY = 'ansible_play'
        setups = ['primary', 'secondary']

        settings = ConfigParser()
        settings.read(conf_file)
        if _SECTION not in settings.sections():
            settings.add_section(_SECTION)
        if not settings.has_option(_SECTION, _TARGET):
            settings.set(_SECTION, _TARGET, '')
        if not settings.has_option(_SECTION, _SOURCE):
            settings.set(_SECTION, _SOURCE, '')
        if not settings.has_option(_SECTION, _VAULT):
            settings.set(_SECTION, _VAULT, '')
        if not settings.has_option(_SECTION, _VAR_FILE):
            settings.set(_SECTION, _VAR_FILE, '')
        if not settings.has_option(_SECTION, _ANSIBLE_PLAY):
            settings.set(_SECTION, _ANSIBLE_PLAY, '')

        target_host = settings.get(_SECTION, _TARGET,
                                   vars=DefaultOption(settings,
                                                      _SECTION,
                                                      target_host=None))

        source_map = settings.get(_SECTION, _SOURCE,
                                  vars=DefaultOption(settings,
                                                     _SECTION,
                                                     source_map=None))

        vault_file = settings.get(_SECTION, _VAULT,
                                  vars=DefaultOption(settings,
                                                     _SECTION,
                                                     vault=None))
        vault_file = os.path.expanduser(vault_file)

        var_file = settings.get(_SECTION, _VAR_FILE,
                                vars=DefaultOption(settings,
                                                   _SECTION,
                                                   var_file=None))
        var_file = os.path.expanduser(var_file)

        ansible_play_file = settings.get(_SECTION, _ANSIBLE_PLAY,
                                         vars=DefaultOption(settings,
                                                            _SECTION,
                                                            ansible_play=None))
        ansible_play_file = os.path.expanduser(ansible_play_file)

        while target_host not in setups:
            target_host = input("%s%sThe target host '%s' was not defined. "
                                "Please provide the target host "
                                "to failover to (primary or secondary): %s"
                                % (INPUT, PREFIX, target_host, END))
        while source_map not in setups:
            source_map = input("%s%sThe source mapping '%s' was not defined. "
                               "Please provide the source mapping "
                               "(primary or secondary): %s"
                               % (INPUT, PREFIX, source_map, END))

        while not os.path.isfile(var_file):
            var_file = input("%s%sVar file '%s' does not exist. Please "
                             "provide the location of the var file (%s): %s"
                             % (INPUT, PREFIX, var_file, VAR_FILE_DEF, END)
                             ) or VAR_FILE_DEF
            var_file = os.path.expanduser(var_file)

        while not os.path.isfile(vault_file):
            vault_file = input("%s%sPassword file '%s' does not exist. "
                               "Please provide a valid password file: %s"
                               % (INPUT, PREFIX, vault_file, END))
            vault_file = os.path.expanduser(vault_file)

        while not os.path.isfile(ansible_play_file):
            ansible_play_file = input("%s%sAnsible play file '%s' does not "
                                      "exist. Please provide the ansible play "
                                      "file to run the failover flow (%s): %s"
                                      % (INPUT,
                                         PREFIX,
                                         ansible_play_file,
                                         PLAY_DEF,
                                         END)
                                      ) or PLAY_DEF
            ansible_play_file = os.path.expanduser(ansible_play_file)

        return target_host, source_map, var_file, vault_file, ansible_play_file

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
    FailOver().run(conf_file='dr.conf',
                   log_file='/tmp/ovirt-dr.log',
                   log_level=logging.getLevelName("DEBUG"))
