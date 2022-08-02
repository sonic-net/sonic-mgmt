import logging
import os
import re
import time
import pprint

from . import system_msg_handler

from .system_msg_handler import AnsibleLogAnalyzer as ansible_loganalyzer
from os.path import join, split

ANSIBLE_LOGANALYZER_MODULE = system_msg_handler.__file__.replace(r".pyc", ".py")
COMMON_MATCH = join(split(__file__)[0], "loganalyzer_common_match.txt")
COMMON_IGNORE = join(split(__file__)[0], "loganalyzer_common_ignore.txt")
COMMON_EXPECT = join(split(__file__)[0], "loganalyzer_common_expect.txt")
SYSLOG_TMP_FOLDER = "/tmp/syslog"


class DisableLogrotateCronContext:
    """
    Context class to help disable logrotate cron task and restore it automatically.
    """

    def __init__(self, ansible_host):
        """
        Constructor of DisableLogrotateCronContext.
        :param ansible_host: DUT object representing a SONiC switch under test.
        """
        self.ansible_host = ansible_host

    def __enter__(self):
        """
        Disable logrotate cron task / systemd timer and make sure the running logrotate is stopped.
        """
        # Disable logrotate systemd timer
        self.ansible_host.command("systemctl stop logrotate.timer")
        # Disable logrotate cron task
        self.ansible_host.command("sed -i 's/^/#/g' /etc/cron.d/logrotate")
        logging.debug("Waiting for logrotate from previous cron task or systemd timer run to finish")
        # Wait for logrotate from previous cron task run to finish
        end = time.time() + 60
        while time.time() < end:
            # Verify for exception because self.ansible_host automatically handle command return codes and raise exception for none zero code
            try:
                self.ansible_host.command("pgrep -f logrotate")
            except Exception:
                break
            else:
                time.sleep(5)
                continue
        else:
            logging.error("Logrotate from previous task was not finished during 60 seconds")

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Restore logrotate cron task and systemd timer.
        """
        # Enable logrotate cron task back
        self.ansible_host.command("sed -i 's/^#//g' /etc/cron.d/logrotate")
        # Enable logrotate systemd timer
        self.ansible_host.command("systemctl start logrotate.timer")


class LogAnalyzerError(Exception):
    """Raised when loganalyzer found matches during analysis phase."""
    def __repr__(self):
        return pprint.pformat("Log Analyzer Error- Matches found, please check errors in log")


class LogAnalyzer:
    def __init__(self, ansible_host, marker_prefix, dut_run_dir="/tmp", start_marker=None, additional_files={}):
        self.ansible_host = ansible_host
        self.dut_run_dir = dut_run_dir
        self.extracted_syslog = os.path.join(self.dut_run_dir, "syslog")
        self.marker_prefix = marker_prefix.replace(' ', '_')
        # use existing syslog msg as marker to search in logs instead of writing a new one
        self.start_marker = start_marker
        self.ansible_loganalyzer = ansible_loganalyzer(self.marker_prefix, False, start_marker=self.start_marker)

        self.match_regex = []
        self.expect_regex = []
        self.ignore_regex = []
        self.expected_matches_target = 0
        self._markers = []
        self.fail = True

        self.additional_files = list(additional_files.keys())
        self.additional_start_str = list(additional_files.values())

    def _add_end_marker(self, marker):
        """
        @summary: Add stop marker into syslog on the DUT.

        @return: True for successfull execution False otherwise
        """
        self.ansible_host.copy(src=ANSIBLE_LOGANALYZER_MODULE, dest=os.path.join(self.dut_run_dir, "loganalyzer.py"))

        cmd = "python {run_dir}/loganalyzer.py --action add_end_marker --run_id {marker}".format(run_dir=self.dut_run_dir, marker=marker)

        logging.debug("Adding end marker '{}'".format(marker))
        self.ansible_host.command(cmd)

    def __call__(self, **kwargs):
        """
        Pass additional arguments when the instance is called
        """
        self.fail = kwargs.get("fail", True)
        self.start_marker = kwargs.get("start_marker", None)
        return self

    def __enter__(self):
        """
        Store start markers which are used in analyze phase.
        """
        self._markers.append(self.init())

    def __exit__(self, *args):
        """
        Analyze syslog messages.
        """
        self.analyze(self._markers.pop(), fail=self.fail)

    def _verify_log(self, result):
        """
        Verify that total match and expected missing match equals to zero or raise exception otherwise.
        Verify that expected_match is not equal to zero when there is configured expected regexp in self.expect_regex list
        """
        if not result:
            raise LogAnalyzerError("Log analyzer failed - no result.")
        else:
            result_str = self._results_repr(result)
            if result["total"]["match"] != 0 or result["total"]["expected_missing_match"] != 0:
                raise LogAnalyzerError(result_str)

            # Check for negative case
            if self.expect_regex and result["total"]["expected_match"] == 0:
                err_parse = 'Log Analyzer failed parsing expected messages\n'
                raise LogAnalyzerError(err_parse + result_str)

            # if the number of expected matches is provided
            if (self.expect_regex and (self.expected_matches_target > 0)
               and result["total"]["expected_match"] != self.expected_matches_target):
                err_target = "Log analyzer expected {} messages but found only {}\n".format(self.expected_matches_target, len(self.expect_regex))
                raise LogAnalyzerError(err_target + result_str)

    def _results_repr(self, result):
        """
        @summary: The function converts error analysis dictionary to a readable string format.
        @param result: Dictionary returned from analyze() function
        """
        result_str = ''
        total_dic = result["total"]
        msg_dic = result["match_messages"]
        expect_dic = result['expect_messages']
        unused_list = result['unused_expected_regexp']

        for msg_type, counter in total_dic.items():
            result_str += msg_type + ": " + str(counter) + "\n"

        if any(msg_dic.values()):
            result_str += "\nMatch Messages:\n"
            for match in msg_dic:
                result_str += '\n'.join(msg_dic[match])

        if any(expect_dic.values()):
            result_str += "\nExpected Messages:\n"
            for expect in expect_dic:
                result_str += '\n'.join(expect_dic[expect])

        if unused_list:
            result_str += "\nExpected Messages that are missing:\n"
            result_str += '\n'.join(unused_list)

        return result_str

    def update_marker_prefix(self, marker_prefix):
        """
        @summary: Update configured marker prefix
        """
        self.marker_prefix = marker_prefix.replace(' ', '_')
        return self._setup_marker()

    def load_common_config(self):
        """
        @summary: Load regular expressions from common files, which are localted in folder with legacy loganalyzer.
                  Loaded regular expressions are used by "analyze" method to match expected text in the downloaded log file.
        """
        self.match_regex = self.ansible_loganalyzer.create_msg_regex([COMMON_MATCH])[1]
        self.ignore_regex = self.ansible_loganalyzer.create_msg_regex([COMMON_IGNORE])[1]
        self.expect_regex = self.ansible_loganalyzer.create_msg_regex([COMMON_EXPECT])[1]
        logging.debug('Loaded common config.')

    def parse_regexp_file(self, src):
        """
        @summary: Get regular expressions defined in src file.
        """
        return self.ansible_loganalyzer.create_msg_regex([src])[1]

    def run_cmd(self, callback, *args, **kwargs):
        """
        @summary: Initialize loganalyzer, execute function and analyze syslog.

        @param callback: Python callable or function to be executed.
        @param args: Input arguments for callback function.
        @param kwargs: Input key value arguments for callback function.

        @return: Callback execution result
        """
        marker = self.init()
        fail = kwargs.pop("fail", True)
        try:
            call_result = callback(*args, **kwargs)
        except Exception as err:
            logging.error("Error during callback execution:\n{}".format(err))
            logging.debug("Log analysis result\n".format(self.analyze(marker, fail=fail)))
            raise err
        self.analyze(marker, fail=fail)

        return call_result

    def init(self):
        """
        @summary: Add start marker into log files on the DUT.

        @return: True for successfull execution False otherwise
        """
        logging.debug("Loganalyzer init")

        self.ansible_host.copy(src=ANSIBLE_LOGANALYZER_MODULE, dest=os.path.join(self.dut_run_dir, "loganalyzer.py"))

        log_files = []
        for idx, path in enumerate(self.additional_files):
            if not self.additional_start_str or self.additional_start_str[idx] == '':
                log_files.append(path)

        return self._setup_marker(log_files=log_files)

    def add_start_ignore_mark(self, log_files=None):
        """
        Adds the start ignore marker to the log files
        """
        add_start_ignore_mark = ".".join((self.marker_prefix, time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())))
        cmd = "python {run_dir}/loganalyzer.py --action add_start_ignore_mark --run_id {add_start_ignore_mark}".format(run_dir=self.dut_run_dir, add_start_ignore_mark=add_start_ignore_mark)
        if log_files:
            cmd += " --logs {}".format(','.join(log_files))

        logging.debug("Adding start ignore marker '{}'".format(add_start_ignore_mark))
        self.ansible_host.command(cmd)
        self._markers.append(add_start_ignore_mark)

    def add_end_ignore_mark(self, log_files=None):
        """
        Adds the end ignore marker to the log files
        """
        marker = self._markers.pop()
        cmd = "python {run_dir}/loganalyzer.py --action add_end_ignore_mark --run_id {marker}".format(run_dir=self.dut_run_dir, marker=marker)
        if log_files:
            cmd += " --logs {}".format(','.join(log_files))

        logging.debug("Adding end ignore marker '{}'".format(marker))
        self.ansible_host.command(cmd)

    def _setup_marker(self, log_files=None):
        """
        Adds the marker to the log files
        """
        start_marker = ".".join((self.marker_prefix, time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())))
        cmd = "python {run_dir}/loganalyzer.py --action init --run_id {start_marker}".format(run_dir=self.dut_run_dir, start_marker=start_marker)
        if log_files:
            cmd += " --logs {}".format(','.join(log_files))

        logging.debug("Adding start marker '{}'".format(start_marker))
        self.ansible_host.command(cmd)
        return start_marker

    def analyze(self, marker, fail=True):
        """
        @summary: Extract syslog logs based on the start/stop markers and compose one file. Download composed file, analyze file based on defined regular expressions.

        @param marker: Marker obtained from "init" method.
        @param fail: Flag to enable/disable raising exception when loganalyzer find error messages.

        @return: If "fail" is False - return dictionary of parsed syslog summary, if dictionary can't be parsed - return empty dictionary. If "fail" is True and if found match messages - raise exception.
        """
        logging.debug("Loganalyzer analyze")
        analyzer_summary = {"total": {"match": 0, "expected_match": 0, "expected_missing_match": 0},
                            "match_files": {},
                            "match_messages": {},
                            "expect_messages": {},
                            "unused_expected_regexp": []
                            }
        timestamp = time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())
        tmp_folder = ".".join((SYSLOG_TMP_FOLDER, self.ansible_host.hostname, timestamp))
        marker = marker.replace(' ', '_')
        self.ansible_loganalyzer.run_id = marker

        if not self.start_marker:
            start_string = 'start-LogAnalyzer-{}'.format(marker)
        else:
            start_string = self.start_marker

        with DisableLogrotateCronContext(self.ansible_host):
            # Add end marker into DUT syslog
            self._add_end_marker(marker)

            # On DUT extract syslog files from /var/log/ and create one file by location - /tmp/syslog
            self.ansible_host.extract_log(directory='/var/log', file_prefix='syslog', start_string=start_string,
                                          target_filename=self.extracted_syslog)
            for idx, path in enumerate(self.additional_files):
                file_dir, file_name = split(path)
                extracted_file_name = os.path.join(self.dut_run_dir, file_name)
                if self.additional_start_str and self.additional_start_str[idx] != '':
                    start_str = self.additional_start_str[idx]
                else:
                    start_str = start_string
                self.ansible_host.extract_log(directory=file_dir, file_prefix=file_name, start_string=start_str,
                                              target_filename=extracted_file_name)

        # Download extracted logs from the DUT to the temporal folder defined in SYSLOG_TMP_FOLDER
        self.save_extracted_log(dest=tmp_folder)
        file_list = [tmp_folder]

        for path in self.additional_files:
            file_dir, file_name = split(path)
            extracted_file_name = os.path.join(self.dut_run_dir, file_name)
            tmp_folder = ".".join((extracted_file_name, timestamp))
            self.save_extracted_file(dest=tmp_folder, src=extracted_file_name)
            file_list.append(tmp_folder)

        match_messages_regex = re.compile('|'.join(self.match_regex)) if len(self.match_regex) else None
        ignore_messages_regex = re.compile('|'.join(self.ignore_regex)) if len(self.ignore_regex) else None
        expect_messages_regex = re.compile('|'.join(self.expect_regex)) if len(self.expect_regex) else None

        logging.debug("Analyze files {}".format(file_list))
        logging.debug('    match_regex="{}"'.format(match_messages_regex.pattern if match_messages_regex else ''))
        logging.debug('    ignore_regex="{}"'.format(ignore_messages_regex.pattern if ignore_messages_regex else ''))
        logging.debug('    expect_regex="{}"'.format(expect_messages_regex.pattern if expect_messages_regex else ''))
        analyzer_parse_result = self.ansible_loganalyzer.analyze_file_list(file_list, match_messages_regex, ignore_messages_regex, expect_messages_regex)
        # Print file content and remove the file
        for folder in file_list:
            with open(folder) as fo:
                logging.debug("{} file content:\n\n{}".format(folder, fo.read()))
            os.remove(folder)

        expected_lines_total = []
        unused_regex_messages = []

        for key, value in analyzer_parse_result.items():
            matching_lines, expecting_lines = value
            analyzer_summary["total"]["match"] += len(matching_lines)
            analyzer_summary["total"]["expected_match"] += len(expecting_lines)
            analyzer_summary["match_files"][key] = {"match": len(matching_lines), "expected_match": len(expecting_lines)}
            analyzer_summary["match_messages"][key] = matching_lines
            analyzer_summary["expect_messages"][key] = expecting_lines
            expected_lines_total.extend(expecting_lines)

        # Find unused regex matches
        for regex in self.expect_regex:
            for line in expected_lines_total:
                if re.search(regex, line):
                    break
            else:
                unused_regex_messages.append(regex)
        analyzer_summary["total"]["expected_missing_match"] = len(unused_regex_messages)
        analyzer_summary["unused_expected_regexp"] = unused_regex_messages
        logging.debug("Analyzer summary: {}".format(pprint.pformat(analyzer_summary)))

        if fail:
            self._verify_log(analyzer_summary)
        else:
            return analyzer_summary

    def save_extracted_log(self, dest):
        """
        @summary: Download extracted syslog log file to the ansible host.

        @param dest: File path to store downloaded log file.
        """
        self.ansible_host.fetch(dest=dest, src=self.extracted_syslog, flat="yes")

    def save_extracted_file(self, dest, src):
        """
        @summary: Download extracted file to the ansible host.

        @param dest: File path to store downloaded file.

        @param src: Source path to store downloaded file.
        """
        self.ansible_host.fetch(dest=dest, src=src, flat="yes")
