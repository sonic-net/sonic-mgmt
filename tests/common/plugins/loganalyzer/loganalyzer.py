import sys
import logging
import os
import re
import time
import pprint

import system_msg_handler

from system_msg_handler import AnsibleLogAnalyzer as ansible_loganalyzer
from os.path import join, split
from os.path import normpath

ANSIBLE_LOGANALYZER_MODULE = system_msg_handler.__file__.replace(r".pyc", ".py")
COMMON_MATCH = join(split(__file__)[0], "loganalyzer_common_match.txt")
COMMON_IGNORE = join(split(__file__)[0], "loganalyzer_common_ignore.txt")
COMMON_EXPECT = join(split(__file__)[0], "loganalyzer_common_expect.txt")
SYSLOG_TMP_FOLDER = "/tmp/syslog"


class LogAnalyzerError(Exception):
    """Raised when loganalyzer found matches during analysis phase."""
    def __repr__(self):
        return pprint.pformat(self.message)


class LogAnalyzer:
    def __init__(self, ansible_host, marker_prefix, dut_run_dir="/tmp", start_marker=None):
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
        if result["total"]["match"] != 0 or result["total"]["expected_missing_match"] != 0:
            raise LogAnalyzerError(result)

        # Check for negative case
        if self.expect_regex and result["total"]["expected_match"] == 0:
            raise LogAnalyzerError(result)

        # if the number of expected matches is provided
        if (self.expect_regex and (self.expected_matches_target > 0)
           and result["total"]["expected_match"] != self.expected_matches_target):
            raise LogAnalyzerError(result)

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
        @summary: Add start marker into syslog on the DUT.

        @return: True for successfull execution False otherwise
        """
        logging.debug("Loganalyzer init")

        self.ansible_host.copy(src=ANSIBLE_LOGANALYZER_MODULE, dest=os.path.join(self.dut_run_dir, "loganalyzer.py"))

        return self._setup_marker()

    def _setup_marker(self):
        """
        Adds the marker to the syslog
        """
        start_marker = ".".join((self.marker_prefix, time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())))
        cmd = "python {run_dir}/loganalyzer.py --action init --run_id {start_marker}".format(run_dir=self.dut_run_dir, start_marker=start_marker)

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
        tmp_folder = ".".join((SYSLOG_TMP_FOLDER, time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime())))
        marker = marker.replace(' ', '_')
        self.ansible_loganalyzer.run_id = marker

        if not self.start_marker:
            start_string = 'start-LogAnalyzer-{}'.format(marker)
        else:
            start_string = self.start_marker

        try:
            # Disable logrotate cron task
            self.ansible_host.command("sed -i 's/^/#/g' /etc/cron.d/logrotate")

            logging.debug("Waiting for logrotate from previous cron task run to finish")
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

            # Add end marker into DUT syslog
            self._add_end_marker(marker)

            # On DUT extract syslog files from /var/log/ and create one file by location - /tmp/syslog
            self.ansible_host.extract_log(directory='/var/log', file_prefix='syslog', start_string=start_string, target_filename=self.extracted_syslog)
        finally:
            # Enable logrotate cron task back
            self.ansible_host.command("sed -i 's/^#//g' /etc/cron.d/logrotate")

        # Download extracted logs from the DUT to the temporal folder defined in SYSLOG_TMP_FOLDER
        self.save_extracted_log(dest=tmp_folder)

        match_messages_regex = re.compile('|'.join(self.match_regex)) if len(self.match_regex) else None
        ignore_messages_regex = re.compile('|'.join(self.ignore_regex)) if len(self.ignore_regex) else None
        expect_messages_regex = re.compile('|'.join(self.expect_regex)) if len(self.expect_regex) else None

        analyzer_parse_result = self.ansible_loganalyzer.analyze_file_list([tmp_folder], match_messages_regex, ignore_messages_regex, expect_messages_regex)
        # Print syslog file content and remove the file
        with open(tmp_folder) as fo:
            logging.debug("Syslog content:\n\n{}".format(fo.read()))
        os.remove(tmp_folder)

        total_match_cnt = 0
        total_expect_cnt = 0
        expected_lines_total = []
        unused_regex_messages = []

        for key, value in analyzer_parse_result.iteritems():
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
