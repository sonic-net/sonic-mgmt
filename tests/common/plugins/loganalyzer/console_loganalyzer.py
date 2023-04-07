import logging
import os
import re
import time
import pprint

from . import system_msg_handler

from .system_msg_handler import AnsibleLogAnalyzer as ansible_loganalyzer
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


class ConsoleLogAnalyzer:
    def __init__(self, console_files):
        marker_prefix = 'console_log'
        self.marker_prefix = marker_prefix.replace(' ', '_')
        self.ansible_loganalyzer = ansible_loganalyzer(self.marker_prefix, False, start_marker=None)

        self.match_regex = []
        self.expect_regex = []
        self.ignore_regex = []
        self.expected_matches_target = 0
        self.fail = True
        self.files = console_files

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

    def analyze(self, fail=True):
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
        match_messages_regex = re.compile('|'.join(self.match_regex)) if len(self.match_regex) else None
        ignore_messages_regex = re.compile('|'.join(self.ignore_regex)) if len(self.ignore_regex) else None
        expect_messages_regex = re.compile('|'.join(self.expect_regex)) if len(self.expect_regex) else None

        logging.debug("Analyze files {}".format(self.files))
        analyzer_parse_result = self.ansible_loganalyzer.analyze_file_list(self.files, match_messages_regex, ignore_messages_regex, expect_messages_regex)

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