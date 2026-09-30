'''
Owner:          Hrachya Mughnetsyan <Hrachya@mellanox.com>

Created on:     11/11/2016

Description:    This file contains the log analyzer functionality in order
                to verify no failures are detected in the system logs while
                it can be that traffic/functionality works.

                Design is available in https://github.com/sonic-net/SONiC/wiki/LogAnalyzer

Usage:          Examples of how to use log analyzer
                sudo python loganalyzer.py \
                    --out_dir /home/hrachya/projects/loganalyzer/log.analyzer.results \
                    --action analyze \
                    --run_id myTest114 \
                    --logs file3.log \
                    -m /home/hrachya/projects/loganalyzer/match.file.1.log,/home/hrachya/projects/loganalyzer/match.file.2.log \    # noqa: E501 W605
                    -i ignore.file.1.log,ignore.file.2.log -v
'''

# ---------------------------------------------------------------------
# Global imports
# ---------------------------------------------------------------------

import sys
import getopt
import re
import os
import subprocess
import os.path
import csv
import time
import logging
import logging.handlers
import gzip
from datetime import datetime

# ---------------------------------------------------------------------
# Global variables
# ---------------------------------------------------------------------
tokenizer = ','
comment_key = '#'
system_log_file = '/var/log/syslog'

# -- List of ERROR codes to be returned by AnsibleLogAnalyzer
err_duplicate_start_marker = -1
err_duplicate_end_marker = -2
err_no_end_marker = -3
err_no_start_marker = -4
err_invalid_string_format = -5
err_invalid_input = -6
err_end_ignore_marker = -7
err_start_ignore_marker = -8

# -- Max log message length
# The default maximum length of a single log message. Any line longer than MAX_LOG_MESSAGE_LENGTH
# will not be picked up by the analyzer.
MAX_LOG_MESSAGE_LENGTH = 1000


class AnsibleLogAnalyzer:
    '''
    @summary: Overview of functionality

    This class performs analysis of the log files, searching for concerning messages.
    The definition of concerning messages is passed to analyze_file_list() method,
    as a list of regular expressions.
    Additionally there will be a list of regular expressions which we wish to ignore.
    Any line in log file which will match to the set of matching regex expressions
    AND will not match set of 'ignore' regex expressions, will be considered a
    'match' and will be reported.

    AnsibleLogAnalyzer will be called initially before any test has ran, and will be
    instructed to place 'start' marker into all log files to be analyzed.
    When tests have ran, AnsibleLogAnalyzer will be instructed to place end-marker
    into the log files. After this, AnsibleLogAnalyzer will be invoked to perform the
    analysis of logs. The analysis will be performed on specified log files.
    For each log file only the content between start/end markers will be analyzed.

    For details see comments on analyze_file_list method.
    '''

    '''
    Prefixes used to build start and end markers.
    The prefixes will be combined with a unique string, called run_id, passed by
    the caller, to produce start/end markers for given analysis run.
    '''

    start_marker_prefix = "start-LogAnalyzer"
    end_marker_prefix = "end-LogAnalyzer"
    start_ignore_marker_prefix = "start-ignore-LogAnalyzer"
    end_ignore_marker_prefix = "end-ignore-LogAnalyzer"

    def init_sys_logger(self):
        logger = logging.getLogger('LogAnalyzer')
        logger.setLevel(logging.DEBUG)
        # 'LogAnalyzer' is a named (shared) logger, so repeated calls would
        # otherwise keep appending SysLogHandlers. That would make a single
        # logger.info(marker) fan out through every accumulated handler and
        # write duplicate marker lines to /var/log/syslog on retries, which
        # analyze_file() rejects with err_duplicate_start/end_marker. Remove
        # and close any previously attached handlers so exactly one datagram
        # is emitted per info() call.
        for existing in list(logger.handlers):
            logger.removeHandler(existing)
            try:
                existing.close()
            except Exception:
                # Keep logger setup working if a detached handler cannot close.
                pass
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        logger.addHandler(handler)
        return logger
    # ---------------------------------------------------------------------

    def __init__(self, run_id, verbose, start_marker=None):
        self.run_id = run_id
        self.verbose = verbose
        self.start_marker = start_marker
    # ---------------------------------------------------------------------

    def print_diagnostic_message(self, message):
        if (not self.verbose):
            return

        print(('[LogAnalyzer][diagnostic]:%s' % message))
    # ---------------------------------------------------------------------

    def create_start_marker(self):
        if (self.start_marker is None) or (len(self.start_marker) == 0):
            return self.start_marker_prefix + "-" + self.run_id
        else:
            return self.start_marker

    # ---------------------------------------------------------------------

    def is_filename_stdin(self, file_name):
        return file_name == "-"

    # ---------------------------------------------------------------------

    def require_marker_check(self, file_path):
        '''
        @summary: Check if log file needs to check for default start/end markers

        There are a few log files that do not follow the default start/end markers
        due to datetime format or capability of adding default end marker in tests.
        This function is introduced to identify whether a file needs default marker
        check.
        '''
        files_to_skip = ["sairedis.rec", "bgpd.log"]
        return not any([target in file_path for target in files_to_skip])

    # ---------------------------------------------------------------------

    def create_end_marker(self):
        return self.end_marker_prefix + "-" + self.run_id
    # ---------------------------------------------------------------------

    def create_start_ignore_marker(self):
        return self.start_ignore_marker_prefix + "-" + self.run_id
    # ---------------------------------------------------------------------

    def create_end_ignore_marker(self):
        return self.end_ignore_marker_prefix + "-" + self.run_id
    # ---------------------------------------------------------------------

    def flush_rsyslogd(self):
        '''
        @summary: flush all remaining buffer in rsyslogd to disk

        Uses 'systemctl reload rsyslog' instead of 'kill -HUP' to avoid a race
        condition where buffered syslog messages can be lost during the signal
        handler's file-close/reopen cycle.  systemctl reload performs a cleaner
        reload that is less prone to dropping in-flight messages.

        After the reload, a short sleep gives rsyslog time to finish flushing
        its internal queues to disk.

        See: https://serverfault.com/questions/813871/proper-way-to-reload-rsyslog
        '''
        os.system("sudo systemctl reload rsyslog 2>/dev/null || true")
        time.sleep(0.5)

    def place_marker_to_file(self, log_file, marker):
        '''
        @summary: Place marker into each log file specified.
        @param log_file : File path, to be applied with marker.
        @param marker:    Marker to be placed into log files.
        '''
        if not len(log_file) or self.is_filename_stdin(log_file):
            self.print_diagnostic_message(
                'Log file {} not found. Skip adding marker.'.format(log_file))
        self.print_diagnostic_message(
            'log file:{}, place marker {}'.format(log_file, marker))
        with open(log_file, 'a') as file:
            file.write(datetime.now().strftime("%b %d %H:%M:%S.%f") + ' ')
            file.write(marker)
            file.write('\n')
            file.flush()

    def place_marker_to_syslog(self, marker, flush=True):
        '''
        @summary: Place marker into '/dev/log'.

        Writes to '/dev/log' use a datagram socket (SysLogHandler). When rsyslog
        is overloaded the socket buffer can fill and the datagram is silently
        dropped, so the marker never reaches /var/log/syslog. Rather than
        emitting duplicate copies of the marker (which would produce duplicate
        start/end marker lines and make analyze_file() fail with
        err_duplicate_start_marker / err_duplicate_end_marker), delivery is made
        reliable by the caller: place_marker() verifies the marker actually
        landed in /var/log/syslog and re-emits it only when it did not appear.

        @param marker:  Marker to be placed into syslog.
        @param flush:   When True, flush rsyslog's queues before writing. The
                        retry path in place_marker() performs its own flush and
                        re-check before re-emitting (to avoid duplicating a
                        merely-delayed marker), so it passes flush=False here.

        Flush rsyslog's internal queues *before* writing the marker so that
        the reload (which briefly closes and reopens log files) does not race
        with the marker message sitting in rsyslog's buffer.  After the marker
        is sent we only need a short sleep for rsyslog to write it out under
        normal (non-reload) conditions.
        '''

        # Flush any previously buffered messages first, so the reload
        # does not interfere with the marker we are about to write.
        if flush:
            self.flush_rsyslogd()

        syslogger = self.init_sys_logger()
        syslogger.info(marker)
        syslogger.info('\n')

        # Give rsyslog time to write the marker to disk.
        # Do NOT call flush_rsyslogd() here — a reload right after writing
        # can cause the marker message to be dropped (see #23562).
        time.sleep(2)

    def _grep_stream_for_marker(self, file_obj, marker):
        '''
        @summary: Check whether marker appears from file_obj's current read
        position onward, using grep -F instead of a Python line-by-line scan
        so marker detection stays reliable when the log file is large or
        growing quickly under heavy rsyslog load.
        '''
        result = subprocess.run(
            ['grep', '-Fq', '--', marker],
            stdin=file_obj,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        return result.returncode == 0

    def is_marker_in_syslog(self, marker, start_pos=0, start_identity=None):
        '''
        @summary: Single, non-blocking, rotation-aware scan for the marker. It
                  does not sleep (unlike wait_for_marker()); it is used by the
                  retry path to detect a marker that a prior rsyslog flush may
                  have just made visible, so we can avoid emitting a duplicate
                  marker line.

                  /var/log/syslog is scanned from ``start_pos`` onward. Markers
                  with the same run_id/prefix from an earlier invocation may
                  already exist in syslog (pytest markers use only second-level
                  timestamp precision and callers may pass stable prefixes);
                  bounding the scan to bytes written after this placement began
                  ensures we only match a marker that the current call emitted,
                  never a stale one.

                  If a rotation is detected (inode change vs ``start_identity``,
                  or the current file being smaller than ``start_pos``), the
                  just-rotated /var/log/syslog.1 is also scanned -- bounded to
                  ``start_pos`` -- because a delayed marker from a previous
                  attempt may have landed in the renamed file, or in the fresh
                  syslog at an offset below the old size. This mirrors
                  wait_for_marker()'s rotation handling so the pre-retry
                  duplicate check does not miss such a marker and re-emit a
                  duplicate in the overload-plus-rotation case.
        @param marker:         Marker to look for.
        @param start_pos:      Byte offset in /var/log/syslog to start from.
        @param start_identity: (st_dev, st_ino) of /var/log/syslog captured
                               before the marker was emitted, used to detect a
                               rotation. When None, rotation is inferred only
                               from the file shrinking below ``start_pos``.
        @return: True if the marker is present at/after start_pos, else False.
        '''
        syslog_file = "/var/log/syslog"
        max_rotated_files = 9
        rotated = False
        if os.path.exists(syslog_file):
            try:
                with open(syslog_file, 'r') as fp:
                    try:
                        fst = os.fstat(fp.fileno())
                        cur_identity = (fst.st_dev, fst.st_ino)
                        cur_size = fst.st_size
                    except (IOError, OSError):
                        cur_identity = None
                        cur_size = None
                    identity_changed = (
                        cur_identity is not None and start_identity is not None
                        and cur_identity != start_identity)
                    shrank_past_start = (
                        cur_size is not None and start_pos
                        and cur_size < start_pos)
                    rotated = identity_changed or shrank_past_start
                    # After a rotation the current file is fresh, so scan it
                    # from the top; otherwise resume from start_pos.
                    if start_pos and not rotated:
                        try:
                            fp.seek(start_pos)
                        except (IOError, OSError):
                            return False
                    if self._grep_stream_for_marker(fp, marker):
                        return True
            except (IOError, OSError):
                return False
        # If rotated, the marker may have moved into rotated files. Scan them bounded
        # to start_pos so pre-placement (stale) bytes are never matched.
        if rotated:
            for i in range(1, max_rotated_files + 1):
                rotated_syslog_file = "{}.{}".format(syslog_file, i)
                # Check for both uncompressed and compressed versions
                files_to_check = [rotated_syslog_file]
                if i > 1:
                    # Files beyond syslog.1 are typically compressed
                    files_to_check.append("{}.gz".format(rotated_syslog_file))

                for file_path in files_to_check:
                    if os.path.exists(file_path):
                        try:
                            # Use gzip.open for .gz files, regular open for others
                            if file_path.endswith('.gz'):
                                file_handle = gzip.open(file_path, 'rt')
                            else:
                                file_handle = open(file_path, 'r')

                            with file_handle as rfp:
                                if start_pos:
                                    try:
                                        rfp.seek(start_pos)
                                    except (IOError, OSError):
                                        continue
                                if file_path.endswith('.gz'):
                                    for logs in rfp:
                                        if marker in logs:
                                            return True
                                elif self._grep_stream_for_marker(rfp, marker):
                                    return True
                        except (IOError, OSError):
                            continue
        return False

    def wait_for_marker(self, marker, timeout=120, polling_interval=2,
                        start_pos=0, start_identity=None):
        '''
        @summary: Wait the marker to appear in the /var/log/syslog file
        @param marker:         Marker to be placed into log files.
        @param timeout:        Maximum time in seconds to wait till Marker in /var/log/syslog
        @param polling_interval:  Polling interval during the wait
        @param start_pos:      Byte offset in /var/log/syslog at which this
                               placement began. Only content written at/after
                               this offset is considered, so a stale marker with
                               the same run_id/prefix left by an earlier
                               invocation is never matched. syslog.1 is only
                               searched once a rotation is detected, because
                               before rotation any match in syslog.1 would
                               necessarily be stale; and that syslog.1 scan is
                               itself bounded to this same start_pos, since
                               syslog.1 is the rotated original file and our
                               marker can only appear at/after where we began.
        @param start_identity: (st_dev, st_ino) of /var/log/syslog captured by
                               the caller *before* emitting the marker. Passing
                               it in is essential: place_marker_to_syslog()
                               sleeps ~2s after writing, and if logrotate runs
                               in that window the marker moves to syslog.1 before
                               this method is even entered. Seeding the baseline
                               identity from before the write lets us still
                               observe that inode change (or fall back to the
                               start_pos > current size heuristic) and search
                               syslog.1. When None, the identity is sampled at
                               entry (best effort).
        '''

        wait_time = 0
        # Resume scanning /var/log/syslog from where this placement began so we
        # skip pre-existing (stale) markers.
        last_check_pos = start_pos
        syslog_file = "/var/log/syslog"
        max_rotated_files = 9
        # Track the syslog file identity (device, inode) so we can detect a
        # rotation reliably. Size shrinkage alone is not a dependable signal:
        # after logrotate creates a fresh syslog it can grow back past
        # last_check_pos before the next poll, which would hide the rotation.
        # When the inode changes we know the previous file (now syslog.1) must
        # be searched and the scan of the new file restarted from the top. The
        # baseline is taken from the caller (pre-write) when provided so a
        # rotation that happened during the post-write sleep is not missed.
        if start_identity is not None:
            prev_identity = start_identity
        else:
            try:
                st = os.stat(syslog_file)
                prev_identity = (st.st_dev, st.st_ino)
            except (IOError, OSError):
                prev_identity = None
        # Once a rotation is observed, keep scanning /var/log/syslog.1 for the
        # rest of the wait. rsyslog may still be draining to the old (now
        # renamed) file descriptor and append this marker to syslog.1 several
        # polls after the inode change was first seen; a per-iteration flag
        # would stop looking there after that single poll and miss it, causing
        # a false failure and a duplicate re-emit on retry.
        rotation_seen = False
        while wait_time <= timeout:
            # look for marker in syslog file
            if os.path.exists(syslog_file):
                with open(syslog_file, 'r') as fp:
                    try:
                        fst = os.fstat(fp.fileno())
                        cur_identity = (fst.st_dev, fst.st_ino)
                        cur_size = fst.st_size
                    except (IOError, OSError):
                        cur_identity = None
                        cur_size = None
                    identity_changed = (
                        cur_identity is not None and prev_identity is not None
                        and cur_identity != prev_identity)
                    # If our starting offset is already past the end of the
                    # current file, the file we began watching was replaced by a
                    # smaller/fresh one (rotation) even if the inode read raced.
                    shrank_past_start = (
                        cur_size is not None and start_pos
                        and cur_size < start_pos)
                    if identity_changed or shrank_past_start:
                        # syslog was rotated while we waited (or during the
                        # post-write sleep). The marker we care about may have
                        # moved into syslog.1; restart from the top of the fresh
                        # file and allow a syslog.1 search below. Latch the
                        # rotation so syslog.1 keeps being scanned for the rest
                        # of the wait, not just this single poll.
                        rotation_seen = True
                        last_check_pos = 0
                    if cur_identity is not None:
                        prev_identity = cur_identity
                    # resume from last search position
                    if last_check_pos:
                        fp.seek(last_check_pos)
                    # check if marker in the file
                    if self._grep_stream_for_marker(fp, marker):
                        return True
                    # record last search position
                    last_check_pos = fp.tell()

            # Logs might get rotated while waiting for marker.
            # Search all rotated syslog files (syslog.1 through syslog.9).
            # This handles cases where logrotate ran between marker write
            # and marker search, pushing the marker into older rotated files.
            # Files beyond syslog.1 are typically compressed (syslog.2.gz, etc).
            if rotation_seen:
                for i in range(1, max_rotated_files + 1):
                    rotated_syslog_file = "{}.{}".format(syslog_file, i)
                    # Check for both uncompressed and compressed versions
                    files_to_check = [rotated_syslog_file]
                    if i > 1:
                        # Files beyond syslog.1 are typically compressed
                        files_to_check.append("{}.gz".format(rotated_syslog_file))

                    for file_path in files_to_check:
                        if os.path.exists(file_path):
                            try:
                                # Use gzip.open for .gz files, regular open for others
                                if file_path.endswith('.gz'):
                                    file_handle = gzip.open(file_path, 'rt')
                                else:
                                    file_handle = open(file_path, 'r')

                                with file_handle as rfp:
                                    # rotated file is the just-rotated original /var/log/syslog that
                                    # we began watching at ``start_pos``. Our marker, if it made
                                    # it there, was appended at/after ``start_pos`` (it was
                                    # written after we sampled that offset), so bound the scan to
                                    # ``start_pos``. This prevents matching a stale marker with
                                    # the same run_id/prefix that existed *before* this placement
                                    # began -- exactly the pre-rotation bytes the raw scan would
                                    # otherwise falsely accept. Seek unconditionally: if the file
                                    # is smaller than ``start_pos`` (it is not our original file,
                                    # or was truncated) the seek lands past EOF and iteration
                                    # yields no lines, which is the safe outcome (we keep waiting
                                    # / re-emit rather than trust a stale match). Never fall back
                                    # to scanning from offset 0, which would read stale lines.
                                    safe_to_scan = True
                                    if start_pos:
                                        try:
                                            rfp.seek(start_pos)
                                        except (IOError, OSError):
                                            # Could not position the scan safely; skip this file
                                            # this round rather than risk matching stale bytes.
                                            safe_to_scan = False
                                    # check if marker in the file
                                    if safe_to_scan:
                                        if file_path.endswith('.gz'):
                                            found = any(marker in logs for logs in rfp)
                                        else:
                                            found = self._grep_stream_for_marker(rfp, marker)
                                        if found:
                                            self.print_diagnostic_message(
                                                'Found marker {} in rotated file {}'
                                                .format(marker, file_path)
                                            )
                                            return True
                            except (IOError, OSError, EOFError, UnicodeDecodeError) as e:
                                # File might be compressed or deleted during rotation
                                self.print_diagnostic_message(
                                    'Could not read {}: {}'
                                    .format(file_path, str(e))
                                )
                                continue
            time.sleep(polling_interval)
            wait_time += polling_interval

        return False

    def place_marker(self, log_file_list, marker, wait_for_marker=False,
                     write_attempts=3, marker_timeout=160):
        '''
        @summary: Place marker into '/dev/log' and each log file specified.
        @param log_file_list :   List of file paths, to be applied with marker.
        @param marker:           Marker to be placed into log files.
        @param wait_for_marker:  When True, verify the marker actually reached
                                 /var/log/syslog and re-emit it (with backoff)
                                 until it appears or write_attempts is exhausted.
                                 This guards against silent drops when rsyslog is
                                 overloaded on the DUT.
        @param write_attempts:   Max number of write+verify cycles when
                                 wait_for_marker is True. Exactly one marker is
                                 emitted per cycle, so at most one marker line is
                                 written on the successful attempt -- this avoids
                                 duplicate start/end markers that would make
                                 analyze_file() fail.
        @param marker_timeout:   Overall time budget (seconds) shared across all
                                 write attempts when wait_for_marker is True.
                                 Callers run this under parallel_run(timeout=180)
                                 (see analyzer_add_marker), so the per-attempt
                                 The first attempt waits up to 120 seconds, as
                                 the previous single-write path did; remaining
                                 time is shared across retries. Must stay below
                                 the caller's parallel_run timeout.
        '''

        for log_file in log_file_list:
            self.place_marker_to_file(log_file, marker)

        if not wait_for_marker:
            self.place_marker_to_syslog(marker)
            return

        # Overload-resilient path: write, verify it landed in syslog, and
        # re-emit if it didn't. Writing to the datagram /dev/log socket can be
        # silently dropped, so a single write is not reliable. Only one marker
        # is emitted per attempt and we stop as soon as it is observed, keeping
        # exactly one marker line in syslog under normal conditions.
        #
        # Record where syslog ends before we emit anything. Both the pre-write
        # duplicate check and the post-write verify are bounded to this offset
        # so a same run_id/prefix marker from an earlier invocation (markers
        # have second-level precision and can use stable prefixes) is never
        # matched -- otherwise we would skip writing the current start/end
        # marker and bound analysis to a stale window. Capture the file
        # identity too: place_marker_to_syslog() sleeps ~2s after writing, and a
        # logrotate in that window would otherwise be invisible to
        # wait_for_marker() (its baseline would already be the new file).
        try:
            _st = os.stat("/var/log/syslog")
            syslog_start_pos = _st.st_size
            syslog_start_identity = (_st.st_dev, _st.st_ino)
        except (IOError, OSError):
            syslog_start_pos = 0
            syslog_start_identity = None

        attempts = max(1, write_attempts)
        # Give the first write the legacy 120-second window before retrying:
        # rsyslog may delay a datagram rather than drop it. Reserve retry time
        # from the overall budget so retries still fit within parallel_run.
        if attempts == 1:
            attempt_timeouts = [marker_timeout]
        else:
            retry_timeout = max(
                10, (marker_timeout - 120) // (attempts - 1))
            first_timeout = min(
                120, max(10, marker_timeout - retry_timeout * (attempts - 1)))
            retry_timeout = max(
                10, (marker_timeout - first_timeout) // (attempts - 1))
            attempt_timeouts = [first_timeout] + [retry_timeout] * (attempts - 1)
        polling_interval = min(5, min(attempt_timeouts))

        for attempt, attempt_timeout in enumerate(attempt_timeouts, start=1):
            # Flush rsyslog first, then re-check before (re-)emitting. A
            # datagram from a previous attempt may have been merely delayed
            # inside rsyslog rather than dropped; the flush can push it out to
            # /var/log/syslog. Detecting it here avoids emitting a second
            # identical marker, which analyze_file() would reject as a
            # duplicate start/end marker. The scan is bounded to bytes written
            # after syslog_start_pos so stale markers are never matched, and it
            # is a non-blocking single scan so it adds no wait on the common
            # path. It is also rotation-aware (syslog_start_identity): if a
            # logrotate happened after the offset was captured, a delayed
            # marker may now be in the fresh syslog below the old size or in
            # syslog.1, and this check follows it there so we do not re-emit a
            # duplicate.
            self.flush_rsyslogd()
            if self.is_marker_in_syslog(marker, start_pos=syslog_start_pos,
                                        start_identity=syslog_start_identity):
                return
            self.place_marker_to_syslog(marker, flush=False)
            if self.wait_for_marker(marker, timeout=attempt_timeout,
                                    polling_interval=polling_interval,
                                    start_pos=syslog_start_pos,
                                    start_identity=syslog_start_identity):
                return
            self.print_diagnostic_message(
                "marker {} not found in syslog after attempt {}/{}, retrying"
                .format(marker, attempt, attempts))

        raise RuntimeError(
            "cannot find marker {} in /var/log/syslog after {} attempts"
            .format(marker, attempts))
    # ---------------------------------------------------------------------

    def error_to_regx(self, error_string):
        r'''
        This method converts a (list of) strings to one regular expression.

        @summary: Meta characters are escaped by inserting a '\' beforehand
                  Digits are replaced with the arbitrary '\d+' code
                  A list is converted into an alteration statement (|)

        @param error_string:  the string(s) to be converted into a regular expression

        @return: A SINGLE regular expression string
        '''

        # -- Check if error_string is a string or a list --#
        if (isinstance(error_string, str)):
            # -- Escapes out of all the meta characters --#
            error_string = re.escape(error_string)
            # -- Replaces a white space with the white space regular expression
            error_string = re.sub(r"(\\\s+)+", "\\\\s+", error_string)
            # -- Replaces a digit number with the digit regular expression
            error_string = re.sub(r"\b\d+\b", "\\\\d+", error_string)
            # -- Replaces a hex number with the hex regular expression
            error_string = re.sub(
                r"0x[0-9a-fA-F]+", "0x[0-9a-fA-F]+", error_string)
            self.print_diagnostic_message(
                'Built error string: %s' % error_string)

        # -- If given a list, concatenate into one regx --#
        else:
            error_string = '|'.join(map(self.error_to_regx, error_string))

        return error_string
    # ---------------------------------------------------------------------

    def create_msg_regex(self, file_lsit):
        '''
        @summary: This method reads input file containing list of regular expressions
                  to be matched against.

        @param file_list : List of file paths, contains search expressions.

        @return: A regex class instance, corresponding to loaded regex expressions.
            Will be used for matching operations by callers.
        '''
        messages_regex = []

        if file_lsit is None or (0 == len(file_lsit)):
            return None

        for filename in file_lsit:
            self.print_diagnostic_message(
                'processing match file:%s' % filename)
            with open(filename, 'r') as csvfile:
                csvreader = csv.reader(csvfile, quotechar='"', delimiter=',',
                                       skipinitialspace=True)

                for index, row in enumerate(csvreader):
                    row = [item for item in row if item != ""]
                    self.print_diagnostic_message(
                        '[diagnostic]:processing row:%d' % index)
                    self.print_diagnostic_message('row:%s' % row)
                    try:
                        # -- Ignore Empty Lines
                        if not row:
                            continue
                        # -- Ignore commented Lines
                        if row[0].startswith(comment_key):
                            self.print_diagnostic_message(
                                '[diagnostic]:skipping row[0]:%s' % row[0])
                            continue

                        # -- ('s' | 'r') = (Raw String | Regular Expression)
                        is_regex = row[0]
                        if ('s' == row[0]):
                            is_regex = False
                        elif ('r' == row[0]):
                            is_regex = True
                        else:
                            raise Exception('file:%s, malformed line:%d. '
                                            'must be \'s\'(string) or \'r\'(regex)'
                                            % (filename, index))

                        if (is_regex):
                            messages_regex.extend(row[1:])
                        else:
                            messages_regex.append(self.error_to_regx(row[1:]))

                    except Exception as e:
                        print(('ERROR: line %d is formatted incorrectly in file %s. Skipping line' % (
                            index, filename)))
                        print((repr(e)))
                        sys.exit(err_invalid_string_format)

        if (len(messages_regex)):
            regex = re.compile('|'.join(messages_regex))
        else:
            regex = None
        return regex, messages_regex
    # ---------------------------------------------------------------------

    def line_matches(self, str, match_messages_regex, ignore_messages_regex):
        '''
        @summary: This method checks whether given string matches against the
                  set of regular expressions.

        @param str: string to match against 'match' and 'ignore' regex expressions.
            A string which matched to the 'match' set will be reported.
            A string which matches to 'match' set, but also matches to
            'ignore' set - will not be reported (will be ignored)

        @param match_messages_regex:
            regex class instance containing messages to match against.

        @param ignore_messages_regex:
            regex class instance containing messages to ignore match against.

        @return: True is str matches regex criteria, otherwise False.
        '''

        ret_code = False

        if ((match_messages_regex is not None) and (match_messages_regex.findall(str))):
            if (ignore_messages_regex is None):
                ret_code = True

            elif (not ignore_messages_regex.findall(str)):
                self.print_diagnostic_message('matching line: %s' % str)
                ret_code = True

        return ret_code
    # ---------------------------------------------------------------------

    def line_is_expected(self, str, expect_messages_regex):
        '''
        @summary: This method checks whether given string matches against the
                  set of "expected" regular expressions.
        '''

        ret_code = False
        if self.run_id.startswith("test_advanced_reboot_test_"):
            # Use the stricter (and better-performing) match instead of findall, but only when analyzing
            # logs for advanced reboot test cases. This is so that other test cases are not affected in
            # case their regexes don't start with .*
            if (expect_messages_regex is not None) and (expect_messages_regex.match(str)):
                ret_code = True
        else:
            if (expect_messages_regex is not None) and (expect_messages_regex.findall(str)):
                ret_code = True

        return ret_code

    def analyze_file(self, log_file_path, match_messages_regex, ignore_messages_regex, expect_messages_regex,
                     maximum_log_length=None):
        '''
        @summary: Analyze input file content for messages matching input regex
                  expressions. See line_matches() for details on matching criteria.

        @param log_file_path: Patch to the log file.

        @param match_messages_regex:
            regex class instance containing messages to match against.

        @param ignore_messages_regex:
            regex class instance containing messages to ignore match against.

        @param expect_messages_regex:
            regex class instance containing messages that are expected to appear in logfile.

        @param end_marker_regex - end marker

        @param maximum_log_length - The long log message (length > maximum_log_length) will be dropped by LogAnalyzer.

        @return: List of strings match search criteria.
        '''

        self.print_diagnostic_message('analyzing file: %s' % log_file_path)

        # -- indicates whether log analyzer currently is in the log range between start
        # -- and end marker. see analyze_file method.
        check_marker = self.require_marker_check(log_file_path)
        in_analysis_range = not check_marker
        stdin_as_input = self.is_filename_stdin(log_file_path)
        matching_lines = []
        expected_lines = []
        found_start_marker = False
        found_end_marker = False
        if stdin_as_input:
            log_file = sys.stdin
        else:
            log_file = open(log_file_path, 'r')

        start_marker = self.create_start_marker()
        end_marker = self.create_end_marker()

        ignore_marker_run_ids = []
        for rev_line in reversed(log_file.readlines()):
            if stdin_as_input:
                in_analysis_range = True
            else:
                if end_marker in rev_line:
                    self.print_diagnostic_message(
                        'found end marker: %s' % end_marker)
                    if (found_end_marker):
                        print('ERROR: duplicate end marker found')
                        sys.exit(err_duplicate_end_marker)
                    found_end_marker = True
                    in_analysis_range = True
                    continue
                elif self.end_ignore_marker_prefix in rev_line:
                    marker_run_id = rev_line.split(
                        self.end_ignore_marker_prefix)[1]
                    ignore_marker_run_ids.append(marker_run_id)
                    self.print_diagnostic_message('found end ignore marker: %s'
                                                  % rev_line[rev_line.index(self.end_ignore_marker_prefix):])
                    if not in_analysis_range:
                        print('ERROR: duplicate end ignore marker found')
                        sys.exit(err_end_ignore_marker)
                    in_analysis_range = False
                    continue

                elif self.start_ignore_marker_prefix in rev_line:
                    marker_run_id = ignore_marker_run_ids.pop()
                    self.print_diagnostic_message('found start ignore marker: %s'
                                                  % rev_line[rev_line.index(self.start_ignore_marker_prefix):])
                    if in_analysis_range or marker_run_id not in rev_line:
                        print('ERROR: unexpected start ignore marker found')
                        sys.exit(err_start_ignore_marker)
                    in_analysis_range = True
                    continue

            if not stdin_as_input:
                if rev_line.find(start_marker) != -1 and 'extract_log' not in rev_line:
                    self.print_diagnostic_message(
                        'found start marker: %s' % start_marker)
                    if (found_start_marker):
                        print('ERROR: duplicate start marker found')
                        sys.exit(err_duplicate_start_marker)
                    found_start_marker = True

                    if (not in_analysis_range):
                        print(
                            ('ERROR: found start marker:%s without corresponding end marker' % rev_line))
                        sys.exit(err_no_end_marker)
                    in_analysis_range = False
                    break

            if in_analysis_range:
                # Skip long logs in sairedis recording since most likely
                # they are bulk set operations for non-default routes
                # without much insight while they are time consuming to analyze
                # In advanced_reboot test, we need to analyze the bulk operations for mac learning
                # So we need to allow long lines
                if maximum_log_length is None:
                    maximum_log_length = MAX_LOG_MESSAGE_LENGTH
                if not check_marker and len(rev_line) > maximum_log_length:
                    continue

                if self.line_is_expected(rev_line, expect_messages_regex):
                    expected_lines.append(rev_line)

                elif self.line_matches(rev_line, match_messages_regex, ignore_messages_regex):
                    matching_lines.append(rev_line)

        # care about the markers only if input is not stdin or no need to check start marker
        if not stdin_as_input and check_marker:
            if (not found_start_marker):
                print('ERROR: start marker was not found')
                sys.exit(err_no_start_marker)

            if (not found_end_marker):
                print('ERROR: end marker was not found')
                sys.exit(err_no_end_marker)

        return matching_lines, expected_lines
    # ---------------------------------------------------------------------

    def analyze_file_list(self, log_file_list, match_messages_regex, ignore_messages_regex, expect_messages_regex,
                          maximum_log_length=None):
        '''
        @summary: Analyze input files messages matching input regex expressions.
            See line_matches() for details on matching criteria.

        @param log_file_list: List of paths to the log files.

        @param match_messages_regex:
            regex class instance containing messages to match against.

        @param ignore_messages_regex:
            regex class instance containing messages to ignore match against.

        @param expect_messages_regex:
            regex class instance containing messages that are expected to appear in logfile.

        @param maximum_log_length
            The maximum length of the log message. If the length of the log message is greater than this value,

        @return: Returns map <file_name, list_of_matching_strings>
        '''
        res = {}

        for log_file in log_file_list:
            if not len(log_file):
                continue
            match_strings, expect_strings = self.analyze_file(log_file, match_messages_regex, ignore_messages_regex,
                                                              expect_messages_regex,
                                                              maximum_log_length=maximum_log_length)

            match_strings.reverse()
            expect_strings.reverse()
            res[log_file] = [match_strings, expect_strings]

        return res
    # ---------------------------------------------------------------------


def usage():
    print('loganalyzer input parameters:')
    print('--help                           Print usage')
    print('--verbose                        Print verbose output during the run')
    print('--action                         init|analyze - action to perform.')
    print('                                 init - initialize analysis by placing start-marker')
    print('                                 to all log files specified in --logs parameter.')
    print('                                 analyze - perform log analysis of files specified in --logs parameter.')
    print('                                 add_end_marker - add end marker to all log files specified in --logs parameter.')           # noqa: E501
    print('--out_dir path                   Directory path where to place output files, ')
    print('                                 must be present when --action == analyze')
    print('--logs path{,path}               List of full paths to log files to be analyzed.')
    print('                                 Implicitly system log file will be also processed')
    print('--run_id string                  String passed to loganalyzer, uniquely identifying ')
    print('                                 analysis session. Used to construct start/end markers. ')
    print('--match_files_in path{,path}     List of paths to files containing strings. A string from log file')
    print('                                 By default syslog will be always analyzed and should be passed by match_files_in.')         # noqa: E501
    print('                                 matching any string from match_files_in will be collected and ')
    print('                                 reported. Must be present when action == analyze')
    print('--ignore_files_in path{,path}    List of paths to files containing string. ')
    print('                                 A string from log file matching any string from these')
    print('                                 files will be ignored during analysis. Must be present')
    print('                                 when action == analyze.')
    print('--expect_files_in path{,path}    List of path to files containing string. ')
    print('                                 All the strings from these files will be expected to present')
    print('                                 in one of specified log files during the analysis. Must be present')
    print('                                 when action == analyze.')

# ---------------------------------------------------------------------


def check_action(action, log_files_in, out_dir, match_files_in, ignore_files_in, expect_files_in):
    '''
    @summary: This function validates command line parameter 'action' and
        other related parameters.

    @return: True if input is correct
    '''

    ret_code = True

    if action in ['init', 'add_end_marker', 'add_start_ignore_mark', 'add_end_ignore_mark']:
        ret_code = True
    elif action == 'analyze':
        if out_dir is None or len(out_dir) == 0:
            print('ERROR: missing required out_dir for analyze action')
            ret_code = False

        elif match_files_in is None or len(match_files_in) == 0:
            print('ERROR: missing required match_files_in for analyze action')
            ret_code = False

    else:
        ret_code = False
        print(('ERROR: invalid action:%s specified' % action))

    return ret_code
# ---------------------------------------------------------------------


def check_run_id(run_id):
    '''
    @summary: Validate command line parameter 'run_id'

    @param run_id: Unique string identifying current run

    @return: True if input is correct
    '''

    ret_code = True

    if ((run_id is None) or (len(run_id) == 0)):
        print('ERROR: no run_id specified')
        ret_code = False

    return ret_code
# ---------------------------------------------------------------------


def write_result_file(run_id, out_dir, analysis_result_per_file, messages_regex_e, unused_regex_messages):
    '''
    @summary: Write results of analysis into a file.

    @param run_id: Uinique string identifying current run

    @param out_dir: Full path to output directory where to place the result file.

    @param analysis_result_per_file: map file_name: [list of found matching strings]

    @return: void
    '''

    match_cnt = 0
    expected_cnt = 0
    expected_lines_total = []

    with open(out_dir + "/result.loganalysis." + run_id + ".log", 'w') as out_file:
        for key, val in list(analysis_result_per_file.items()):
            matching_lines, expected_lines = val

            out_file.write(
                "\n-----------Matches found in file:'%s'-----------\n" % key)
            for s in matching_lines:
                out_file.write(s)
            out_file.write('\nMatches:%d\n' % len(matching_lines))
            match_cnt += len(matching_lines)

            out_file.write(
                "\n-------------------------------------------------\n\n")

            for i in expected_lines:
                out_file.write(i)
                expected_lines_total.append(i)
            out_file.write('\nExpected and found matches:%d\n' %
                           len(expected_lines))
            expected_cnt += len(expected_lines)

        out_file.write(
            "\n-------------------------------------------------\n\n")
        out_file.write('Total matches:%d\n' % match_cnt)
        # Find unused regex matches
        for regex in messages_regex_e:
            for line in expected_lines_total:
                if re.search(regex, line):
                    break
            else:
                unused_regex_messages.append(regex)

        out_file.write('Total expected and found matches:%d\n' % expected_cnt)
        out_file.write('Total expected but not found matches: %d\n\n' %
                       len(unused_regex_messages))
        for regex in unused_regex_messages:
            out_file.write(regex + "\n")

        out_file.write(
            "\n-------------------------------------------------\n\n")
        out_file.flush()
# ---------------------------------------------------------------------


def write_summary_file(run_id, out_dir, analysis_result_per_file, unused_regex_messages):
    '''
    @summary: This function writes results summary into a file

    @param run_id: Unique string identifying current run

    @param out_dir: Output directory full path.

    @param analysis_result_per_file: map file_name:[list of matching strings]

    @return: void
    '''

    out_file = open(out_dir + "/summary.loganalysis." + run_id + ".log", 'w')
    out_file.write("\nLOG ANALYSIS SUMMARY\n")
    total_match_cnt = 0
    total_expect_cnt = 0
    for key, val in list(analysis_result_per_file.items()):
        matching_lines, expecting_lines = val

        file_match_cnt = len(matching_lines)
        file_expect_cnt = len(expecting_lines)
        out_file.write("FILE:    %s    MATCHES    %d\n" %
                       (key, file_match_cnt))
        out_file.write("FILE:    %s    EXPECTED MATCHES    %d\n" %
                       (key, file_expect_cnt))
        out_file.flush()
        total_match_cnt += file_match_cnt
        total_expect_cnt += file_expect_cnt

    out_file.write("-----------------------------------\n")
    out_file.write("TOTAL MATCHES:                  %d\n" % total_match_cnt)
    out_file.write("TOTAL EXPECTED MATCHES:         %d\n" % total_expect_cnt)
    out_file.write("TOTAL EXPECTED MISSING MATCHES: %d\n" %
                   len(unused_regex_messages))
    out_file.write("-----------------------------------\n")
    out_file.flush()
    out_file.close()
# ---------------------------------------------------------------------


def main(argv):

    action = None
    run_id = None
    start_marker = None
    log_files_in = ""
    out_dir = None
    match_files_in = None
    ignore_files_in = None
    expect_files_in = None
    verbose = False

    try:
        opts, args = getopt.getopt(argv, "a:r:s:l:o:m:i:e:vh",
                                   ["action=", "run_id=", "start_marker=", "logs=",
                                    "out_dir=", "match_files_in=", "ignore_files_in=",
                                    "expect_files_in=", "verbose", "help"])

    except getopt.GetoptError:
        print("Invalid option specified")
        usage()
        sys.exit(err_invalid_input)

    for opt, arg in opts:
        if (opt in ("-h", "--help")):
            usage()
            sys.exit(err_invalid_input)

        if (opt in ("-a", "--action")):
            action = arg

        elif (opt in ("-r", "--run_id")):
            run_id = arg

        elif (opt in ("-s", "--start_marker")):
            start_marker = arg

        elif (opt in ("-l", "--logs")):
            log_files_in = arg

        elif (opt in ("-o", "--out_dir")):
            out_dir = arg

        elif (opt in ("-m", "--match_files_in")):
            match_files_in = arg

        elif (opt in ("-i", "--ignore_files_in")):
            ignore_files_in = arg

        elif (opt in ("-e", "--expect_files_in")):
            expect_files_in = arg

        elif (opt in ("-v", "--verbose")):
            verbose = True

    if not (check_action(action, log_files_in, out_dir, match_files_in, ignore_files_in, expect_files_in)
            and check_run_id(run_id)):
        usage()
        sys.exit(err_invalid_input)

    analyzer = AnsibleLogAnalyzer(run_id, verbose, start_marker)

    log_file_list = list([_f for _f in log_files_in.split(tokenizer) if _f])

    result = {}
    if action == "init":
        analyzer.place_marker(log_file_list, analyzer.create_start_marker(), wait_for_marker=True)
        return 0
    elif action == "analyze":
        match_file_list = match_files_in.split(tokenizer)
        ignore_file_list = ignore_files_in.split(tokenizer)
        expect_file_list = expect_files_in.split(tokenizer)

        analyzer.place_marker(
            log_file_list, analyzer.create_end_marker(), wait_for_marker=True)

        match_messages_regex, messages_regex_m = analyzer.create_msg_regex(
            match_file_list)
        ignore_messages_regex, messages_regex_i = analyzer.create_msg_regex(
            ignore_file_list)
        expect_messages_regex, messages_regex_e = analyzer.create_msg_regex(
            expect_file_list)

        # if no log file specified - add system log
        if not log_file_list:
            log_file_list.append(system_log_file)

        result = analyzer.analyze_file_list(log_file_list, match_messages_regex,
                                            ignore_messages_regex, expect_messages_regex)
        unused_regex_messages = []
        write_result_file(run_id, out_dir, result,
                          messages_regex_e, unused_regex_messages)
        write_summary_file(run_id, out_dir, result, unused_regex_messages)
    elif action == "add_end_marker":
        analyzer.place_marker(
            log_file_list, analyzer.create_end_marker(), wait_for_marker=True)
        return 0
    elif action == "add_start_ignore_mark":
        analyzer.place_marker(
            log_file_list, analyzer.create_start_ignore_marker(), wait_for_marker=True)
        return 0
    elif action == "add_end_ignore_mark":
        analyzer.place_marker(
            log_file_list, analyzer.create_end_ignore_marker(), wait_for_marker=True)
        return 0

    else:
        print(('Unknown action:%s specified' % action))
    return len(result)
# ---------------------------------------------------------------------


if __name__ == "__main__":
    main(sys.argv[1:])
