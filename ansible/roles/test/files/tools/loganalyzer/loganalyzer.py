'''
Owner:          Hrachya Mughnetsyan <Hrachya@mellanox.com>

Created on:     11/11/2016

Description:    This file contains the log analyzer functionality in order
                to verify no failures are detected in the system logs while
                it can be that traffic/functionality works.

                Design is available in https://github.com/Azure/SONiC/wiki/LogAnalyzer

Usage:          Examples of how to use log analyzer
                sudo python loganalyzer.py  --out_dir /home/hrachya/projects/loganalyzer/log.analyzer.results --action analyze --run_id myTest114 --logs file3.log -m /home/hrachya/projects/loganalyzer/match.file.1.log,/home/hrachya/projects/loganalyzer/match.file.2.log  -i ignore.file.1.log,ignore.file.2.log -v
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import sys
import getopt
import re
import csv
import pprint
import logging
import logging.handlers
from __builtin__ import True

#---------------------------------------------------------------------
# Global variables
#---------------------------------------------------------------------
tokenizer = ','
comment_key = '#'
system_log_file = '/var/log/syslog'

#-- List of ERROR codes to be returned by LogAnalyzer
err_duplicate_start_marker = -1
err_duplicate_end_marker = -2
err_no_end_marker = -3
err_no_start_marker = -4
err_invalid_string_format = -5
err_invalid_input = -6

class LogAnalyzer:
    '''
    @summary: Overview of functionality

    This class performs analysis of the log files, searching for concerning messages.
    The definition of concerning messages is passed to analyze_file_list() method,
    as a list of regular expressions.
    Additionally there will be a list of regular expressions which we wish to ignore.
    Any line in log file which will match to the set of matching regex expressions
    AND will not match set of 'ignore' regex expressions, will be considered a
    'match' and will be reported.

    LogAnalyzer will be called initially before any test has ran, and will be
    instructed to place 'start' marker into all log files to be analyzed.
    When tests have ran, LogAnalyzer will be instructed to place end-marker
    into the log files. After this, LogAnalyzer will be invoked to perform the
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

    def init_sys_logger(self):
        logger = logging.getLogger('LogAnalyzer')
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        logger.addHandler(handler)
        return logger
    #---------------------------------------------------------------------

    def __init__(self, run_id, verbose):
        self.run_id = run_id
        self.verbose = verbose
    #---------------------------------------------------------------------

    def print_diagnostic_message(self, message):
        if (not self.verbose):
            return

        print '[LogAnalyzer][diagnostic]:%s' % message
    #---------------------------------------------------------------------

    def create_start_marker(self):
        return self.start_marker_prefix + "-" + self.run_id

    #---------------------------------------------------------------------

    def is_filename_stdin(self, file_name):
        return file_name == "-"

    #---------------------------------------------------------------------

    def create_end_marker(self):
        return self.end_marker_prefix + "-" + self.run_id
    #---------------------------------------------------------------------

    def place_marker(self, log_file_list, marker):
        '''
        @summary: Place marker into each log file specified.
        @param log_file_list : List of file paths, to be applied with marker.
        @param marker:         Marker to be placed into log files.
        '''

        for log_file in log_file_list:
            if not len(log_file) or self.is_filename_stdin(log_file):
                continue
            self.print_diagnostic_message('log file:%s, place marker %s'%(log_file, marker))
            with open(log_file, 'a') as file:
                file.write(marker)
                file.write('\n')
                file.flush()

        syslogger = self.init_sys_logger()
        syslogger.info(marker)
        syslogger.info('\n')

        return
    #---------------------------------------------------------------------

    def error_to_regx(self, error_string):
        '''
        This method converts a (list of) strings to one regular expression.

        @summary: Meta characters are escaped by inserting a '\' beforehand
                  Digits are replaced with the arbitrary '\d+' code
                  A list is converted into an alteration statement (|)

        @param error_string:  the string(s) to be converted into a regular expression

        @return: A SINGLE regular expression string
        '''

        #-- Check if error_string is a string or a list --#
        if (isinstance(error_string, basestring)):
            original_string = error_string
            #-- Escapes out of all the meta characters --#
            error_string = re.escape(error_string)
            #-- Replaces a white space with the white space regular expression
            error_string = re.sub(r"(\\\s+)+", "\\\\s+", error_string)
            #-- Replaces a digit number with the digit regular expression
            error_string = re.sub(r"\b\d+\b", "\\\\d+", error_string)
            #-- Replaces a hex number with the hex regular expression
            error_string = re.sub(r"0x[0-9a-fA-F]+", "0x[0-9a-fA-F]+", error_string)
            self.print_diagnostic_message('Built error string: %s' % error_string)

        #-- If given a list, concatenate into one regx --#
        else:
            error_string = '|'.join(map(self.error_to_regx, error_string))

        return error_string
    #---------------------------------------------------------------------

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
            self.print_diagnostic_message('processing match file:%s' % filename)
            with open(filename, 'rb') as csvfile:
                csvreader = csv.reader(csvfile, quotechar='"', delimiter=',',
                                       skipinitialspace=True)

                for index, row in enumerate(csvreader):
                    self.print_diagnostic_message('[diagnostic]:processing row:%d' % index)
                    self.print_diagnostic_message('row:%s'% row)
                    try:
                        #-- Ignore commented Lines and Empty Lines
                        if (not row or row[0].startswith(comment_key)):
                            self.print_diagnostic_message('[diagnostic]:skipping row[0]:%s' % row[0])
                            continue

                        #-- ('s' | 'r') = (Raw String | Regular Expression)
                        is_regex = row[0]
                        if ('s' == row[0]):
                            is_regex = False
                        elif ('r' == row[0]):
                            is_regex = True
                        else:
                            raise Exception('file:%s, malformed line:%d. '
                                            'must be \'s\'(string) or \'r\'(regex)'
                                            %(filename,index))

                        #-- One error message per line
                        error_string = row[1]

                        if (is_regex):
                            messages_regex.append(error_string)
                        else:
                            messages_regex.append(self.error_to_regx(error_string))

                    except Exception as e:
                        print 'ERROR: line %d is formatted incorrectly in file %s. Skipping line' % (index, filename)
                        print repr(e)
                        sys.exit(err_invalid_string_format)

        if (len(messages_regex)):
            regex = re.compile('|'.join(messages_regex))
        else:
            regex = None
        return regex, messages_regex
    #---------------------------------------------------------------------

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
    #---------------------------------------------------------------------

    def line_is_expected(self, str, expect_messages_regex):
        '''
        @summary: This method checks whether given string matches against the
                  set of "expected" regular expressions.
        '''

        ret_code = False
        if (expect_messages_regex is not None) and (expect_messages_regex.findall(str)):
            ret_code = True

        return ret_code

    def analyze_file(self, log_file_path, match_messages_regex, ignore_messages_regex, expect_messages_regex):
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

        @return: List of strings match search criteria.
        '''


        self.print_diagnostic_message('analyzing file: %s'% log_file_path)

        #-- indicates whether log analyzer currently is in the log range between start
        #-- and end marker. see analyze_file method.
        in_analysis_range = False
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

        for rev_line in reversed(log_file.readlines()):

            if stdin_as_input:
                in_analysis_range = True
            else:
                if rev_line.find(end_marker) != -1:
                    self.print_diagnostic_message('found end marker: %s' % end_marker)
                    if (found_end_marker):
                        print 'ERROR: duplicate end marker found'
                        sys.exit(err_duplicate_end_marker)
                    found_end_marker = True
                    in_analysis_range = True
                    continue

            if not stdin_as_input:
                if rev_line.find(start_marker) != -1:
                    self.print_diagnostic_message('found start marker: %s' % start_marker)
                    if (found_start_marker):
                        print 'ERROR: duplicate start marker found'
                        sys.exit(err_duplicate_start_marker)
                    found_start_marker = True

                    if(not in_analysis_range):
                        print 'ERROR: found start marker:%s without corresponding end marker' % rev_line
                        sys.exit(err_no_end_marker)
                    in_analysis_range = False
                    break

            if in_analysis_range :
                if self.line_is_expected(rev_line, expect_messages_regex):
                    expected_lines.append(rev_line)

                elif self.line_matches(rev_line, match_messages_regex, ignore_messages_regex):
                    matching_lines.append(rev_line)

        # care about the markers only if input is not stdin
        if not stdin_as_input:
            if (not found_start_marker):
                print 'ERROR: start marker was not found'
                sys.exit(err_no_start_marker)

            if (not found_end_marker):
                print 'ERROR: end marker was not found'
                sys.exit(err_no_end_marker)

        return matching_lines, expected_lines
    #---------------------------------------------------------------------

    def analyze_file_list(self, log_file_list, match_messages_regex, ignore_messages_regex, expect_messages_regex):
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

        @return: Returns map <file_name, list_of_matching_strings>
        '''
        res = {}

        for log_file in log_file_list:
            if not len(log_file):
                continue
            match_strings, expect_strings = self.analyze_file(log_file, match_messages_regex, ignore_messages_regex, expect_messages_regex)

            match_strings.reverse()
            expect_strings.reverse()
            res[log_file] = [ match_strings, expect_strings ]

        return res
    #---------------------------------------------------------------------

def usage():
    print 'loganalyzer input parameters:'
    print '--help                           Print usage'
    print '--verbose                        Print verbose output during the run'
    print '--action                         init|analyze - action to perform.'
    print '                                 init - initialize analysis by placing start-marker'
    print '                                 to all log files specified in --logs parameter.'
    print '                                 analyze - perform log analysis of files specified in --logs parameter.'
    print '--out_dir path                   Directory path where to place output files, '
    print '                                 must be present when --action == analyze'
    print '--logs path{,path}               List of full paths to log files to be analyzed.'
    print '                                 Implicetly system log file will be also processed'
    print '--run_id string                  String passed to loganalyzer, uniquely identifying '
    print '                                 analysis session. Used to construct start/end markers. '
    print '--match_files_in path{,path}     List of paths to files containing strings. A string from log file'
    print '                                 By default syslog will be always analyzed and should be passed by match_files_in.'
    print '                                 matching any string from match_files_in will be collected and '
    print '                                 reported. Must be present when action == analyze'
    print '--ignore_files_in path{,path}    List of paths to files containing string. '
    print '                                 A string from log file matching any string from these'
    print '                                 files will be ignored during analysis. Must be present'
    print '                                 when action == analyze.'
    print '--expect_files_in path{,path}    List of path to files containing string. '
    print '                                 All the strings from these files will be expected to present'
    print '                                 in one of specified log files during the analysis. Must be present'
    print '                                 when action == analyze.'

#---------------------------------------------------------------------

def check_action(action, log_files_in, out_dir, match_files_in, ignore_files_in, expect_files_in):
    '''
    @summary: This function validates command line parameter 'action' and
        other related parameters.

    @return: True if input is correct
    '''

    ret_code = True

    if (action == 'init'):
        ret_code = True

    elif (action == 'analyze'):
        if out_dir is None or len(out_dir) == 0:
            print 'ERROR: missing required out_dir for analyze action'
            ret_code = False

        elif match_files_in is None or len(match_files_in) == 0:
            print 'ERROR: missing required match_files_in for analyze action'
            ret_code = False


    else:
        ret_code = False
        print 'ERROR: invalid action:%s specified' % action

    return ret_code
#---------------------------------------------------------------------

def check_run_id(run_id):
    '''
    @summary: Validate command line parameter 'run_id'

    @param run_id: Unique string identifying current run

    @return: True if input is correct
    '''

    ret_code = True

    if ((run_id is None) or (len(run_id) == 0)):
        print 'ERROR: no run_id specified'
        ret_code = False

    return ret_code
#---------------------------------------------------------------------

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
        for key, val in analysis_result_per_file.iteritems():
            matching_lines, expected_lines = val

            out_file.write("\n-----------Matches found in file:'%s'-----------\n" % key)
            for s in matching_lines:
                out_file.write(s)
            out_file.write('\nMatches:%d\n' % len(matching_lines))
            match_cnt += len(matching_lines)

            out_file.write("\n-------------------------------------------------\n\n")

            for i in expected_lines:
                out_file.write(i)
                expected_lines_total.append(i)
            out_file.write('\nExpected and found matches:%d\n' % len(expected_lines))
            expected_cnt += len(expected_lines)

        out_file.write("\n-------------------------------------------------\n\n")
        out_file.write('Total matches:%d\n' % match_cnt)
        # Find unused regex matches
        for regex in messages_regex_e:
            regex_used = False
            for line in expected_lines_total:
                if re.search(regex, line):
                    regex_used = True
                    break
            if not regex_used:
                unused_regex_messages.append(regex)

        out_file.write('Total expected and found matches:%d\n' % expected_cnt)
        out_file.write('Total expected but not found matches: %d\n\n' % len(unused_regex_messages))
        for regex in unused_regex_messages:
            out_file.write(regex + "\n")

        out_file.write("\n-------------------------------------------------\n\n")
        out_file.flush()

#---------------------------------------------------------------------

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
    for key, val in analysis_result_per_file.iteritems():
        matching_lines, expecting_lines = val

        file_match_cnt = len(matching_lines)
        file_expect_cnt = len(expecting_lines)
        out_file.write("FILE:    %s    MATCHES    %d\n" % (key, file_match_cnt))
        out_file.write("FILE:    %s    EXPECTED MATCHES    %d\n" % (key, file_expect_cnt))
        out_file.flush()
        total_match_cnt += file_match_cnt
        total_expect_cnt += file_expect_cnt

    out_file.write("-----------------------------------\n")
    out_file.write("TOTAL MATCHES:                  %d\n" % total_match_cnt)
    out_file.write("TOTAL EXPECTED MATCHES:         %d\n" % total_expect_cnt)
    out_file.write("TOTAL EXPECTED MISSING MATCHES: %d\n" % len(unused_regex_messages))
    out_file.write("-----------------------------------\n")
    out_file.flush()
    out_file.close()
#---------------------------------------------------------------------

def main(argv):

    action = None
    run_id = None
    log_files_in = ""
    out_dir = None
    match_files_in = None
    ignore_files_in = None
    expect_files_in = None
    verbose = False

    try:
        opts, args = getopt.getopt(argv, "a:r:l:o:m:i:e:vh", ["action=", "run_id=", "logs=", "out_dir=", "match_files_in=", "ignore_files_in=", "expect_files_in=", "verbose", "help"])

    except getopt.GetoptError:
        print "Invalid option specified"
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

    if not (check_action(action, log_files_in, out_dir, match_files_in, ignore_files_in, expect_files_in) and check_run_id(run_id)):
        usage()
        sys.exit(err_invalid_input)

    analyzer = LogAnalyzer(run_id, verbose)

    log_file_list = filter(None, log_files_in.split(tokenizer))

    result = {}
    if (action == "init"):
        analyzer.place_marker(log_file_list, analyzer.create_start_marker())
        return 0
    elif (action == "analyze"):
        match_file_list = match_files_in.split(tokenizer);
        ignore_file_list = ignore_files_in.split(tokenizer);
        expect_file_list = expect_files_in.split(tokenizer);

        analyzer.place_marker(log_file_list, analyzer.create_end_marker())

        match_messages_regex, messages_regex_m = analyzer.create_msg_regex(match_file_list)
        ignore_messages_regex, messages_regex_i = analyzer.create_msg_regex(ignore_file_list)
        expect_messages_regex, messages_regex_e = analyzer.create_msg_regex(expect_file_list)

        # if no log file specified - add system log
        if not log_file_list:
            log_file_list.append(system_log_file)

        result = analyzer.analyze_file_list(log_file_list, match_messages_regex,
                                            ignore_messages_regex, expect_messages_regex)
        unused_regex_messages = []
        write_result_file(run_id, out_dir, result, messages_regex_e, unused_regex_messages)
        write_summary_file(run_id, out_dir, result, unused_regex_messages)

    else:
        print 'Unknown action:%s specified' % action
    return len(result)
#---------------------------------------------------------------------

if __name__ == "__main__":
    main(sys.argv[1:])
