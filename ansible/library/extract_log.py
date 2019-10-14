#!/usr/bin/python

DOCUMENTATION = '''
module:  extract_log
version_added:  "1.0"
short_description: Unrotate logs and extract information starting from a row with predefined string
description: The module scans the 'directory' in search of files which filenames start with 'file_prefix'.
The found files are ungzipped and combined together in the rotation order. After that all lines after
'start_string' are copied into a file with name 'target_filename'. All input strings with 'nsible' in it
aren't considered as 'start_string' to avoid clashing with ansible output.

Options:
    - option-name: directory
      description: a name of a directory with target log files
      required: True
      Default: None

    - option-name: file_prefix
      description: a prefix of target log files
      required: True
      Default: None

    - option-name: start_string
      description: a string which last copy is used as a start tag for extracting log information
      required: True
      Default: None

    - option-name: target_filename
      description: a filename of a file where the extracted lines will be saved
      required: True
      Default: None

'''

EXAMPLES = '''
- name: Extract all syslog entries since the last reboot
  extract_log:
    directory: '/var/log'
    file_prefix: 'syslog'
    start_string: 'Initializing cgroup subsys cpuset'
    target_filename: '/tmp/syslog'

- name: Copy the exctracted syslog entries to the local machine
  fetch:
    src: '/tmp/syslog'
    dest: '/tmp/'
    flat: yes

- name: Extract all sairedis.rec entries since the last reboot
  extract_log:
    directory: '/var/log/swss'
    file_prefix: 'sairedis.rec'
    start_string: 'recording on:'
    target_filename: '/tmp/sairedis.rec'

- name: Copy the exctracted sairedis.rec entries to the local machine
  fetch:
    src: '/tmp/sairedis.rec'
    dest: '/tmp/'
    flat: yes

- name: Extract all swss.rec entries since the last reboot
  extract_log:
    directory: '/var/log/swss'
    file_prefix: 'swss.rec'
    start_string: 'recording started'
    target_filename: '/tmp/swss.rec'

- name: Copy the exctracted swss.rec entries to the local machine
  fetch:
    src: '/tmp/swss.rec'
    dest: '/tmp/'
    flat: yes
'''

import os
import gzip
import re
import sys
from datetime import datetime
from ansible.module_utils.basic import *


def extract_lines(directory, filename, target_string):
    path = os.path.join(directory, filename)
    file = None
    if 'gz' in path:
        file = gzip.GzipFile(path)
    else:
        file = open(path)
    result = None
    with file:
        # This might be a gunzip file or logrotate issue, there has
        # been '\x00's in front of the log entry timestamp which
        # messes up with the comparator.
        # Prehandle lines to remove these sub-strings
        result = [(filename, line.replace('\x00', '')) for line in file if target_string in line and 'nsible' not in line]

    return result


def extract_number(s):
    """Extracts number from string, if not number found returns 0"""
    ns = re.findall(r'\d+', s)
    if len(ns) == 0:
        return 0
    else:
        return int(ns[0])


def convert_date(s):
    dt = None
    re_result = re.findall(r'^\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}\.?\d*', s)
    # Workaround for pytest-ansible
    loc = locale.getlocale()
    locale.setlocale(locale.LC_ALL, (None, None))

    if len(re_result) > 0:
        str_date = re_result[0]
        try:
            dt = datetime.strptime(str_date, '%b %d %X.%f')
        except ValueError:
            dt = datetime.strptime(str_date, '%b %d %X')
    else:
        re_result = re.findall(r'^\d{4}-\d{2}-\d{2}\.\d{2}:\d{2}:\d{2}\.\d{6}', s)
        str_date = re_result[0]
        dt = datetime.strptime(str_date, '%Y-%m-%d.%X.%f')
    locale.setlocale(locale.LC_ALL, loc)

    return dt


def comparator(l, r):
    nl = extract_number(l[0])
    nr = extract_number(r[0])
    if nl == nr:
        dl = convert_date(l[1])
        dr = convert_date(r[1])
        if dl == dr:
            return 0
        elif dl < dr:
            return -1
        else:
            return 1
    elif nl > nr:
        return -1
    else:
        return 1


def filename_comparator(l, r):
    """Compares log filenames, assumes file with greater number is
    older, e.g syslog.2 is older than syslog.1. This is how logrotate is currently configured.
    Returns 0 if log files l and r are the same,
    1 if log file l is older then r and -1 if l is newer then r"""

    nl = extract_number(l)
    nr = extract_number(r)
    if nl == nr:
        return 0
    elif nl > nr:
        return 1
    else:
        return -1


def list_files(directory, prefixname):
    """Returns a sorted list(sort order is from newer to older)
    of files in @directory starting with @prefixname
    (Comparator used is @filename_comparator)"""

    return sorted([filename for filename in os.listdir(directory)
        if filename.startswith(prefixname)], cmp=filename_comparator)


def extract_latest_line_with_string(directory, filenames, start_string):
    """Extracts latest line with string @start_string. Assumes @filenames are sorted
    and first file in @filenames is the newest log file"""

    target_lines = []
    for filename in filenames:
        extracted_lines = extract_lines(directory, filename, start_string)
        if extracted_lines:
            # found lines are the lates since we start from the newest file
            # assignt to target_lines and break the loop
            target_lines = extracted_lines
            break

    # find the latest line from traget_lines comparing by date in line
    target = target_lines[0] if len(target_lines) > 0 else None
    for line in target_lines:
        if comparator(line, target) > 0:
            target = line

    if target is None:
        raise Exception("{} was not found in {}".format(start_string, directory))

    return target


def calculate_files_to_copy(filenames, file_with_latest_line):
    files_to_copy = filenames[:filenames.index(file_with_latest_line) + 1]
    return files_to_copy


def combine_logs_and_save(directory, filenames, start_string, target_filename):
    do_copy = False
    with open(target_filename, 'w') as fp:
        for filename in reversed(filenames):
            path = os.path.join(directory, filename)
            file = None
            if 'gz' in path:
                file = gzip.GzipFile(path)
            else:
                file = open(path)
            with file:
                for line in file:
                    if line == start_string:
                        do_copy = True
                    if do_copy:
                        fp.write(line)


def extract_log(directory, prefixname, target_string, target_filename):
    filenames = list_files(directory, prefixname)
    file_with_latest_line, latest_line = extract_latest_line_with_string(directory, filenames, target_string)
    files_to_copy = calculate_files_to_copy(filenames, file_with_latest_line)
    combine_logs_and_save(directory, files_to_copy, latest_line, target_filename)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            directory=dict(required=True, type='str'),
            file_prefix=dict(required=True, type='str'),
            start_string=dict(required=True, type='str'),
            target_filename=dict(required=True, type='str'),
        ),
        supports_check_mode=False)

    p = module.params;
    try:
        extract_log(p['directory'], p['file_prefix'], p['start_string'], p['target_filename'])
    except:
        err = str(sys.exc_info())
        module.fail_json(msg="Error: %s" % err)
    module.exit_json()


if __name__ == '__main__':
    main()
