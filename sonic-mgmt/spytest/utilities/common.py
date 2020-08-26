import os
import re
import sys
import csv
import time
import base64
import random
import socket
import string
import struct
import hashlib
import textwrap
import datetime
import subprocess
from inspect import currentframe
from collections import OrderedDict

import yaml

from tabulate import tabulate
from prettytable import PrettyTable
from jinja2 import Environment

from . import json_helpers as json

def find_file(filename, paths=[]):
    if os.path.isfile(filename):
        return filename
    for path in paths:
        if os.path.isfile(path):
            path = os.path.dirname(path)
        filename1 = os.path.join(path, filename)
        if os.path.isfile(filename1):
            return filename1
    return None

def ensure_parent(filename):
    path = os.path.dirname(filename)
    path = os.path.abspath(path)
    if not os.path.exists(path):
        os.makedirs(path)

def open_file(filename, mode="r"):

    if mode == "w":
        ensure_parent(filename)

    if sys.version_info.major < 3:
        return open(filename, mode+"b")

    return open(filename, mode, newline='')

def delete_file(filename):
    if os.path.exists(filename):
        os.remove(filename)
        return True
    return False

def write_file(filename, data, mode="w"):
    if filename:
        ensure_parent(filename)
        fh = open(filename, mode)
        fh.write(data)
        fh.close()
    return data

def make_list(arg):
    """
    todo: Update Documentation
    :param arg:
    :type arg:
    :return:
    :rtype:
    """
    if arg is None:
        return []
    if isinstance(arg, list):
        return arg
    return [arg]

def filter_and_select(output, select=None, match=None):
    """

    This method applies the given match in the output and
    returns columns as per given select

    :param output: output to which match has to be applied
    :param select: select expression
    :param match: match expression
    :return: columns as per the select
    """
    def match_entry(ent, match):
        if isinstance(match, list):
            # list of matches - select if any one is matched
            for m in match:
                if not m or match_entry(ent, m):
                    return True
            return False
        elif not isinstance(match, dict):
            print("expecting the match to be a dict")
        # select if all conditions match
        for key, value in match.items():
            if key not in ent or str(ent[key]) != str(value):
                return False
        return True

    def select_entry(ent, select):
        newd = dict()
        for col in select:
            if col not in ent:
                return None
            newd[col] = ent[col]
        return newd

    # collect the matched/all entries
    retval = []
    for ent in output:
        if not match or match_entry(ent, match):
            retval.append(ent)

    # return all columns if select is not specified
    if not select:
        return retval

    # return only columns specified in select
    retval2 = []
    for ent in retval:
        tmp = select_entry(ent, select)
        if tmp:
            retval2.append(tmp)
    return retval2


def compare_data(data1, data2, ignore=None, expected=True):
    """
    todo: Update Documentation
    :param data1:
    :type data1:
    :param data2:
    :type data2:
    :param ignore:
    :type ignore:
    :param expected:
    :type expected:
    :return:
    :rtype:
    """
    print(data1)
    print(data2)
    return expected


def sprint_data(d, msg=""):
    rv = "========================{}===========================\n".format(msg)
    rv = rv + "{}".format(d)
    rv = rv + "\n=====================================================\n"
    return rv

def print_data(d, msg=""):
    print (sprint_data(d, msg))

def sprint_yaml(d, msg="", default_flow_style=False):
    rv = "========================{}===========================\n".format(msg)
    rv = rv + yaml.dump(d, default_flow_style=default_flow_style)
    rv = rv + "\n=====================================================\n"
    return rv

def print_yaml(d, msg="", default_flow_style=False):
    print (sprint_yaml(d, msg, default_flow_style))

def random_string(slen=10):
    include_list = string.ascii_letters + string.digits
    return ''.join(random.choice(include_list) for i in range(slen))

def random_username(slen=10):
    include_list = string.ascii_lowercase + string.digits + '_-'
    first_char = random.choice(string.ascii_lowercase+'_')
    return first_char+''.join(random.choice(include_list) for _ in range(slen-1))

def random_password(slen=10):
    include_list = string.ascii_letters + string.digits + '!@#$%^&*()'
    return ''.join(random.choice(include_list) for _ in range(slen))

def random_vlan_list(count=1, exclude=[]):
    """
    todo: Update Documentation
    :param count:
    :type count:
    :param exclude:
    :type exclude:
    :return:
    :rtype:
    """
    retval = []
    while count > 0:
        val = random.randint(2, 4094)
        if exclude and val in exclude:
            pass
        elif val not in retval:
            retval.append(val)
            count = count - 1
    return retval

def get_proc_name():
    """
    todo: Update Documentation
    :return:
    :rtype:
    """
    return sys._getframe(1).f_code.co_name

def get_line_number():
    cf = currentframe()
    return cf.f_back.f_lineno

def trace(fmt, *args):
    sys.stdout.write(fmt % args)

def trim_dict(d, match=["", None, {}]):
    new_dict = {}
    if not isinstance(d, dict):
        return new_dict
    for k, v in d.items():
        if isinstance(v, dict):
            v = trim_dict(v, match)
        if v not in match:
            new_dict[k] = v
    return new_dict

def is_unicode(arg):
    if sys.version_info[0] >= 3:
        return bool(isinstance(arg, str))
    return bool(isinstance(arg, unicode))

def ipcheck(addr):
    try:
        subprocess.check_output(["ping", "-c", "1", "-w", "2", str(addr)])
        return True
    except subprocess.CalledProcessError:
        return False

def sprintf(fmt, *args):
    return fmt % args

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def b64encode(file_path):
    fh = open_file(file_path)
    text = fh.read()
    encoded_data = base64.b64encode(text)
    retval = []
    for i in xrange((len(encoded_data) / 76) + 1):
        retval.append(encoded_data[i * 76:(i + 1) * 76])
    return retval

######################## to be removed after refactoring ####################
######################## to be removed after refactoring ####################
class ExecAllFunc(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

def exec_foreach (use_threads, items, func, *args, **kwargs):
    from . import parallel
    return parallel.exec_foreach (use_threads, items, func, *args, **kwargs)

def exec_all(use_threads, entries, first_on_main=False):
    from . import parallel
    return parallel.exec_all(use_threads, entries, first_on_main)
######################## to be removed after refactoring ####################
######################## to be removed after refactoring ####################

def sprint_vtable(header, rows, max_width=0):
    t = PrettyTable(header)
    #t.align = "l"
    if max_width:
        t.max_width = max_width
    t.hrules = True
    for row in rows:
        t.add_row(row)
    return str(t)

def sprint_htable(header, row):
    t = PrettyTable(["Name", "value"])
    t.hrules = True
    for index in range(0, len(row)):
        t.add_row([header[index], row[index]])
    return str(t)

def date_parse(datestr):
    try:
        return datetime.datetime.strptime(datestr, '%Y-%m-%d %H:%M:%S')
    except:
        pass
    try:
        return datetime.datetime.strptime(datestr, '%Y-%m-%d %H:%M:%S.%f')
    except:
        pass
    return None

def time_parse(timestr):
    try:
        (h,m,s) = timestr.split(':')
        secs = int(h) * 3600 + int(m) * 60 + int(s)
    except:
        secs = 0
    return secs

def time_format(seconds):
    hour = seconds // 3600
    seconds = seconds % 3600
    minutes = seconds // 60
    seconds = seconds % 60
    return "%d:%02d:%02d" % (hour, minutes, seconds)

def time_diff(start, end, fmt=False, add=0):
    if not start or not end:
        seconds = 0
    else:
        time_taken = end - start
        seconds = time_taken.total_seconds()
        if time_taken.microseconds >= 500:
            seconds = seconds + 1
    seconds = seconds + add
    if not fmt:
        return int(seconds)
    return time_format(seconds)

def dict_reduce(first, second):
  return {k: v for k, v in first.items() if k not in second}

def get_digits(arg, sortit=False):
    """
    Get all the digits in the given list or string
    :param arg:
    :type arg: string/list
    :param sortit: sort the output or not
    :type sortit: boolean
    :return: list of integers
    :rtype: list
    """
    retval = []
    for ent in make_list(arg):
        dlist = re.findall(r'\d+', str(ent))
        retval.extend([int(x) for x in dlist if x not in retval])
    if sortit:
      retval.sort()
    return retval

def iprange(start, count, incr=1, exclude=[]):
    start_addr = struct.unpack("!I", socket.inet_aton(start))[0]
    retval = []
    while len(retval) < count:
        while True:
            addr = socket.inet_ntoa(struct.pack('>I', start_addr))
            start_addr = start_addr + incr
            if addr not in exclude:
                retval.append(addr)
                break
    return retval

def string_list(text):
    str_list = []
    for arg in make_list(text):
        arg = str(arg) if arg else ""
        arg = arg.strip()
        for ent in arg.split("\n"):
            ent = ent.strip()
            if ent:
                str_list.append(ent)
    return str_list

def split_byall(text, tostr=False, sep=",;"):
    text = str(text) if text else ""
    text = text.strip()
    text = text.replace("\n", " ")
    if sep:
        for ch in list(sep):
            text = text.replace(ch, " ")
    retval = []
    for ent in text.split():
        if tostr:
            retval.append(str(ent))
        else:
            retval.append(ent)
    return retval

def read_lines(filepath):
    fh = open(filepath, 'r')
    data = fh.readlines()
    fh.close()
    data = map(str.strip, data)
    return data

def find_duplicate(items, unique=[]):
    retval = []
    for item in items:
        if item not in unique:
            unique.append(item)
        else:
            retval.append(item)
    return retval

def write_csv_writer(cols, rows, writer, append=False):
    if not append:
        writer.writeheader()

    for i in range(0, len(rows)):
        d = OrderedDict()
        for j in range(0, len(cols)):
            d[cols[j]] = rows[i][j]
        writer.writerow(d)

def write_csv_file(cols, rows, filepath, append=False):
    if sys.version_info.major < 3:
        mode = "ab" if append else "wb"
        fd = open(filepath, mode)
    else:
        mode = "a" if append else "w"
        fd = open(filepath, mode, newline='')
    writer = csv.DictWriter(fd, fieldnames=cols, dialect="excel")
    write_csv_writer(cols, rows, writer, append)
    fd.flush()
    fd.close()

def write_html_table(cols, rows, filepath=None):
    html = """{table}"""
    tbl=tabulate(rows, headers=cols, tablefmt="html")
    html = html.format(table=tbl)
    html = html.replace("<table>", "<table border='1'>")

    return write_file(filepath, html)

def write_html_table2(cols, rows, filepath=None, links=None):
    template = textwrap.dedent("""\
    <table border='1'>
    <thead>
      {%- for col in cols %}
      <th>{{col}}</th>
      {%- endfor %}
    </thead>
    <tbody>
      {%- for row in rows %}
      <tr>
        {%- for cell in row %}
        <td>{{cell}}</td>
        {%- endfor %}
      </tr>
      {%- endfor %}
    </tbody>
    </table>
    """)

    if links:
        l_rows = []
        for index in range(0, len(rows)):
            l_row = list(rows[index])
            if links[index]:
                l_row[0]="<a href='{}'>{}</a>".format(links[index],l_row[0])
            l_rows.append(l_row)
    else:
        l_rows = rows
    html = Environment().from_string(template).render(cols=cols, rows=l_rows)
    return write_file(filepath, html)

# entries should be output of traceback.format_exc()
def stack_trace(entries):
    if isinstance(entries, str):
        return [entries]

    retval = []
    index = 0
    try:
        for item in reversed(entries):
            fname, line, func, text = item
            msg = "[{}] {}:{} {} {}".format(index, fname, line, func, text)
            index = index + 1
            retval.append(msg)
    except:
        retval.append("Failed to parse stack trace {}".format(str(entries)))

    return retval

def poll_wait(method, timeout, *args, **kwargs):
    t = time.time() + timeout
    while True:
      time.sleep(1)
      if time.time() > t:
        break
      elif method(*args, **kwargs):
        return True
    return False

def time_span_to_sec(time_span):
    try:
        return sum(x * int(t) for x, t in zip([3600, 60, 1], time_span.split(":")))
    except:
        return 0

def to_string(data):
    if sys.version_info.major < 3:
        return str(data)
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return data

def split_lines_trim(text):
    text = str(text) if text else ""
    text = text.replace("\n", " ")
    retval = []
    for ent in text.split():
        retval.append(to_string(ent))
    return retval

def dicts_list_values(dict_list, name):
    retval = []
    for d in dict_list:
        if name in d:
            retval.append(d[name])
    return  retval

def invert_dict(d):
    retval = {}
    for key in d:
        retval.setdefault(d[key], []).append(key)
    return retval

def split_list(data, size):
    if size == 0:
        size = len(data)
    return [data[x:x+size] for x in range(0, len(data), size)]

def filter_list(full_list, excludes):
    s = set(excludes)
    return list(x for x in full_list if x not in s)

def banner(msg, width=80, delimiter="#", wrap=True, func=None, tnl=True, lnl=True):
    msg_list = [""] if lnl else []
    msg_list.append(delimiter*width)
    if msg != None:
        if wrap: output = ["{0} {1} {0}".format(delimiter,each.center(width-4))
                            for each in textwrap.wrap(msg, width=width-4)]
        else: output = ["{0} {1:{2}} {0}".format(delimiter,each,(width-4))
                            for each in textwrap.wrap(msg, width=width-4)]
        msg_list.extend(['\n'.join(output), delimiter*width])
    if tnl: msg_list.append("")
    for each_line in msg_list:
        if func: func(each_line)
        else: print(each_line)

def split_with_quoted_strings(s):
    def strip_quotes(s):
        if s and (s[0] == '"' or s[0] == "'") and s[0] == s[-1]:
            return s[1:-1]
        return s
    return [strip_quotes(p).replace('\\"', '"').replace("\\'", "'")
            for p in re.findall(r'"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\'|[^\s]+', s)]

def is_valid_ipv4(s):
    regex = r"""
        ^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.
        (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.
        (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.
        (25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)
        """
    regex = "".join(regex.split())
    return bool(re.search(regex, s))

def integer_parse(s, default=None):
    #return re.match(r"[-+]?\d+$", s) is not None
    try:
        return int(s)
    except:
        return default

def min(n1, n2):
    return n1 if n1 < n2 else n2

def max(n1, n2):
    return n1 if n1 > n2 else n2

def j2_apply(text, **kwargs):
    return Environment().from_string(text).render(**kwargs)

def json_parse(text=None, file=None, paths=[], **kwargs):
    root = None
    if text:
        text = Environment().from_string(text).render(**kwargs)
    elif file:
        if "::" in file: [file, root] = file.split("::", 2)
        file = find_file(file, paths)
        text = "\n".join(read_lines(file))
        text = Environment().from_string(text).render(**kwargs)
    else:
        raise Exception("Neither text nor file argument provided")
    data = json.fix(text, "Invalid json text/file supplied", True)
    if not root: return data
    if root in data: return data[root]
    return None

def convert_to_bits(count_dict):
    """
    This method will take nested dictionary(inner dictionaries values are strings) as input and return nested
    dictionaries(inner dictionaries values as float values) and convert Kilo Bits, Mega Bits, Giga Bits to  Bits
    :param count_dict:
    :return:
    """
    for port, counters in count_dict.items():
        for property, value in counters.items():
            if 'K' in value:
                multiple = 10**3
            elif 'M' in value:
                multiple = 10**6
            elif 'G' in value:
                multiple = 10**9
            else:
                multiple = 1
            count_dict[port][property] = float(re.findall(r"\d+[.]?[\d+]?", value.replace(',',''))[0])*multiple
    return count_dict

def get_current_datetime():
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to get current date time
    :return:
    """
    now = datetime.datetime.now()
    return now.strftime("%m%d%Y%H%M%S")


def write_to_json_file(content, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to write the json file
    :param content:
    :param file_path:
    :return:
    """
    import json
    json_dump = json.dumps(content)
    parsed = json.loads(json_dump)
    json_content = json.dumps(parsed, indent=4, sort_keys=True)
    src_fp = open(file_path, "w")
    src_fp.write(json_content)
    src_fp.close()
    return file_path

def remove_last_line_from_string(data):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to remove the last line of the string
    :param data:
    :return:
    """
    return data[:data.rfind('\n')]


if __name__ == "__main__":
    # indent the json file
    text = "\n".join(read_lines(sys.argv[1]))
    data = json.fix(text, load=True)
    print(json.dumps(data))

