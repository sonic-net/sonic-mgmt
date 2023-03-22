import os
import re
import sys
import csv
import glob
import base64
import random
import socket
import string
import struct
import shutil
import hashlib
import textwrap
import datetime
import fnmatch
import subprocess
import inspect
from collections import OrderedDict

import yaml

from tabulate import tabulate
from prettytable import PrettyTable
from jinja2 import Environment

from . import json_helpers as jsonutil

if sys.version_info[0] >= 3:
    unicode = str
    basestring = str

def to_ascii(msg):
    msg = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', ' ', msg)
    msg = re.sub(r'[^\x00-\x7F]+', ' ', msg)
    try:
        return msg.encode('ascii', 'ignore').decode('ascii')
    except Exception as exp:
        print(str(exp))
    return "non-ascii characters"

def list_files_tree(dir_path, pattern="*"):
    matches = []
    for root, _, filenames in os.walk(dir_path):
        for filename in fnmatch.filter(filenames, pattern):
            matches.append(os.path.join(root, filename))
    return matches

def list_files(entry, pattern="*"):
    if os.path.isdir(entry):
        return list_files_tree(entry, pattern)
    if os.path.isfile(entry):
        return [entry]
    return glob.glob(entry)

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

def ensure_folder(path):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        os.makedirs(path)

def ensure_parent(filename):
    path = os.path.dirname(filename)
    ensure_folder(path)

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

def copytree(src, dst, symlinks=False, ignore=None):
    ensure_folder(dst)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)

def write_file(filename, data, mode="w"):
    if not filename: return data
    ensure_parent(filename)
    try:    data2 = to_ascii(data)
    except Exception: data2 = data
    fh = open(filename, mode)
    fh.write(data2)
    fh.close()
    return data2

def make_list(*args):
    retval = []
    for arg in args:
        if arg is None:
            retval.append(arg)
        elif isinstance(arg, list):
            retval.extend(arg)
        else:
            retval.append(arg)
    return retval

# same as make_list but excludes None
def make_list2(*args):
    retval = []
    for arg in args:
        if arg is None:
            pass
        elif isinstance(arg, list):
            for a in arg:
                if a is not None:
                    retval.append(a)
            retval.extend(arg)
        else:
            retval.append(arg)
    return retval

def iterable(obj):
    if obj is None or isinstance(obj, bool):
        return []
    return obj

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
    for ent in iterable(output):
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

def sprint_obj(obj, msg=""):
    rv = "========================{}===========================\n".format(msg)
    for attr in dir(obj):
        if hasattr( obj, attr ):
            rv = rv + "obj.%s = %s\n" % (attr, getattr(obj, attr))
    rv = rv + "\n=====================================================\n"
    return rv

def sprint_data(d, msg=""):
    rv = "========================{}===========================\n".format(msg)
    rv = rv + "{}".format(d)
    rv = rv + "\n=====================================================\n"
    return rv

def print_data(d, msg=""):
    print(sprint_data(d, msg))

def sprint_yaml(d, msg="", default_flow_style=False):
    rv = "========================{}===========================\n".format(msg)
    rv = rv + yaml.dump(d, default_flow_style=default_flow_style)
    rv = rv + "\n=====================================================\n"
    return rv

def print_yaml(d, msg="", default_flow_style=False):
    print(sprint_yaml(d, msg, default_flow_style))

def random_integer(min=0, max=10):
    return random.randint(min, max)

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
    return sys._getframe(1).f_code.co_name

def get_line_number(lvl=0):
    cf = inspect.currentframe()
    for _ in range(lvl):
        if cf.f_back:
            cf = cf.f_back
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

def copy_items(src, dst, include=None, exclude=None):
    if include is not None:
        for k, v in src.items():
            if k in include:
                dst[k] = v
    elif exclude is not None:
        for k, v in src.items():
            if k not in exclude:
                dst[k] = v

def is_unicode(arg):
    return bool(isinstance(arg, unicode))

def is_basestring(arg):
    return bool(isinstance(arg, basestring))

def do_eval(arg):
    return eval(arg)

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

def str_encode(s):
    if sys.version_info[0] >= 3:
        rv = str.encode(s)
        return rv
    return s

def str_decode(s):
    if sys.version_info[0] >= 3:
        rv = s.decode() if s else s
        return rv
    return s

def b64encode(file_path):
    fh = open_file(file_path)
    text = str_encode(fh.read())
    encoded_data = base64.b64encode(text)
    encoded_data = str_decode(encoded_data)
    retval = []
    for i in range(int((len(encoded_data)/76)) + 1):
        retval.append(encoded_data[i*76:(i+1)*76])
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

def sprint_htable(header, rows):
    t = PrettyTable(["Name", "value"])
    t.hrules = True
    for index, row in enumerate(rows):
        t.add_row([header[index], row])
    return str(t)

def date_parse(datestr):
    try:
        return datetime.datetime.strptime(datestr, '%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    try:
        return datetime.datetime.strptime(datestr, '%Y-%m-%d %H:%M:%S.%f')
    except Exception:
        pass
    return None

def time_parse(timestr):
    try:
        (h,m,s) = timestr.split(':')
        secs = int(h) * 3600 + int(m) * 60 + int(s)
    except Exception:
        secs = 0
    return secs

def time_format(value, msec=False):
    if msec: milli, value = value % 1000, value // 1000
    minutes, seconds = divmod(value, 60)
    hour, minutes = divmod(minutes, 60)
    retval = "%d:%02d:%02d" % (hour, minutes, seconds)
    if msec: retval = "%s.%03d" % (retval, milli)
    return retval

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

def read_lines(filepath, strip=True):
    fh = open(filepath, 'r')
    data = fh.readlines()
    fh.close()
    if strip:
        data = map(str.strip, data)
    else:
        data = map(str, data)
    return data

def find_duplicate(items):
    retval, unique = [], []
    for item in items:
        if item not in unique:
            unique.append(item)
        else:
            retval.append(item)
    return retval, unique

def read_csv(filepath):
    rows = []
    try:
        with open_file(filepath) as fd:
            for row in csv.reader(fd):
                rows.append(row)
    except Exception:
        pass

    return rows

def write_csv_writer(cols, rows, writer, append=False):
    if not append:
        writer.writeheader()

    for row in rows:
        d = OrderedDict()
        for j, col in enumerate(cols):
            d[col] = row[j]
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

def write_html_table2(cols, rows, filepath=None, links=None, colors=None, color_col=None):
    template = textwrap.dedent("""\
    <table border='1'>
    <thead>
      {%- for col in cols %}
      <th>{{col}}</th>
      {%- endfor %}
    </thead>
    <tbody>
      {%- for row in rows %}
      <tr {{row_css[loop.index0]}}>
        {% set outer_loop = loop %}
        {%- for cell in row %}
        <td {{cell_css[outer_loop.index0][loop.index0]}}>{{cell}}</td>
        {%- endfor %}
      </tr>
      {%- endfor %}
    </tbody>
    </table>
    """)

    if links:
        l_rows = []
        for index, row in enumerate(rows):
            l_row = list(row)
            if links[index]:
                l_row[0]="<a href='{}'>{}</a>".format(links[index],l_row[0])
            l_rows.append(l_row)
    else:
        l_rows = rows

    row_css = ["" for _ in l_rows]
    cell_css = [["" for _ in cols] for _ in l_rows]
    for col_index, col in enumerate(cols):
        for row_index, l_row in enumerate(l_rows):
            if not colors: continue
            color = 'style="background-color:{}"'.format(colors[row_index])
            if color_col is None:
                row_css[row_index] = color
            elif col == color_col:
                cell_css[row_index][col_index] = color

    html = j2_apply(template, cols=cols, rows=l_rows, row_css=row_css, cell_css=cell_css)
    return write_file(filepath, html)

# links, colors and align are dictionaries or None
# where key is column name or None and value is list of links/colors/align
# None key is used for entire row
# text-align None=center, True=Left, False=Right
def write_html_table3(cols, rows, filepath=None, links=None, colors=None, align=None, total=True):
    js_tmpl = textwrap.dedent("""\
    <head>
      <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
      <meta http-equiv="Pragma" content="no-cache" />
      <meta http-equiv="Expires" content="0" />
      <link href="https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css" rel="stylesheet" />
      <link href="https://cdn.datatables.net/buttons/1.6.2/css/buttons.dataTables.min.css" rel="stylesheet" />
      <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
      <script src="https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
      <script src="https://cdn.datatables.net/buttons/1.6.2/js/dataTables.buttons.min.js"></script>
      <script src="https://cdn.datatables.net/buttons/1.6.2/js/buttons.colVis.min.js"></script>
      <script src="https://cdn.datatables.net/buttons/1.6.2/js/buttons.html5.min.js"></script>
      <style>
        table.dataTable thead th {text-align:center; padding:0px 15px 0px 5px; font-weight:normal;}
        table.dataTable tbody td {text-align:center; padding:0px 5px 0px 5px}
        table.dataTable tfoot td {text-align:center; padding:0px 5px 0px 5px}
      </style>
      <script>
        $(function () {
          {%- if total == 'True' %}
          var last = $('table tr:last').remove()
          var foot = $("table").find('tfoot');
          if (!foot.length) foot = $('<tfoot>').appendTo("table");
          foot.append(last)
          {%- endif %}
          function selectedColumn(idx, data, node) {
            searchInput = $('table').parents('.dataTables_wrapper').find('select');
            let columnIndex = ourSelect.prop('selectedIndex');
            return ((columnIndex <= 0) || (idx == columnIndex - 1));
          }
          function get_uniq(data, obj) {
            return data.split('\\n').filter((item, i, allItems) => {return i === allItems.indexOf(item);}).join('\\n');
          }
          buttons = [{ extend: 'colvis', className: 'btn btn-primary' },
                     { extend: 'copy', className: 'btn btn-primary', title: '',
                       text: 'Copy Column', header: false, customize: get_uniq,
                       exportOptions: { columns: selectedColumn }
                     }];
          dataTable = $('table').DataTable({dom: 'Bfrtip', buttons: buttons,
            iDisplayLength: 100, paging: false, "order": []
          });
          col_css = {{col_css}}
          $('table.dataTable tr').filter(function() {
             return this.parentNode !== "thead";
            }).each(function(tr_idx,tr) {
            $(tr).children('td').each(function(td_idx, td) {
              $(td).css("text-align", col_css[td_idx]["align"])
            });
          });
          // support for search by
          searchInput = $('table').parents('.dataTables_wrapper').find('input[type=search]')
          ourInput = $(document.createElement('input')).attr({type: 'search'});
          scopeSpan = $(document.createElement('span')).text('Column Scope:').attr({style: "padding-right:5"})
          searchSpan = $(document.createElement('span')).text('Search:').attr({style: "padding-left:5"})
          ourLabel = $(document.createElement('label'))
          ourSelect = $(document.createElement('select'))
          var select = '<option/>';
          $("table thead tr th").each(function(){
            select += '<option>' + this.innerHTML + '</option>';
          })
          ourSelect.html(select);
          ourLabel.append(scopeSpan).append(ourSelect).append(searchSpan).append(ourInput).insertBefore(searchInput.parent());
          searchInput.parent().css("display", "none")
          let query = undefined;
          function hanleInputEvent() {
            query = ourInput.val().toLowerCase();
            if (query === '') { query = undefined; }
            dataTable.draw();
          }
          ourInput.on('keyup', hanleInputEvent)
          ourInput.on('search', hanleInputEvent)
          function filterDataTable(settings, data, dataIndex) {
            if (query === undefined) { return true; }
            let columnIndex = ourSelect.prop('selectedIndex')
            if (columnIndex > 0) {
              return data[columnIndex-1].toLowerCase().indexOf(query) !== -1;
            }
            for (var i = 0; i < data.length; i++) {
              if (data[i].toLowerCase().indexOf(query) !== -1) return true;
            }
            return 0
          }
          $.fn.dataTable.ext.search.push(filterDataTable);
        });
      </script>
    </head>
    """)

    html_tmpl = textwrap.dedent("""\
    {{js}}
    <body>
      <table border='1'>
      <thead>
        <tr>
          {%- for col in cols %}
          <th>{{col}}</th>
          {%- endfor %}
        </tr>
      </thead>
      <tbody>
        {%- for row in rows %}
        <tr{{row_css[loop.index0]}}>
          {%- set outer_loop = loop %}
          {%- for cell in row %}
          <td{{cell_css[outer_loop.index0][loop.index0]}}>{{cell}}</td>
          {%- endfor %}
        </tr>
        {%- endfor %}
      </tbody>
      </table>
    </body>
    """)

    l_rows = [[row[i] for i, _ in enumerate(cols)] for row in rows]
    for col_index, col in enumerate(cols):
        for row_index, l_row in enumerate(l_rows):
            if not links: continue
            if col in links and row_index < len(links[col]):
                l_link = links[col][row_index]
            elif None in links and row_index < len(links[None]):
                l_link = links[None][row_index]
            else: continue
            if not l_link: continue
            l_row[col_index]="<a href='{}'>{}</a>".format(l_link, l_row[col_index])

    row_css = ["" for _ in l_rows]
    col_css = [{prop: "center" for prop in ["align"]} for _ in cols]
    cell_css = [["" for _ in cols] for _ in l_rows]
    for col_index, col in enumerate(cols):
        if align and col in align:
            col_css[col_index]["align"] = "left" if align[col] else "center"
        elif align and None in align:
            col_css[col_index]["align"] = "left" if align[None] else "center"
        for row_index, l_row in enumerate(l_rows):
            if not colors: continue
            if col in colors and row_index <= len(colors[col]):
                color = ' style="background-color:{}"'.format(colors[col][row_index])
                cell_css[row_index][col_index] = color
            elif None in colors and row_index <= len(colors[None]):
                color = ' style="background-color:{}"'.format(colors[None][row_index])
                row_css[row_index] = color

    js = j2_apply(js_tmpl, total=str(total), col_css=col_css)
    html = j2_apply(html_tmpl, js=js, cols=cols, rows=l_rows, row_css=row_css,
                    cell_css=cell_css, col_css=col_css)
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
    except Exception:
        retval.append("Failed to parse stack trace {}".format(str(entries)))

    return retval

def poll_wait(method, timeout, *args, **kwargs):
    from spytest import st
    return st.poll_wait(method, timeout, *args, **kwargs)

def time_span_to_sec(time_span):
    try:
        return sum(x * int(t) for x, t in zip([3600, 60, 1], time_span.split(":")))
    except Exception:
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
    for d in iterable(dict_list):
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
        msg = str(msg)
        if wrap: output = ["{0} {1} {0}".format(delimiter,each.center(width-4))
                            for each in textwrap.wrap(msg, width=width-4)]
        else: output = ["{0} {1:{2}} {0}".format(delimiter,each,(width-4))
                            for each in textwrap.wrap(msg, width=width-4)]
        msg_list.extend(['\n'.join(output), delimiter*width])
    if tnl: msg_list.append("")
    for each_line in msg_list:
        if func: func(each_line)
        else: print(each_line)
    return "\n".join(msg_list)

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
    except Exception:
        return default

def min(n1, n2):
    return n1 if n1 < n2 else n2

def max(n1, n2):
    return n1 if n1 > n2 else n2

def j2_apply(text=None, file=None, paths=[], **kwargs):
    if text:
        text = Environment().from_string(text).render(**kwargs)
    elif file:
        file = find_file(file, paths)
        text = "\n".join(read_lines(file))
        text = Environment().from_string(text).render(**kwargs)
    else:
        raise Exception("Neither text nor file argument provided")
    return text

def json_parse(text=None, file=None, paths=[], **kwargs):
    root, text = None, j2_apply(text, file, paths, **kwargs)
    data = jsonutil.fix(text, "Invalid json text/file supplied", True)
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

def get_current_datetime(fmt="%m%d%Y%H%M%S"):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to get current date time
    :return:
    """
    now = datetime.datetime.now()
    return now.strftime(fmt)


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

def get_random_seed():
    if not os.getenv("SPYTEST_RAMDOM_SEED"):
        value = str(random.randint(10000,20000))
        os.environ["SPYTEST_RAMDOM_SEED"] = value
    return int(os.getenv("SPYTEST_RAMDOM_SEED", "100"))

def inject_module(mdl, depth=0, asvar=None):
    if "__all__" in mdl.__dict__:
        names = mdl.__dict__["__all__"]
    else:
        names = [x for x in mdl.__dict__ if not x.startswith("_")]
    f_globals = inspect.stack()[depth+1][0].f_globals
    upd_dict = {k: getattr(mdl, k) for k in names}
    if asvar: upd_dict = {asvar: upd_dict}
    f_globals.update(upd_dict)

def import_file_path(path, depth=0, asvar=None, inject=True):
    name = os.path.splitext(os.path.basename(path))[0]
    if sys.version_info[0] == 2:
        import imp
        sys.path.append(os.path.dirname(path))
        mdl = imp.load_source(name, path)
    elif sys.version_info[:2] <= (3, 4):
        from importlib.machinery import SourceFileLoader # pylint: disable=no-name-in-module,import-error
        mdl = SourceFileLoader(name, path).load_module() # pylint: disable=deprecated-method
    else:
        import importlib.util as importlib_util # pylint: disable=no-name-in-module,import-error
        spec = importlib_util.spec_from_file_location(name, path)
        mod = importlib_util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mdl = mod
    if inject:
        inject_module(mdl, depth+1, asvar)
    return mdl

def set_repeat(path, name, topo):
    import_file_path(path, 1)
    frame = inspect.stack()[1]
    filename = frame[0].f_code.co_filename
    os.environ["SPYTEST_REPEAT_NAME_{}".format(filename)] = name
    os.environ["SPYTEST_REPEAT_TOPO_{}".format(filename)] = topo

def unused(*args):
    pass

def get_env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except Exception:
        pass
    return default

if __name__ == "__main__":
    # indent the json file
    text = "\n".join(read_lines(sys.argv[1]))
    data = jsonutil.fix(text, load=True)
    print(jsonutil.dumps(data))

