import os
import re
import sys
import csv
import glob
import time
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

from . import ctrl_chars

if sys.version_info[0] >= 3:
    unicode = str
    basestring = str

def list_files_tree(dir_path, pattern="*", recursive=True):
    matches = []
    if recursive:
        res = os.walk(dir_path)
    else:
        res = [next(os.walk(dir_path))]
    for root, _, filenames in res:
        for filename in fnmatch.filter(filenames, pattern):
            matches.append(os.path.join(root, filename))
    return matches

def list_files(entry, pattern="*", recursive=True):
    if os.path.isdir(entry):
        return list_files_tree(entry, pattern, recursive)
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

def grep_file(filepath, regex, first=False):
    regObj = re.compile(regex)
    res = []
    with open(filepath) as f:
        for line in f:
            if regObj.match(line):
                res.append(line)
                if first: break
    return res

def ensure_folder(path):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        os.makedirs(path)
    return  path

def ensure_parent(filename):
    path = os.path.dirname(filename)
    return ensure_folder(path)

def open_file(filename, mode="r"):

    if mode == "w":
        ensure_parent(filename)

    if sys.version_info.major < 3:
        return open(filename, mode+"b")

    return open(filename, mode, newline='')

def delete_folder(folder):
    try: shutil.rmtree(folder)
    except Exception: pass

def delete_file(filename):
    if os.path.exists(filename):
        os.remove(filename)
        return True
    return False

def copyfile(src, dst, check=True):
    if check: ensure_folder(dst)
    shutil.copy2(src, dst)

def copy_file(src, dst, check=True):
    copyfile(src, dst, check)

def rename_file(src, dst):
    ensure_parent(dst)
    if os.path.exists(src):
        shutil.move(src, dst)

def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copytree(s, d, symlinks, ignore)
        else:
            copyfile(s, d, False)

def write_file(filename, data, mode="w"):
    if not filename: return data
    ensure_parent(filename)
    try:    data2 = ctrl_chars.tostring(data)
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
            if col in ent:
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
    print (sprint_data(d, msg))

def sprint_yaml(d, msg="", default_flow_style=False):
    rv = "========================{}===========================\n".format(msg)
    rv = rv + yaml.dump(d, default_flow_style=default_flow_style)
    rv = rv + "\n=====================================================\n"
    return rv

def print_yaml(d, msg="", default_flow_style=False):
    print (sprint_yaml(d, msg, default_flow_style))

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
        val = random.randint(2, 3966)
        if exclude and val in exclude:
            pass
        elif val not in retval:
            retval.append(val)
            count = count - 1
    return retval

def get_proc_name():
    return sys._getframe(1).f_code.co_name

def get_location(lvl=0):
    callerframerecord = inspect.stack()[lvl+1]
    frame = callerframerecord[0]
    finfo = inspect.getframeinfo(frame)
    return "{}:{}".format(os.path.basename(finfo.filename), finfo.lineno)

def get_line_number(lvl=0):
    cf = inspect.currentframe()
    for _ in range(lvl):
        if cf.f_back:
            cf = cf.f_back
    return cf.f_back.f_lineno if cf.f_back else 0

def get_line_numbers(lvl=0, count=4):
    lines = []
    for _ in range(count):
        lvl = lvl + 1
        line = get_line_number(lvl)
        if line == 0:
            break
        lines.append(get_line_number(lvl))
    if count == 1:
        return lines[0]
    return "/".join([str(line) for line in lines])

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

def is_unicode_string(arg):
    return bool(isinstance(arg, (unicode, str, bytes)))

def is_unicode(arg):
    return bool(isinstance(arg, unicode))

def to_unicode(arg):
    return unicode(arg)

def is_basestring(arg):
    return bool(isinstance(arg, basestring))

def do_eval(arg):
    return eval(arg)

def ipcheck(addr, max_attempts=1, logf=None, addr_type="", sleep=0):
    for attempt in range(1, max_attempts+1):
        try:
            subprocess.check_output(["ping", "-c", "2", "-w", "2", str(addr)])
            return True
        except subprocess.CalledProcessError as exp:
            if logf:
                msg = "{}IP {} is not reachable - attempt {} {}"
                logf(msg.format(addr_type, addr, attempt, str(exp)))
            if attempt <= max_attempts:
                time.sleep(sleep)
    return False

def urlcheck(url):
    data = parse_url(url)
    from http.client import HTTPConnection
    conn = HTTPConnection(data["netloc"])
    try:
        conn.request('HEAD', data["path"])
        res = conn.getresponse()
        return bool(res.status == 200), None
    except Exception as exp:
        return False, exp

def sprintf(fmt, *args):
    return fmt % args

def md5(fname, data=None):
    hash_md5 = hashlib.md5(data or b"")
    if fname:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    return hash_md5.hexdigest()

def str_encode(s, etype="ascii"):
    try: return s.encode(etype)
    except Exception: return s

def str_decode(s, etype="ascii"):
    try: return s.decode(etype)
    except Exception: return s

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

def read_lines(filepath, strip=True, default=[]):
    try:
        fh = open(filepath, 'r')
        data = fh.readlines()
        fh.close()
    except Exception:
        data = default
    if strip:
        data = map(str.strip, data)
    else:
        data = map(str, data)
    return list(data)

def find_duplicate(items):
    retval, unique = [], []
    for item in items or []:
        if item not in unique:
            unique.append(item)
        else:
            retval.append(item)
    return retval, unique

def remove_duplicates(*args):
    for arg in args:
        _, unique = find_duplicate(arg)
        del arg[:]
        arg.extend(unique)

def list_flatten(l, rv=None):
    rv = rv or []
    for i in l:
        if isinstance(i, list):
            list_flatten(i, rv)
        else:
            rv.append(i)
    return rv

def list_insert(lst, *args):
    rv = list(lst)
    for arg in args:
        if isinstance(arg, list):
            tmp = list_flatten(arg)
        else:
            tmp = [arg]
        for i in tmp:
            if i not in rv:
                rv.append(i)
    return rv

def list_append(lst, *args):
    for arg in args:
        if arg not in lst:
            lst.append(arg)

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
    ensure_parent(filepath)
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

def get_cdn_base(cdn=None):
    cdn0 = "https://cdn.datatables.net/v/dt/jq-3.6.0/dt-1.12.1/b-2.2.3/b-colvis-2.2.3/b-html5-2.2.3/fh-3.2.4/"
    return cdn0 if cdn is None else cdn

def copy_web_include(dst_path):
    web_incl_path = os.path.join(os.path.dirname(__file__), "web")
    copyfile(os.path.join(web_incl_path, "datatables.min.css"), dst_path)
    copyfile(os.path.join(web_incl_path, "datatables.min.js"), dst_path)

# links, colors and align are dictionaries or None
# where key is column name or None and value is list of links/colors/align
# None key is used for entire row
# text-align None=center, True=Left, False=Right
# total data in rows None: not present True: Last row False: First row
# total_pos False: Head True: FOOT None: Hide
def write_html_table3(cols, rows, filepath=None, links=None, colors=None,
                      align=None, total=True, total_pos=False, addl_cols=None,
                      cdn=None, fixedHeader=None):
    cdn = get_cdn_base(cdn)
    js_tmpl = textwrap.dedent(r"""
    <head>
      <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
      <meta http-equiv="Pragma" content="no-cache" />
      <meta http-equiv="Expires" content="0" />
      <link rel="stylesheet" type="text/css" href="{{cdn}}datatables.min.css"/>
      <script type="text/javascript" src="{{cdn}}datatables.min.js"></script>
      <style>
        table.dataTable thead th {text-align:center; padding:0px 15px 0px 5px; font-weight:bold;}
        table.dataTable tbody td {text-align:center; padding:0px 5px 0px 5px}
        table.dataTable tfoot td {text-align:center; padding:0px 5px 0px 5px}
        .dt-button-collection .dt-button.buttons-columnVisibility {
            background: none !important; background-color: transparent !important;
            box-shadow: none !important; border: none !important; padding: 0.25em 1em !important;
            margin: 0 !important; text-align: left !important;
        }
        .dt-button-collection .buttons-columnVisibility:before,
        .dt-button-collection .buttons-columnVisibility.active span:before {
            display:block; position:absolute; top:1.2em; left:0;
            width:12px; height:12px; box-sizing:border-box;
        }
        .dt-button-collection .buttons-columnVisibility:before {
            content:' '; margin-top:-8px; margin-left:10px; border:1px solid black; border-radius:3px;
        }
        .dt-button-collection .buttons-columnVisibility.active span:before {
            font-family: 'Arial' !important; content:'\\2714'; margin-top: -15px; margin-left: 12px;
            text-align: center; text-shadow: 1px 1px #fff, -1px -1px #fff, 1px -1px #fff, -1px 1px #fff;
        }
        .dt-button-collection .buttons-columnVisibility span { margin-left:17px; }
      </style>
      <script>
        $(function () {
          {%- if total != 'None' %}
            {%- if total == 'True' %}
              var last = $('table tr:last').remove()
            {%- else %}
              var last = $('table tr').eq(1).remove()
            {%- endif %}
            {%- if total_pos != 'None' %}
              {%- if total_pos == 'True' %}
                var tfoot = $("table").find('tfoot');
                if (!tfoot.length) tfoot = $('<tfoot>').appendTo("table");
                tfoot.append(last)
              {%- else %}
                var thead = $("table").find('thead');
                if (!thead.length) {
                    thead = $('<thead>').prependTo("table");
                    thead.prepend(last)
                } else {
                    thead.prepend(last)
                    //TODO: see if we need to insert before last child
                }
              {%- endif %}
            {%- endif %}
          {%- endif %}
          var url = new URL(window.location); var search_params = url.searchParams;
          if (parseInt(search_params.get("nocache")|0, 0) != 0) {
            search_params.set('timestamp', Date.now()/1000|0);
            search_params.delete('nocache'); window.location = url.toString();
          }
          function selectedColumn(idx, data, node) {
            oldSearchInput = $('table').parents('.dataTables_wrapper').find('select');
            let columnIndex = columnScopeSelect.prop('selectedIndex');
            return ((columnIndex <= 0) || (idx == columnIndex - 1));
          }
          function get_uniq(data, obj) {
            return data.split('\\n').filter((item, i, allItems) => {return i === allItems.indexOf(item);}).join('\\n');
          }
          buttons = [{ extend: 'colvis', className: 'btn btn-primary', collectionLayout: 'two-column' },
                     { extend: 'copy', className: 'btn btn-primary', title: '',
                       text: 'Copy Column', header: false, customize: get_uniq,
                       exportOptions: { columns: selectedColumn }
                     }];
          function parseTimeStamp(ts) {
            var parts = ts.split(":"), total = 0, multiplier=1;
            for(var i = parts.length; i>0; i--) {
              total = total + parseInt(parts[i-1])*multiplier;
              multiplier=multiplier*60;
            }
            return total;
          }
          jQuery.fn.dataTableExt.aTypes.unshift(function (sData) {
            return /^(\d+):(\d+):(\d+)/i.test(sData) ? 'duration' : null
          });
          jQuery.fn.dataTableExt.oSort['duration-asc'] = function (a, b) {
            var ordA = parseTimeStamp(a), ordB = parseTimeStamp(b);
            return (ordA < ordB) ? -1 : ((ordA > ordB) ? 1 : 0);
          };
          jQuery.fn.dataTableExt.oSort['duration-desc'] = function (a, b) {
            var ordA = parseTimeStamp(a), ordB = parseTimeStamp(b);
            return (ordA < ordB) ? 1 : ((ordA > ordB) ? -1 : 0);
          };
          dataTable = $('table').DataTable({dom: 'Bfrtip', buttons: buttons,
            stateSave: true, iDisplayLength: 100, paging: false, order: [],
            fixedHeader: {{fixedHeader}}, stateDuration: 60 * 60 * 24
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
          oldSearchInput = $('table').parents('.dataTables_wrapper').find('input[type=search]')
          searchInput = $(document.createElement('input')).attr({type: 'search'});
          columnScopeLabel = $(document.createElement('span')).text('Column Scope:').attr({style: "padding-right:5"})
          searchLabel = $(document.createElement('span')).text('Search:').attr({style: "padding-left:5"})
          negateLabel = $(document.createElement('span')).text('Negate Results:').attr({style: "padding-left:2"})
          negateCheckbox = $(document.createElement('input')).attr({type: 'checkbox', style: "padding-left:0"})
          mainLabel = $(document.createElement('label'))
          columnScopeSelect = $(document.createElement('select'))
          var select = '<option/>';
          $("table thead tr:last-child th").each(function(){
            select += '<option>' + this.innerHTML + '</option>';
          })
          columnScopeSelect.html(select);
          mainLabel.append(columnScopeLabel)
          mainLabel.append(columnScopeSelect)
          mainLabel.append(searchLabel)
          mainLabel.append(searchInput)
          mainLabel.append(negateLabel)
          mainLabel.append(negateCheckbox)
          mainLabel.insertBefore(oldSearchInput.parent());
          oldSearchInput.parent().css("display", "none")
          let query = undefined;
          function hanleInputEvent() {
            query = searchInput.val().toLowerCase();
            if (query === '') { query = undefined; }
            dataTable.draw();
          }
          searchInput.on('keyup', hanleInputEvent)
          searchInput.on('search', hanleInputEvent)
          negateCheckbox.on('click', hanleInputEvent)
          search_val = search_params.get("search")|0
          if (search_val != 0) {
            searchInput.val(search_val)
            setTimeout(function(){searchInput.trigger('keyup')}, 1);
          }
          function matchit(value) {
            if (query.trim() === "") {
              found = (value === "");
            } else if (typeof value === 'undefined') {
              found = false;
            } else {
              found = (value.toLowerCase().indexOf(query) !== -1);
            }
            if (negateCheckbox.is(":checked")) {
              return !found;
            }
            return found;
          }
          function filterDataTable(settings, data, dataIndex) {
            if (query === undefined) { return true; }
            let columnIndex = columnScopeSelect.prop('selectedIndex')
            if (columnIndex > 0) {
              return matchit(data[columnIndex-1])
            }
            for (var i = 0; i < data.length; i++) {
              if (matchit(data[i])) {
                return true;
              }
            }
            return false
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
        {% if addl_cols %}
        <tr>
          {%- for col, span in addl_cols %}
          <th colspan="{{span}}">{{col}}</th>
          {%- endfor %}
        </tr>
        {% endif %}
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
            elif col_index in colors and row_index <= len(colors[col_index]):
                color = ' style="background-color:{}"'.format(colors[col_index][row_index])
                cell_css[row_index][col_index] = color
            elif None in colors and row_index <= len(colors[None]):
                color = ' style="background-color:{}"'.format(colors[None][row_index])
                row_css[row_index] = color

    fixedHeader = "true" if fixedHeader in [None, True] else "false"
    js = j2_apply(js_tmpl, total=str(total), total_pos=str(total_pos),
                  col_css=col_css, cdn=cdn, fixedHeader=fixedHeader)
    addl_cols = addl_cols or []
    html = j2_apply(html_tmpl, js=js, cols=cols, rows=l_rows, row_css=row_css,
                    cell_css=cell_css, col_css=col_css, addl_cols=addl_cols)
    return write_file(filepath, html)

def write_html_table4(cols, rows, filepath=None, links=None, colors=None,
                      align=None, total=True, total_pos=False, addl_cols=None,
                      fixedHeader=None):
    return  write_html_table3(cols, rows, filepath, links, colors,
                      align, total, total_pos, addl_cols, cdn="",
                      fixedHeader=fixedHeader)

def stack_trace0(entries):

    if entries is None:
        return []

    if isinstance(entries, str):
        return entries.split("\n")

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

def get_call_stack(lvl, lines=None):
    import traceback
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..')) + os.sep
    lines = lines or []
    for item in reversed(traceback.extract_stack()[:-lvl]):
        fname, line, func, text = item
        if not os.path.exists(fname): continue
        if not fname.startswith(root) and fname.startswith(os.sep): continue
        fname = fname.replace(root, "")
        msg = "{}:{} {} {}".format(fname, line, func, text)
        lines.append(msg)
    return lines

def get_call_stack_all(lvl=0, ident="CallStack:"):
    lines = []
    for line in get_call_stack(3+lvl):
        lines.append("[{}] {}".format(len(lines), line))
    from . import parallel
    for line in parallel.get_call_stack():
        lines.append("[{}] {}".format(len(lines), line))
    if not lines: return lines
    lines.insert(0, ident)
    return lines

# entries should be output of traceback.format_exc()
def stack_trace(entries=None, call_stack=None):
    import traceback
    if not entries and sys.exc_info()[0] is not None:
        entries = traceback.format_exc()[:-2]
    retval = stack_trace0(entries)
    if not call_stack: return retval
    lines = get_call_stack_all(1, "StackTraceCallStack:")
    retval.extend(lines)
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

def no_print(msg):
    pass

def banner(msg, width=80, delimiter="#", wrap=True, func=None, tnl=True, lnl=True):
    msg_list = [""] if lnl else []
    msg_list.append(delimiter*width)
    if msg is not None:
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

def is_integer(n):
    try:
        float(n)
    except ValueError:
        return False
    else:
        return float(n).is_integer()

def integer_parse(s, default=None):
    try: s = s.replace(",", "")
    except Exception: pass
    try:
        return int(s)
    except Exception:
        return default

def parse_integer(s, default=None):
    return integer_parse(s, default)

def parse_float(s, default=None):
    try:
        return float(s)
    except Exception:
        return default

def div_float(dividend, divisor, default=None):
    try:
        return (1.0 * dividend)/divisor
    except Exception as e:
        if default is None:
            raise(e)
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
        raise ValueError("Neither text nor file argument provided")
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


def get_current_test_name():
    """Returns current test function name"""
    # PYTEST_CURRENT_TEST value will be of syntax "FILE_NAME::FUNC_NAME (STAGE)"
    full_name = os.getenv("PYTEST_CURRENT_TEST", "").split(" ")[0]
    return full_name.split("::")[-1]

def get_current_test_id():
    """Returns current test function id"""
    # PYTEST_CURRENT_TEST value will be of syntax "FILE_NAME::FUNC_NAME (STAGE)"
    full_name = os.getenv("PYTEST_CURRENT_TEST", "").split(" ")[0]
    return full_name

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
    n = data.rfind('\n')
    return data[:n] if n > 0 else ""

def get_random_seed():
    if not os.getenv("SPYTEST_RANDOM_SEED"):
        value = str(random.randint(10000,20000))
        os.environ["SPYTEST_RANDOM_SEED"] = value
    return int(os.getenv("SPYTEST_RANDOM_SEED", "100"))

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
        import imp # pylint: disable=deprecated-module
        sys.path.append(os.path.dirname(path))
        mdl = imp.load_source(name, path)
    elif sys.version_info[:2] <= (3, 4):
        from importlib.machinery import SourceFileLoader # pylint: disable=no-name-in-module,import-error
        mdl = SourceFileLoader(name, path).load_module() # pylint: disable=deprecated-method,no-value-for-parameter
    else:
        import importlib.util as importlib_util # pylint: disable=no-name-in-module,import-error
        spec = importlib_util.spec_from_file_location(name, path)
        mod = importlib_util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mdl = mod
    if inject:
        inject_module(mdl, depth+1, asvar)
    return mdl

def set_repeat(mname, path, name, topo):
    import_file_path(path, 1)
    frame = inspect.stack()[1]
    filename = frame[0].f_code.co_filename
    os.environ["SPYTEST_REPEAT_NAME_{}".format(filename)] = name
    os.environ["SPYTEST_REPEAT_TOPO_{}".format(mname)] = topo

def unused(*args):
    pass

def get_env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        pass
    return default

def re_match_any(data, *args):
    for arg in args:
        if re.match(arg, data):
            return True
    return False

def dict_copy(from_dict, to_dict, *names):
    for name in names:
        if name in from_dict:
            to_dict[name] = from_dict.get(name)

def list_copy(from_list, to_list=None):
    retval = to_list or []
    for item in from_list or []:
        retval.append(item)
    return retval

def parse_url(url):
    try: from urllib.parse import urlparse
    except Exception: from urlparse import urlparse
    retval = {}
    pr = urlparse(url)
    retval["protocol"] = pr.scheme
    retval["netloc"] = pr.netloc
    retval["path"] = pr.path
    parts = pr.netloc.split("@")
    port_parts = parts[-1].split(":")
    retval["ip"] = port_parts[0]
    retval["port"] = port_parts[1] if len(port_parts) > 1 else None
    if len(parts) > 1:
        parts = parts[0].split(":")
        retval["user"] = parts[0]
        retval["pwd"] = parts[1] if len(parts) > 1 else None
    else:
        retval["user"], retval["pwd"] = None, None
    return retval

def download_url(url, path):
    try: from urllib import urlretrieve
    except Exception: from urllib.request import urlretrieve
    urlretrieve(url, path)

def download_large_file(url, filepath=None):
    filepath = filepath or url.split('/')[-1]
    ensure_parent(filepath)
    import requests
    with requests.get(url, stream=True, timeout=600) as r:
        r.raise_for_status()
        with open(filepath, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return filepath

def csv2list(value, uniq=True):
    retval = []
    if value is not None:
        for val in value.split(","):
            if not uniq or val not in retval:
                retval.append(val)
    return retval

def print_table(*args, **kwargs):
    from spytest import st
    kwargs["tablefmt"] = 'grid'
    msg = tabulate(*args, **kwargs)
    st.log("\n{}".format(msg))

def print_log(msg):
    from spytest import st
    log_start = "\n================================================================================\n"
    log_end = "\n================================================================================"
    st.log("{} {} {}".format(log_start, msg, log_end))

def print_log_alert(message,alert_type="LOW"):
    from spytest import st
    '''
    Uses st.log procedure with some formatting to display proper log messages
    :param message: Message to be printed
    :param alert_level:
    :return:
    '''
    log_start = "\n======================================================================================\n"
    log_end =   "\n======================================================================================"
    log_delimiter ="\n###############################################################################################\n"

    if alert_type == "HIGH":
        st.log("{0} {1} {0}".format(log_delimiter,message))
    elif alert_type == "MED":
        st.log("{} {} {}".format(log_start,message,log_end))
    elif alert_type == "LOW":
        st.log(message)
    elif alert_type == "ERROR":
        st.error("{0} {1} {0}".format(log_start,message))

def check_file_pdb(filepath=None):
    from spytest import st
    filepath = filepath or st.get_logs_path("pdb.txt")
    if os.path.exists(filepath):
        st.warn("Entering into PDB as {} is present".format(filepath))
        import pdb;pdb.set_trace()

def remove_empty_lines(text):
    return os.linesep.join([s for s in text.splitlines() if s])

def remove_prefix(txt, sstr):
    return txt[len(sstr):] if txt.startswith(sstr) else txt

def remove_suffix(txt, sstr):
    return txt[:-(len(sstr))] if txt.endswith(sstr) else txt

def kwargs_to_dict_list(**kwargs):

    input_dict_list =[]

    #Converting all kwargs to list type to handle single or list of instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in list(kwargs.keys()):
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    return input_dict_list

def get_yang_data_type(data_type):
    """
    Common function to get the yang data types
    :param data_type:
    :return:
    """
    from spytest import st
    from apis.yang.utils.query_param import YangDataType
    supported_data_types = {"ALL":YangDataType.ALL, "CONFIG":YangDataType.CONFIG, "NON_CONFIG":YangDataType.NON_CONFIG}
    st.debug("Returning Yang data type as {} : {}".format(data_type, supported_data_types.get(data_type)))
    return supported_data_types.get(data_type)


def get_query_params(**kwargs):
    """
    Common utils function to prepare the query params for gNMI calls
    :param kwargs:
    :return:
    """
    from spytest import st
    from apis.yang.utils.query_param import QueryParam
    query_param = QueryParam()
    cli_type = kwargs.get("cli_type", "gnmi")
    if cli_type == "gnmi":
        if kwargs.get("yang_data_type"):
            if kwargs.get("yang_data_type").upper() == "OPERATIONAL":
                query_param.set_gnmi_operational_type()
            else:
                data_type = get_yang_data_type(kwargs.get("yang_data_type").upper())
                if not data_type:
                    st.error("Invalid Yang Datatype : {}".format(kwargs.get("yang_data_type")))
                query_param.set_content(data_type)
        if kwargs.get("depth"):
            query_param.set_depth(kwargs.get("depth"))
        if kwargs.get("set_fields"):
            query_param.set_fields(kwargs.get("set_fields"))
        if kwargs.get("unset_fields"):
            query_param.unset_fields()
    else:
        data_type = get_yang_data_type(kwargs.get("yang_data_type", "ALL").upper())
        query_param.set_content(data_type)
    return query_param

def concat(*args):
    retval = []
    for arg in args:
        if arg and isinstance(arg, list):
            retval.append(concat(*arg))
            continue
        arg = str(arg).strip()
        if arg: retval.append(arg)
    return " ".join(retval).strip()

def read_build_info(filename):
    retval = {}
    for line in read_lines(filename):
        name, value = line.split(":", 1)
        retval[name] = value.strip()
    return retval

def abort_run(val):
    print("ABORTING RUN {}".format(val))
    time.sleep(2)
    os._exit(val)

def compare_llists(l1, l2, names=[], headers=[]):
    common = [x for x in l1 if x in l2]
    l1addl = [x for x in l1 if x not in l2]
    l2addl = [x for x in l2 if x not in l1]

    rows = []
    if not names or len(names) < 2:
        names = ["1", "2"]

    for row in common:
        tmp = ["Both"]
        tmp.extend(row)
        rows.append(tmp)

    for row in l1addl:
        tmp = [names[0]]
        tmp.extend(row)
        rows.append(tmp)

    for row in l2addl:
        tmp = [names[1]]
        tmp.extend(row)
        rows.append(tmp)

    return tabulate(rows, headers=headers)

def dump_connections(msg=""):
    lines = []
    try:
        import psutil
        p = psutil.Process()
        for line in p.connections(kind='inet'):
            msg_line = "{}{}".format(msg, line)
            lines.append(msg_line)
    except Exception:
        pass
    return lines

def set_ps_name(name):
    try:
        import sys_prctl # pylint: disable=import-error
        sys_prctl.setprocname(name) # pylint: disable=no-member
        return True
    except Exception: return False

def get_doc_string(func):
    if isinstance(func, str):
        name = func
        func = locals().get(name) or globals().get(name)
    else:
        name = getattr(func, "__name__", "")
    doc = func.__doc__ or ""
    lines = []
    for line in doc.split("\n"):
        line = line.strip()
        if not line or "Author" in line:
            continue
        lines.append(line)
    return name, " ".join(lines)

def get_meminfo():
    def pretty(size, fmt=['','kb','mb', 'gb']):
        return "{}{}".format(size, fmt[0]) if size < 1024 or len(fmt) <= 1 else pretty(size>>10, fmt[1:])
    try:
        import psutil
        vm = psutil.virtual_memory()
        return "MEM: {} {}%".format(pretty(vm.total), vm.percent)
    except Exception: return ""

def parse_hyphon_name_value(s):
    name, val, rv = None, [], {}
    for w in s.split():
        if w[:1] != "-":
            val.append(w)
        else:
            if name: rv[name] = " ".join(val)
            name, val = w, []
    if name: rv[name] = " ".join(val)
    return rv

def move_to_end(lst, elem):
    if elem in lst:
        lst = [x for x in lst if x != elem]
        lst.append(elem)
    return lst

def move_to_start(lst, elem):
    if elem in lst:
        lst = [x for x in lst if x != elem]
        lst.insert(0, elem)
    return lst

def logargs(*args, **kwargs):
    retval = []
    for arg in args:
        retval.append(str(arg))
    for key, val in kwargs.items():
        retval.append("{}={}".format(key, str(val)))
    return ", ".join(retval)

def logcall(func, *args, **kwargs):
    retval = logargs(*args, **kwargs)
    if not func: return retval
    return "{}({})".format(func, retval)

def get_range_from_sequence(val=[]):
    val=[int(i) for i in val]
    val.sort()
    result= []
    start = end = val[0]

    for i in range(1, len(val)):
        if val[i] == end + 1:
            end = val[i]
        else:
            if start == end:
                result.append(str(start))
            else:
                result.append("{}-{}".format(str(start), str(end)))
            start = val[i]
            end = val[i]

    if start == end:
        result.append(str(start))
    else:
        result.append("{}-{}".format(str(start), str(end)))

    return result
