import sys
import csv
import os
import enum

from collections import OrderedDict

import utilities.common as utils

from spytest.st_time import get_timestamp
from spytest.datamap import DataMap
import spytest.paths as paths
import spytest.env as env

from .mail import send as email

class ReportType(enum.IntEnum):
    FUNCTIONS = 0
    TESTCASES = 1
    SYSLOGS = 2
    STATS = 3
    SYSINFO = 4
    DEFAULTS = 5
    ANALISYS = 6

hide_log_text, hide_log_host = True, True

slave_cols0 = ['#', 'Module', 'TestFunction', 'Result', 'TimeTaken',
              'ExecutedOn', 'Syslogs', 'FCLI', "TSSH", "DCNT", 'Description', "Devices"]
slave_cols1 = ['#', 'Feature', 'TestCase', 'Result',
              'ResultType', 'ExecutedOn', 'Description', 'Function', 'Module', "Devices"]
slave_cols2 = ['#', "Device", 'Module', 'TestFunction', "LogDate", "LogHost", "LogLevel", "LogModule", "LogMessage", "LogText"]
if hide_log_text: slave_cols2.remove("LogText")
if hide_log_host: slave_cols2.remove("LogHost")
slave_cols3 = ["#", "Module", "Function", "Result", "Test Time", "Helper Time", "CMD Time",
               "TG Time", "Wait", "TGWait", "PROMPT NFOUND", "Description"]
slave_cols4 = ["#", "Module", "DUTs", "MEM0", "MEM1", "MEM", "CPU0", "CPU1", "CPU"]
slave_cols5 = ["#", "Name", "Value"]
slave_cols6 = ['Feature', 'TestCase', 'Result', 'Description', 'Function', 'Module', "Devices",
               'Analisis', 'DUT Defect ID', 'SQA Defect ID', 'Engineer']


slave_cols = [slave_cols0, slave_cols1, slave_cols2, slave_cols3, slave_cols4, slave_cols5, slave_cols6]
merge_cols0 = ['#', "Node", 'Module', 'TestFunction', 'Result',
              'TimeTaken', 'ExecutedOn', 'Syslogs', 'FCLI', "TSSH", "DCNT", 'Description', "Devices"]
merge_cols1 = ['#', "Node", 'Feature', 'TestCase', 'Result',
               'ResultType', 'ExecutedOn', 'Description', 'Function', 'Module', "Devices"]
merge_cols2 = ['#', "Node", "Device", 'Module', 'TestFunction', "LogDate", "LogHost", "LogLevel", "LogModule", "LogMessage", "LogText"]
if hide_log_text: merge_cols2.remove("LogText")
if hide_log_host: merge_cols2.remove("LogHost")
merge_cols3 = ["#", "Node", "Module", "Function", "Result", "Test Time", "Helper Time", "CMD Time",
                "TG Time", "Wait", "TGWait", "PROMPT NFOUND", "Description"]
merge_cols4 = ["#", "Node", "Module", "DUTs", "MEM0", "MEM1", "MEM", "CPU0", "CPU1", "CPU"]
merge_cols5 = ["#", "Name", "Value"]
merge_cols6 = ['Feature', 'TestCase', 'Result', 'Description', 'Function', 'Module', "Devices",
               'Analisis', 'DUT Defect ID', 'SQA Defect ID', 'Engineer']
merge_cols = [merge_cols0, merge_cols1, merge_cols2, merge_cols3, merge_cols4, merge_cols5, merge_cols6]

colors_map = OrderedDict([
    (99, "green"),
    (80, "white"),
    (50, "yellow"),
    (0, "red")
])
class Result(object):

    def __init__(self, prefix, is_slave=True):
        self.csv_fd = [None, None, None]
        self.writer = [None, None, None]
        self.count  = [0, 0, 0]
        self.result = None
        self.desc = None
        self.default_result = None
        self.default_desc = None
        dmap = DataMap("messages")
        self.msgs = dmap.get()
        self.prefix = prefix
        self.report_csv = [None, None, None]
        self.report_csv[0] = "{}_functions.csv".format(prefix)
        self.report_csv[1] = "{}_testcases.csv".format(prefix)
        self.report_csv[2] = "{}_syslog.csv".format(prefix)
        if is_slave:
            self.open_csv(prefix, 0)
            self.open_csv(prefix, 1)
            self.open_csv(prefix, 2)

    def __del__(self):
        self.close_csv(0)

    def clear(self):
        self.result = None
        self.desc = None
        self.default_result = None
        self.default_desc = None

    def get(self):
        if not self.result:
            if not self.default_result:
                return ["ScriptError", "test case exited without setting any result"]
            return [self.default_result, self.default_desc]
        return [self.result, self.desc]

    def build_msg(self, name, *args):
        if name not in self.msgs:
            raise ValueError("unknown message identifier '{}'".format(name))

        s = self.msgs[name]
        try:
            rv = s.format(*args)
        except Exception:
            raise ValueError("expected arguments not provided")

        return rv

    def set_default_error(self, res, code, *args):
        self.default_result = res
        if not code:
            self.default_desc = None
        else:
            self.default_desc, msg_ok = self.msg(code, *args)
            if not msg_ok: self.default_result = "Fail"
        return self.default_desc

    def set(self, res, code, *args):
        if self.result and self.result != "Pass":
            msg = "result already set to {} -- ignoring".format(self.result)
            return msg
        self.result = res
        self.desc, msg_ok = self.msg(code, *args)
        if not msg_ok: self.result = "Fail"
        return self.desc

    def msg(self, code, *args):
        try:
            desc = self.build_msg(code, *args)
            msg_ok = True
        except Exception as e:
            print(e)
            desc = "Invalid error code {} : {}".format(code, e)
            msg_ok = False
        return desc, msg_ok

    def _build_record(self, nodeid, func, tcid, time_taken, comp, result=None,
                      desc=None, rtype="Executed", index=0, syslog_count=0,
                      fcli=0, tryssh=0, dut_list=[]):
        self.count[index] = self.count[index] + 1
        result_def, desc_def = self.get()
        result = result_def if result is None else result
        desc = desc_def if desc is None else desc

        executedOn = get_timestamp(False)

        if comp:
            rcdict = {
                "#": self.count[index],
                "Feature": comp,
                "TestCase": tcid,
                "Result": result,
                "ExecutedOn": executedOn,
                "ResultType": rtype,
                "Description": desc,
                "Function": func,
                "Module": paths.get_mlog_basename(nodeid),
                "Devices": " ".join(map(str, dut_list)),
            }
        else:
            rcdict = {
                "#": self.count[index],
                "Module": paths.get_mlog_basename(nodeid),
                "TestFunction": func,
                "Result": result,
                "ExecutedOn": executedOn,
                "TimeTaken": time_taken,
                "Syslogs": syslog_count,
                "FCLI": fcli,
                "TSSH": tryssh,
                "DCNT": len(dut_list),
                "Description": desc,
                "Devices": " ".join(map(str, dut_list)),
            }
        return rcdict

    def publish(self, nodeid, func, tcid, time_taken, comp, result=None,
                desc=None, rtype="Executed", syslogs=None,
                fcli=0, tryssh=0, dut_list=[]):
        syslog_count = 0 if not syslogs else len(syslogs)
        index = 0 if rtype == "Executed" else 1
        rcdict = self._build_record(nodeid, func, tcid, time_taken, comp,
                                    result, desc, rtype, index, syslog_count,
                                    fcli, tryssh, dut_list)
        self.write_csv(rcdict, index)

        if not comp:
            index = 2
            for devname, msgtype, date, host, level, text, module, msg in syslogs:
                func = func if func else msgtype
                self.count[index] = self.count[index] + 1
                d = {
                    "#": self.count[index],
                    "Device": devname,
                    "Module": paths.get_mlog_basename(nodeid),
                    "TestFunction": func,
                    "LogDate": date,
                    "LogHost": host,
                    "LogLevel": level,
                    "LogModule": module,
                    "LogMessage": msg,
                    "LogText": text,
                    }
                if hide_log_text: d.pop("LogText")
                if hide_log_host: d.pop("LogHost")
                self.write_csv(d, index)

        return rcdict

    def email(self, mailcfg, attachments=None, is_html=False):
        body = """
    Note: This is an automated mail sent by the SpyTest application. Please do not reply.
    """
        if is_html:
            body = mailcfg.body
        else:
            body = mailcfg.body + body
        subject = mailcfg.subject
        recipients = utils.split_byall(mailcfg.recipients)
        server = mailcfg.server
        if attachments is None:
            attachments = []
            attachments.append(self.report_csv[0])
            attachments.append(self.report_csv[1])
            attachments.append(self.report_csv[2])
        email(server, recipients, subject, body, attachments, is_html)

    def open_csv(self, prefix, index):
        report_csv = self.report_csv[index]
        if env.get("SPYTEST_RESULTS_PREFIX"):
            rows = Result.read_report_csv(report_csv)
        else:
            rows = []
        if sys.version_info.major < 3:
            csv_fd = open(report_csv, "wb")
        else:
            csv_fd = open(report_csv, "w", newline='')
        writer = csv.DictWriter(csv_fd, fieldnames=slave_cols[index],
                                     dialect="excel")
        self.csv_fd[index] = csv_fd
        if not rows:
            writer.writeheader()
        else:
            l_rows = Result.prepend_row_index(rows)
            utils.write_csv_writer(slave_cols[index], l_rows, writer)
            self.count[index] = len(rows)
        self.writer[index] = writer

    def close_csv(self, index):
        if self.csv_fd[index]:
            self.csv_fd[index].close()
            self.csv_fd[index] = None
        self.writer[index] = None

    def write_csv(self, rcdict, index):
        if self.writer[index]:
            self.writer[index].writerow(rcdict)
            self.csv_fd[index].flush()

    @staticmethod
    def read_report_csv(filepath, rmindex=True):
        rows = []
        try:
            with utils.open_file(filepath) as fd:
                for row in csv.reader(fd):
                    if row[0] != '#':
                        if rmindex:
                            row.pop(0)
                        rows.append(row)
        except Exception:
            #print("failed to open {} to read".format(filepath))
            pass

        return rows

    @staticmethod
    def write_report_csv(filepath, rows, rtype, is_batch=True, append=False, row_index=True):
        if append or not row_index:
            l_rows = rows
        else:
            l_rows = Result.prepend_row_index(rows)
        if is_batch:
            utils.write_csv_file(merge_cols[rtype], l_rows, filepath, append)
        else:
            utils.write_csv_file(slave_cols[rtype], l_rows, filepath, append)

    @staticmethod
    def prepend_row_index(rows):
        l_rows=[]
        for i,row in enumerate(rows):
            l_row = [i+1]
            l_row.extend(row)
            l_rows.append(l_row)
        return l_rows

    @staticmethod
    def write_report_png(filepath, rows, index):
        if env.get("SPYTEST_RESULTS_PNG", "1") == "0":
            return
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            buckets = dict()
            all_colors = {
                "green":0, "red":0, "orange":0, "blue":0,
                "cyan":0, "olive":0, "sienna":0, "peru":0,
                "indigo":0, "magenta":0, "lightblue":0,
                "yellow":0, "salmon":0, "palegreen":0,
                "pink":0, "crimson":0, "lightpink":0
            }
            res_colors = {
                "Pass":"green", "DUTFail":"red", "Fail":"orange",
                "ScriptError":"blue", "EnvFail":"cyan", "DepFail":"olive",
                "ConfigFail":"sienna", "TopoFail":"peru", "TGenFail":"indigo",
                "Timeout":"magenta", "Skipped":"lightblue", "Unsupported": "yellow"
            }
            for row in rows:
                res = row[index]
                if not res:
                    continue
                if res not in buckets:
                    buckets[res] = 0
                buckets[res] = buckets[res] + 1
            labels = []
            colors = []
            for label in buckets:
                if label in res_colors:
                    color = res_colors[label]
                    all_colors[color]=1
                else:
                    for c,used in all_colors.items():
                        if not used:
                            color=c
                            all_colors[color]=1
                            break
                colors.append(color)
                labels.append("{} [{}]".format(label, buckets[label]))
            sizes = buckets.values()
            plt.pie(sizes, colors=colors, labels=labels, autopct='%1.1f%%', startangle=140)
            plt.axis('equal')
            plt.savefig(filepath)
            plt.clf()
        except Exception as e:
            print(e)

    @staticmethod
    def write_report_html(filepath, rows, rtype=ReportType.FUNCTIONS, is_batch=True,
                          index=3, links=None, colors=None, align=None):
        l_rows = Result.prepend_row_index(rows)
        hdr = Result.get_header(rtype, is_batch)
        utils.write_html_table3(hdr, l_rows, filepath, links, colors, align, False)
        if rtype in [ReportType.FUNCTIONS, ReportType.TESTCASES]:
            png_file = os.path.splitext(filepath)[0]+'.png'
            Result.write_report_png(png_file, l_rows, index)

    @staticmethod
    def get_header(rtype=ReportType.FUNCTIONS, is_batch=True):
        return merge_cols[rtype] if is_batch else slave_cols[rtype]

    @staticmethod
    def get_color(pass_rate):
        color = "white"
        try:
            pass_rate = float(pass_rate.replace("%", ""))
            for r, c in colors_map.items():
                if pass_rate >= r:
                    color = c
                    break
        except Exception: pass
        return color

    @staticmethod
    def get_color_red(pass_rate, threshold=0.00):
        color = "white"
        try:
            pass_rate = float(str(pass_rate).replace("%", ""))
            if pass_rate > threshold: color = "red"
        except Exception: pass
        return color

