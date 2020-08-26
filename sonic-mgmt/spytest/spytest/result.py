import sys
import csv
import os

import utilities.common as utils

from spytest.st_time import get_timestamp
from spytest.datamap import DataMap

from .mail import send as email

slave_cols0 = ['#', 'Module', 'TestFunction', 'Result', 'TimeTaken',
              'ExecutedOn', 'Syslogs', 'FCLI', "TSSH", "DCNT", 'Description', "Devices"]
slave_cols1 = ['#', 'Feature', 'TestCase', 'Result',
              'ResultType', 'ExecutedOn', 'Description', 'Function', 'Module', "Devices"]
slave_cols2 = ['#', "Device", 'Module', 'TestFunction', 'LogMessage']
slave_cols3 = ["#", "Module", "Result", "Test Time", "INFRA Time (ms)", "CMD Time (ms)",
               "TG Time (ms)", "Wait(sec)", "TGWait(sec)", "PROMPT NFOUND", "Description"]

slave_cols = [slave_cols0, slave_cols1, slave_cols2, slave_cols3]
merge_cols0 = ['#', "Node", 'Module', 'TestFunction', 'Result',
              'TimeTaken', 'ExecutedOn', 'Syslogs', 'FCLI', "TSSH", "DCNT", 'Description', "Devices"]
merge_cols1 = ['#', "Node", 'Feature', 'TestCase', 'Result',
               'ResultType', 'ExecutedOn', 'Description', 'Function', 'Module', "Devices"]
merge_cols2 = ['#', "Node", "Device", 'Module', 'TestFunction', 'LogMessage']
merge_cols3 = ["#", "Node", "Module", "Result", "Test Time", "INFRA Time (ms)", "CMD Time (ms)",
                "TG Time (ms)", "Wait(sec)", "TGWait(sec)", "PROMPT NFOUND", "Description"]
merge_cols = [merge_cols0, merge_cols1, merge_cols2, merge_cols3]

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
        self.report_csv[0] = "{}_result.csv".format(prefix)
        self.report_csv[1] = "{}_tcresult.csv".format(prefix)
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
        except:
            raise ValueError("expected arguments not provided")

        return rv

    def set_default_error(self, res, code, *args):
        self.default_result = res
        try:
            if code:
                self.default_desc = self.build_msg(code, *args)
            else:
                self.default_desc = None
        except Exception as e:
            print(e)
            self.default_desc = "Invalid error code {} : {}".format(code, e)
            self.default_result = "Fail"
        return self.default_desc

    def set(self, res, code, *args):
        if self.result and self.result != "Pass":
            msg = "result already set to {} -- ignoring".format(self.result)
            print(msg)
            return msg
        self.result = res
        try:
            self.desc = self.build_msg(code, *args)
        except Exception as e:
            print(e)
            self.desc = "Invalid error code {} : {}".format(code, e)
            self.result = "Fail"
        return self.desc

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
                "Module": nodeid.split(':')[0],
                "Devices": " ".join(dut_list),
            }
        else:
            rcdict = {
                "#": self.count[index],
                "Module": nodeid.split(':')[0],
                "TestFunction": func,
                "Result": result,
                "ExecutedOn": executedOn,
                "TimeTaken": time_taken,
                "Syslogs": syslog_count,
                "FCLI": fcli,
                "TSSH": tryssh,
                "DCNT": len(dut_list),
                "Description": desc,
                "Devices": " ".join(dut_list),
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
            for devname, msgtype, syslog in syslogs:
                func = func if func else msgtype
                self.count[index] = self.count[index] + 1
                d = {
                    "#": self.count[index],
                    "Device": devname,
                    "Module": nodeid.split(':')[0],
                    "TestFunction": func,
                    "LogMessage": syslog,
                    }
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
        if os.getenv("SPYTEST_RESULTS_PREFIX"):
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
        except:
            #print("failed to open {} to read".format(filepath))
            pass

        return rows

    @staticmethod
    def write_report_csv(filepath, rows, rtype, is_batch=True, append=False):
        if append:
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
    def write_report_html(filepath, rows, rtype=0, is_batch=True, index=3):
        l_rows = Result.prepend_row_index(rows)
        if is_batch:
            utils.write_html_table(merge_cols[rtype], l_rows, filepath)
        else:
            utils.write_html_table(slave_cols[rtype], l_rows, filepath)
        if rtype in [0, 1]:
            png_file = os.path.splitext(filepath)[0]+'.png'
            Result.write_report_png(png_file, l_rows, index)

