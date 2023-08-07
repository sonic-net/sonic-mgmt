import sys
import os
import re
import json
from collections import OrderedDict

bundled_parser = os.getenv("SPYTEST_TEXTFSM_USE_BUNDLED_PARSER")
if bundled_parser:
    vendor_dir = os.path.join(os.path.dirname(__file__), '..', "vendor")
    sys.path.insert(0, os.path.abspath(vendor_dir))

import textfsm # noqa: E402
try:
    import clitable
except Exception:
    from textfsm import clitable

from spytest import env # noqa: E402
import utilities.common as utils # noqa: E402


class Template(object):

    def __init__(self, platform=None, cli=None, root=None):
        self.reinit(platform, cli, root)

    def reinit(self, platform=None, cli=None, root=None):
        root = root or env.get("SPYTEST_TEXTFSM_ROOT", "templates")
        basedir = os.path.join(os.path.dirname(__file__), '..', root)
        basedir = os.path.abspath(basedir)
        platform = env.get("SPYTEST_TEXTFSM_PLATFORM", platform)
        self.root = os.path.join(basedir, platform) if platform else basedir
        if not os.path.exists(self.root):
            self.root = basedir
        self.samples = os.path.join(self.root, 'test')
        index = env.get("SPYTEST_TEXTFSM_INDEX_FILENAME", platform or "index")
        self.cli_tables = OrderedDict()
        for index in index.split(","):
            if not os.path.exists(os.path.join(self.root, index)):
                index = "index"
            self.cli_tables[index] = clitable.CliTable(index, self.root)
        self.platform = platform
        self.cli = cli

    # find the template given command
    def get_tmpl(self, cmd):
        attrs = dict(Command=cmd)
        for cli_table in self.cli_tables.values():
            row_idx = cli_table.index.GetRowMatch(attrs)
            if row_idx != 0:
                return cli_table.index.index[row_idx]['Template']
        return None

    # retrieve template and sample file given the command
    def read_sample(self, cmd):
        tmpl_file = self.get_tmpl(cmd)
        if not tmpl_file:
            return ["NONE", ""]
        sample1 = re.sub(r"\s+", '_', re.sub(r"[^\w\s]", '', cmd))
        sample2 = os.path.splitext(tmpl_file)[0]
        txt_files = []
        txt_files.append(sample1 + ".txt")
        txt_files.append(sample2 + ".txt")
        for i in range(10):
            txt_files.append("{}_{}.txt".format(sample1, i))
        for i in range(10):
            txt_files.append("{}_{}.txt".format(sample2, i))
        for txt_file in txt_files:
            fp = os.path.join(self.samples, txt_file)
            if os.path.isfile(fp):
                fh = open(fp, 'r')
                data = fh.read()
                fh.close()
                return [tmpl_file, data]
        return [tmpl_file, ""]

    # find template the given command and apply on given data
    def apply(self, output, cmd):
        attrs = dict(Command=cmd)
        if self.platform:
            attrs["Platform"] = self.platform
        if self.cli:
            attrs["cli"] = self.cli
        try:
            tmpl_file = self.get_tmpl(cmd)
            if not tmpl_file:
                raise ValueError('Unknown command "%s"' % (cmd))
            for cli_table in self.cli_tables.values():
                cli_table.ParseCmd(output, attrs)
                objs = self.result(cli_table.header, cli_table)
                return [tmpl_file, objs]
        except clitable.CliTableError as e:
            raise ValueError('Unable to parse command "%s" - %s' % (cmd, str(e)))

    def result(self, header, rows):
        objs = []
        for row in rows:
            temp_dict = {}
            for index, element in enumerate(row):
                if index >= len(header):
                    print("HEADER: {} ROW: {}".format(header, row))
                temp_dict[header[index].lower()] = element
            objs.append(temp_dict)
        return objs

    def save_sample(self, tmpl, cmd, output, parsed, path=None):
        try:
            key = ",".join(parsed[0].keys())
            md5 = utils.md5(None, key)
            info_file = "{}.{}.info.log".format(tmpl, md5)
            info_file = os.path.join(path or self.samples, info_file)
            if not os.path.isfile(info_file):
                utils.write_file(info_file, "\n".join([tmpl, cmd, key, md5]), "a")
                data_file = info_file.replace(".info.log", ".data.log")
                utils.write_file(data_file, output)
        except Exception:
            print(utils.stack_trace(None, True))

    @staticmethod
    def get_samples(path=None, include=None):
        fpaths, include = [], include or ["*.info.log", "*.data.log"]
        for pattern in utils.make_list(include):
            fpaths.extend(utils.list_files_tree(path, pattern))
        return fpaths

    def verify_samples(self, path=None):
        results, path = [], path or self.samples
        for info_file in utils.list_files_tree(path, "*.info.log"):
            results.append([info_file, self.verify_sample(info_file, path)])
        return results

    def verify_sample(self, info_file, path=None):
        errs = []
        path = path or self.samples
        lines = utils.read_lines(info_file, [])
        for i in range(0, len(lines), 4):
            tmpl, cmd, key, md5 = [data.strip() for data in lines[i:i + 4]]
            data_file = os.path.join(path, "{}.{}.data.log".format(tmpl, md5))
            data_lines = utils.read_lines(data_file, [])
            t, parsed = self.apply("\n".join(data_lines), cmd)
            if t != tmpl:
                errs.append("{} is parsed by different template".format(info_file))
                continue
            k = ",".join(parsed[0].keys())
            if k != key:
                errs.append("{} produced different key".format(info_file))
                continue
        return errs

    # apply the given template on given data
    def apply_textfsm(self, tmpl_file, data):
        tmpl_file2 = os.path.join(self.root, tmpl_file)
        tmpl_fp = open(tmpl_file2, "r")
        re_table = textfsm.TextFSM(tmpl_fp)
        out = re_table.ParseText(data)
        tmpl_fp.close()
        objs = self.result(re_table.header, out)
        return re_table.header, objs


if __name__ == "__main__":
    template = Template()
    if len(sys.argv) <= 2:
        print("USAGE: template.py <command> <data file> [<template file>]")
        sys.exit(0)

    cmd, data_file = sys.argv[1:3]
    data = "\n".join(utils.read_lines(data_file))
    if len(sys.argv) > 3:
        tmpl = sys.argv[3]
        _, rv = template.apply_textfsm(tmpl, data)
    else:
        tmpl, rv = template.apply(data, cmd)
    print("TEXTFSM = {}".format(textfsm.__file__))
    print("============ Template: {}".format(tmpl))
    if env.get("SPYTEST_TEXTFSM_DUMP_INDENT_JSON", "0") == "0":
        # template.save_sample(tmpl, cmd, data, rv)
        for ent in rv:
            print(str(ent) + "\n")
        sys.exit(0)

    try:
        print(json.dumps(rv, indent=2))
    except Exception as exp:
        print("============ ERROR: {}".format(exp))
        print(rv)
