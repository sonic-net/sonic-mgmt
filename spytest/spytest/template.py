import sys
import os
import re
import json

import textfsm
try:
    import clitable
except Exception:
    import textfsm.clitable as clitable

import spytest.env as env

class Template(object):

    def __init__(self, platform=None, cli=None):
        self.reinit(platform, cli)

    def reinit(self, platform=None, cli=None):
        self.root = os.path.join(os.path.dirname(__file__), '..', 'templates')
        self.samples = os.path.join(self.root, 'test')
        index_file = env.get("SPYTEST_TEXTFSM_INDEX_FILENAME", "index")
        self.cli_table = clitable.CliTable(index_file, self.root)
        self.platform = platform
        self.cli = cli

    # find the template given command
    def get_tmpl(self, cmd):
        attrs = dict(Command=cmd)
        row_idx = self.cli_table.index.GetRowMatch(attrs)
        if row_idx == 0:
            return None
        return self.cli_table.index.index[row_idx]['Template']

    # retrive template and sameple file given the command
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
        if self.platform: attrs["Platform"] = self.platform
        if self.cli: attrs["cli"] = self.cli
        try:
            self.cli_table.ParseCmd(output, attrs)
            objs = []
            for row in self.cli_table:
                temp_dict = {}
                for index, element in enumerate(row):
                    if index >= len(self.cli_table.header):
                        print("HEADER: {} ROW: {}".format(self.cli_table.header, row))
                    temp_dict[self.cli_table.header[index].lower()] = element
                objs.append(temp_dict)
            tmpl_file = self.get_tmpl(cmd)
            return [tmpl_file, objs]
        except clitable.CliTableError as e:
            raise Exception('Unable to parse command "%s" - %s' % (cmd, str(e)))

    # apply the given template on given data
    def apply_textfsm(self, tmpl_file, data):
        tmpl_file2 = os.path.join(self.root, tmpl_file)
        tmpl_fp = open(tmpl_file2, "r")
        out = textfsm.TextFSM(tmpl_fp).ParseText(data)
        tmpl_fp.close()
        return out

if __name__ == "__main__":
    template = Template()
    if len(sys.argv) <= 2:
        print("USAGE: template.py <template file> <data file>")
        sys.exit(0)

    f = open(sys.argv[2], "r")
    tmpl, rv = template.apply(f.read(), sys.argv[1])
    print("============ Template: {}".format(tmpl))
    if env.get("SPYTEST_TEXTFSM_DUMP_INDENT_JSON", "0") == "0":
        print (rv)
        sys.exit(0)

    try:
        print(json.dumps(rv, indent=2))
    except Exception as exp:
        print("============ ERROR: {}".format(exp))
        print (rv)

