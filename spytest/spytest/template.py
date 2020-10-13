import sys
import os

import textfsm
try:
    import clitable
except:
    import textfsm.clitable as clitable


class Template(object):
    """
    todo: Update Documentation
    """

    def __init__(self, platform=None):
        """
        Construction of Template object
        """
        self.root = os.path.join(os.path.dirname(__file__), '..', 'templates')
        self.samples = os.path.join(self.root, 'test')
        self.cli_table = clitable.CliTable('index', self.root)
        self.platform = platform

    def read_sample(self, cmd):
        try:
            attrs = dict(Command=cmd)
            row_idx = self.cli_table.index.GetRowMatch(attrs)
            template = self.cli_table.index.index[row_idx]['Template']
            sample = os.path.splitext(template)[0]+'.txt'
            sample = os.path.join(self.samples, sample)
            fh = open(sample, 'r')
            data = fh.read()
            fh.close()
            return data
        except:
            return ""

    def apply(self, output, cmd):
        """
        todo: Update Documentation
        :param output:
        :type output:
        :param cmd:
        :type cmd:
        :return:
        :rtype:
        """
        attrs = dict(Command=cmd)
        if self.platform: attrs["Platform"] = self.platform
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
            return objs
        except clitable.CliTableError as e:
            raise Exception('Unable to parse command "%s" - %s' % (cmd, str(e)))

    def apply_textfsm(self, tmpl_file, data):
        """
        todo: Update Documentation
        :param tmpl_file:
        :type tmpl_file:
        :param data:
        :type data:
        :return:
        :rtype:
        """
        tmpl_file2 = os.path.join(self.root, tmpl_file)
        tmpl_fp = open(tmpl_file2, "r")
        out = textfsm.TextFSM(tmpl_fp).ParseText(data)
        tmpl_fp.close()
        return out

if __name__ == "__main__":
    template = Template()
    if len(sys.argv) > 2:
        f = open(sys.argv[2], "r")
        rv = template.apply(f.read(), sys.argv[1])
    else:
        f = open(sys.argv[1], "r")
        rv = template.apply_textfsm("unix_ifcfg.tmpl", f.read())
    print (rv)

