#!/usr/bin/python

DOCUMENTATION = '''
module:         console_facts
version_added:  "2.0"
author:         Jing Kan (jika@microsoft.com)
short_description: Retrieve console information from Quagga
description:
    - Retrieve console feature information from CONFIG_DB
    - Retrieve console status from show line command
    - Retrieved facts will be inserted into the 'console_facts' key
'''

class ConsoleModule(object):
    LINE_INDEX = 0
    BAUD_INDEX = 1
    FLCT_INDEX = 2
    RDEV_INDEX = 5

    STATUS_BUSY = "BUSY"
    STATUS_IDLE = "IDLE"

    STATUS_INDICATOR = "*"
    FLCT_ENABLED_TEXT = "Enabled"

    def __init__(self, include_remote_device_mapping = True):
        self.include_remote_device_mapping = include_remote_device_mapping
        self.module = AnsibleModule(argument_spec = dict())

    def run(self):
        """
        Main method of the class
        """
        self.module.exit_json(ansible_facts = {
            'console_facts' : self.get_console_facts()
        })

    def get_console_facts(self):
        """
        Retrieve console facts
        """
        facts = {
            "enabled" : self.get_console_feature_status()
        }

        if facts["enabled"]:
            facts["lines"] = self.get_console_lines_status()
            if self.include_remote_device_mapping:
                facts["remote_device_mapping"] = self.build_remote_device_mapping(facts["lines"])
        return facts

    def get_console_feature_status(self):
        """
        Retrieve console feature information
        """
        rt, out, err = self.module.run_command('sonic-db-cli CONFIG_DB HGET CONSOLE_SWITCH|console_mgmt enabled')
        if rt != 0:
            self.module.fail_json("Failed to get console feature status, rt={}, out={}, err={}".format(rt, out, err))
        return True if "yes" in out else False

    def get_console_lines_status(self):
        """
        Retrieve detailed console status
        """
        fields_line_index = 1
        skip_lines = 2
        result = {}

        # We only parse configured lines
        cmd = "show line -b"
        rt, out, err = self.module.run_command(cmd)
        if rt != 0:
            self.module.fail_json(msg = "Failed to get line information! {}".format(err))

        # Parse show line outputs
        lines = out.splitlines()
        if len(lines) == 0:
            self.module.fail_json(msg = "Failed to parse header from show line outputs")
            return None

        try:
            # 1. Extract field mask line according by fileds line
            fields_line = lines[fields_line_index]

            for line in lines[skip_lines:]:
                # 2. Extract fields for each line
                fields = []
                field = ""
                for i in range(len(fields_line)):
                    if i == len(line):
                        break
                    mask = fields_line[i]
                    if mask == '-':
                        field += line[i]
                    elif len(field) > 0:
                        fields.append(field.strip())
                        field = ""
                if len(field) > 0:
                    fields.append(field.strip())

                # 3. Construct line status
                line_status = {}
                line_status['state'] = self.STATUS_BUSY if self.STATUS_INDICATOR in fields[self.LINE_INDEX] else self.STATUS_IDLE
                line_status['baud_rate'] = int(fields[self.BAUD_INDEX])
                line_status['flow_control'] = True if fields[self.FLCT_INDEX] == self.FLCT_ENABLED_TEXT else False
                if len(fields) > self.RDEV_INDEX:
                    line_status['remote_device'] = fields[self.RDEV_INDEX]
                result[fields[self.LINE_INDEX].lstrip(self.STATUS_INDICATOR)] = line_status
            return result
        except Exception as e:
            self.module.fail_json(msg = "Failed to parse header from [{}] outputs: {}".format(cmd, str(e)))

    def build_remote_device_mapping(self, lines):
        """
        Build the mapping between remote device and line number
        """
        mapping = {}
        for line_num, line_status in lines.items():
            if "remote_device" in line_status and line_status["remote_device"]:
                mapping[line_status["remote_device"]] = line_num

def main():
    console_module = ConsoleModule()
    console_module.run()

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
