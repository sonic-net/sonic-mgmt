#!/usr/bin/python
import re
import subprocess
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: sensors_facts
version_added: "0.2"
author: Pavel Shirshov (pavelsh@microsoft.com)
short_description: Retrieve sensors facts for a device. Set alarm if there is hardware alarm
description:
    - Checks are defined in ansible variables. Argument for the module is 'checks' with dictionary with parameters.
    - Retrieved facts will be inserted to the 'sensors' key.
    - Retrieved raw values will be inserted to the 'raw' key.
    - Recognized alarms will be inserted to the 'alarms' key.
    - 'alarm' key will be set to True if the device has any alarm situation.
    - If there's only one PSU on the device, 'warning' is set to True and 'warnings' have a message about it. 
    - sensors data: group_vars/sonic/sku-sensors/data.yml
'''

EXAMPLES = '''
# Gather sensors facts
 - name: Gather sensors
   sensors_facts: checks={{ sensors['Force10-S6000'] }}
 - name: Output of sensors information
   debug: var=vars['sensors']

'''

# Example of the source data
'''
acpitz-virtual-0
temp1:
  temp1_input: 26.800
  temp1_crit: 127.000
temp2:
  temp2_input: 26.800
  temp2_crit: 118.000
'''

class SensorsModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                checks=dict(required=True, type='dict'),
            )
        )

        self.checks = self.module.params['checks']

        self.stdout = None
        self.skip_devices = set()
        self.raw = {}
        self.alarms = {}
        self.warnings = []
        self.facts = {
            'raw': self.raw,
            'alarms': self.alarms,
            'warnings': self.warnings,
            'alarm': False,
            'warning': False,
        }

        return

    def run(self):
        '''
            Main method of the class
        '''
        self.collect_sensors()
        self.parse_sensors()
        self.psu_check()
        self.check_alarms()
        self.module.exit_json(ansible_facts={'sensors': self.facts})

        return

    def collect_sensors(self):
        '''
            Collect sensors by reading output of 'sensors' utility
        '''
        try:
            process = subprocess.Popen(['sensors', '-A', '-u'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
            self.stdout, stderr = process.communicate()
            ret_code = process.returncode
        except Exception as e:
            self.module.fail_json(msg=str(e))
        else:
            if ret_code != 0:
                self.module.fail_json(msg=stderr)

        return

    def parse_sensors(self):
        '''
            Parse 'sensors' utility output into the dictionary self.raw
        '''

        # Return true if the row is an empty line
        is_empty = lambda row: row == ''

        # Return true if the row is a row which represent device
        # ('acpitz-virtual-0' in the example above)
        is_device = lambda row: row[0] != ' ' and row[-1] != ':' and ':' not in row

        # Return true if the row is a row which represent a subsystem of the device
        # ('temp1:' in the example above)
        is_subsystem = lambda row: row[0] != ' ' and row[-1] == ':'

        # Return true if the row is a row which represent a sensor value
        # ('temp1_input: 26.800' in the example above)
        is_sensor = lambda row: row[0] == ' ' and row[-1] != ':' and ':' in row

        device = None
        subsystem = None
        for row in self.stdout.splitlines():
            if is_empty(row):
                continue
            elif is_device(row):
                device = {}
                self.raw[row] = device
            elif is_subsystem(row):
                subsystem = {}
                device[row[:-1]] = subsystem
            elif is_sensor(row):
                key, value = row.split(':')
                subsystem[key.strip()] = value.strip()

        return

    def psu_check(self):
        '''
            Check that both PSU are presented on the remote system.
            if it's not true, we set up self.skip_devices set with devices,
            which should be skipped during checks
        '''

        for dev, attrs in self.checks['psu_skips'].items():
            if dev not in self.raw:
                for idev in attrs['skip_list']:
                    self.skip_devices.add(idev)
                self.facts['warning'] = True
                self.warnings.append("PSU #%s [%s] is absent" % (attrs['number'], attrs['side']))

        return

    def get_raw_value(self, path):
        '''
            Get value in raw output in the path 'path'
        '''
        keys = path.split('/')

        cur_values = self.raw
        res = None
        for key in keys:
            pattern = re.compile(key)
            for cur_value in cur_values.keys():
                res = re.match(pattern, cur_value)
                if res is not None:
                    cur_values = cur_values[res.group()]
                    break
            if res is None:
                return None

        return cur_values

    def check_alarms(self):
        '''
            Calculate alarm situation using the lists
        '''

        # Return True if the value should be skipped
        skip_the_value = lambda path: path.split('/')[0] in self.skip_devices

        # check alarm lists
        for hw_part, alarm_list in self.checks['alarms'].items():
            reasons = '%s_reasons' % hw_part
            self.alarms[hw_part] = False
            self.alarms[reasons] = []
            for path in alarm_list:
                if skip_the_value(path):
                    continue
                value = self.get_raw_value(path)
                if value is None:
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Path %s is not exist' % path)
                elif value != '0.000':
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Alarm on %s' % path)

        # check compare lists
        for hw_part, compare_list in self.checks['compares'].items():
            reasons = '%s_reasons' % hw_part
            for (path_input, path_max) in compare_list:
                if skip_the_value(path_input):
                    continue                
                value_input = self.get_raw_value(path_input)
                value_max = self.get_raw_value(path_max)
                if value_input is None:
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Path %s is not exist' % path_input)
                elif value_max is None:
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Path %s is not exist' % path_max)
                elif float(value_input) >= float(value_max) :
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Alarm on %s' % path_input)

        # check not zero lists
        for hw_part, not_zero_list in self.checks['non_zero'].items():
            reasons = '%s_reasons' % hw_part
            for path in not_zero_list:
                if skip_the_value(path):
                    continue
                value = self.get_raw_value(path)
                if value is None:
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Path %s is not exist' % path)
                elif value == '0.000':
                    self.alarms[hw_part] = True
                    self.facts['alarm'] = True
                    self.alarms[reasons].append('Alarm on %s' % path)

        return

def main():
    sensors = SensorsModule()
    sensors.run()

    return

if __name__ == '__main__':
    main()
