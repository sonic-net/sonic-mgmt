#!/usr/bin/python
# -*- coding: utf-8 -*-
import operator
try:
    import psutil
except ImportError:
    HAS_PSUTIL = False
else:
    HAS_PSUTIL = True
import re
import time
from ansible.module_utils.basic import AnsibleModule
from collections import namedtuple

DOCUMENTATION = """
module: monit_process
short_description: retrieve process cpu and memory usage
description:
    - Retrieve process cpu and memory usage for a given period
version_added: "2.8"
options:
    delay_interval:
        description:
            - Specify the delay interval between each polling(in seconds)
        required: false
        default: 5
    iterations:
        description:
            - Specify the maximum number of polling iterations
        required: false
        default: 12
"""

MonitResult = namedtuple('MonitResult', ['processes', 'memory'])


def monit_process(module, interval, iterations):
    """Retrieve process statistics."""

    def _monit_processes_with_top(module, interval, iterations):
        cmd = 'top -d {interval} -n {iterations} -b -E k'.format(
            interval=interval, iterations=(iterations + 1)
            )
        rc, stdout, _ = module.run_command(args=cmd)

        monit_results = []
        proc_section = False
        mem_re = re.compile(
            (r"^KiB Mem\s+:\s+(?P<total>\d+)\s+total,\s+(?P<free>\d+)"
             r"\s+free,\s+(?P<used>\d+)\s+used,\s+\d+\s+buff/cache$")
        )
        mem_attrs = ('total', 'free', 'used')
        proc_attrs = ('pid', 'status', 'cpu_percent', 'memory_percent', 'name')
        proc_attrs_getter = operator.itemgetter(0, 7, 8, 9, 11)
        for line in stdout.splitlines():
            if not line:
                proc_section = False
            elif line.startswith('top'):
                monit_results.append(MonitResult([], {}))
            elif line.startswith('KiB Mem'):
                line_match = mem_re.match(line)
                values = (line_match.group(_) for _ in mem_attrs)
                memory = {k: int(v) for k, v in zip(mem_attrs, values)}
                used_percent = memory['used'] * 100 / float(memory['total'])
                memory['used_percent'] = round(used_percent, 2)
                monit_results[-1].memory.update(memory)
            elif "PID" in line:
                proc_section = True
            elif proc_section:
                process = dict(
                    zip(proc_attrs, proc_attrs_getter(line.split()))
                    )
                process['cpu_percent'] = float(process['cpu_percent'])
                process['memory_percent'] = float(process['memory_percent'])
                process['pid'] = int(process['pid'])
                monit_results[-1].processes.append(process)

        monit_results = monit_results[1:]
        return monit_results

    def _monit_processes_with_psutil(interval, iterations):
        def _poll(interval):
            time.sleep(interval)
            processes = []
            for proc in psutil.process_iter(['pid', 'name',
                                             'cpu_percent',
                                             'memory_percent',
                                             'status']):
                processes.append(proc.info)
            processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
            return processes

        _poll(0)
        monit_results = []
        for _ in range(iterations):
            processes = _poll(interval)
            _mem = psutil.virtual_memory()
            memory = {
                "total": _mem.total / 1024,
                "free": _mem.available / 1024,
                "used": _mem.used / 1024,
                "used_percent": _mem.percent,
            }
            monit_results.append(MonitResult(processes, memory))
        return monit_results

    if HAS_PSUTIL:
        return _monit_processes_with_psutil(interval, iterations)
    else:
        return _monit_processes_with_top(module, interval, iterations)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            delay_interval=dict(required=False, type=int, default=5),
            iterations=dict(require=False, type=int, default=6),
        )
    )
    interval = module.params["delay_interval"]
    iterations = module.params["iterations"]
    module.exit_json(
        monit_results=monit_process(module, interval, iterations),
        changed=False
        )


if __name__ == "__main__":
    main()
