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
            - In CPU readiness mode, require this many consecutive low-CPU samples
        required: false
        default: 12
    process_name:
        description:
            - Exact process name to check in CPU readiness mode
        required: false
    cpu_threshold:
        description:
            - Maximum integer CPU percentage for every matching process
        required: false
    timeout:
        description:
            - Poll on the DUT until CPU readiness or this timeout in seconds
            - Return the last iterations samples, including when readiness times out
        required: false
"""

MonitResult = namedtuple('MonitResult', ['processes', 'memory'])


def monit_process(module, interval, iterations):
    """Retrieve process statistics."""

    def _monit_processes_with_top(module, interval, iterations):
        cmd = 'top -d {interval} -n {iterations} -b -E k -w 512'.format(
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
                line_match = mem_re.match(line.strip())
                if line_match is None:
                    module.fail_json(msg="Unable to parse top memory summary: {}".format(line))
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

    def _monit_processes_with_psutil(interval, iterations, process_name=None):
        def _poll(interval):
            time.sleep(interval)
            processes = []
            attrs = ['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'status']
            for proc in psutil.process_iter(['pid', 'name'] if process_name else attrs):
                if process_name and proc.info['name'] != process_name:
                    continue
                try:
                    processes.append(proc.as_dict(attrs) if process_name else proc.info)
                except psutil.NoSuchProcess:
                    module.warn("Process {} exited during CPU sampling".format(proc.pid))
            processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
            return processes

        _poll(0)
        count = 0
        while iterations is None or count < iterations:
            processes = _poll(interval)
            _mem = psutil.virtual_memory()
            memory = {
                "total": _mem.total / 1024,
                "free": _mem.available / 1024,
                "used": _mem.used / 1024,
                "used_percent": _mem.percent,
            }
            yield MonitResult(processes, memory)
            count += 1

    timeout = module.params.get("timeout")
    if timeout is not None:
        deadline = time.monotonic() + timeout
        samples = []
        consecutive = 0
        process_name = module.params["process_name"]
        sampler = _monit_processes_with_psutil(interval, None, process_name) if HAS_PSUTIL else None
        while time.monotonic() < deadline:
            if HAS_PSUTIL:
                sample = next(sampler)
            else:
                readings = _monit_processes_with_top(module, interval, 1)
                if len(readings) != 1:
                    module.fail_json(msg="Expected one CPU sample from top, received {}".format(len(readings)))
                sample = readings[0]
            matching = [proc for proc in sample.processes if proc["name"] == process_name]
            samples.append(MonitResult(matching, sample.memory))
            samples = samples[-iterations:]
            ready = bool(matching) and all(
                int(float(proc["cpu_percent"])) <= module.params["cpu_threshold"] for proc in matching
            )
            consecutive = consecutive + 1 if ready else 0
            if consecutive == iterations:
                break
        return dict(monit_results=samples, cpu_ready=consecutive == iterations)

    if HAS_PSUTIL:
        return dict(monit_results=list(_monit_processes_with_psutil(interval, iterations)))
    else:
        return dict(monit_results=_monit_processes_with_top(module, interval, iterations))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            delay_interval=dict(required=False, type=int, default=5),
            iterations=dict(require=False, type=int, default=6),
            process_name=dict(required=False, type=str),
            cpu_threshold=dict(required=False, type=int),
            timeout=dict(required=False, type=int),
        ),
        required_together=[["process_name", "cpu_threshold", "timeout"]],
    )
    interval = module.params["delay_interval"]
    iterations = module.params["iterations"]
    if module.params["timeout"] is not None:
        if (module.params["timeout"] <= 0 or interval <= 0 or iterations <= 0
                or module.params["cpu_threshold"] < 0 or not module.params["process_name"]):
            module.fail_json(msg="CPU readiness requires positive timeout, delay_interval and iterations, "
                                 "a nonempty process_name and a nonnegative cpu_threshold")
    module.exit_json(changed=False, **monit_process(module, interval, iterations))


if __name__ == "__main__":
    main()
