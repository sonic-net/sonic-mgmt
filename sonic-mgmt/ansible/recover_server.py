#!/usr/bin/env python
"""
Script used to recover testbed servers after reboot/upgrade/black-out.
    - Cleanup server
    - Start vms
    - Add topos
    - Deploy minigraphs
"""
from __future__ import print_function
import argparse
import collections
import datetime
import imp
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time

from tabulate import tabulate
# Add tests path to syspath
sys.path.append('../')


ANSIBLE_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(ANSIBLE_DIR)


root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def parse_testbed(testbedfile, testbed_servers):
    """Return a dictionary containing mapping from server name to testbeds."""
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    testbeds = {server_name: list() for server_name in testbed_servers}
    for tbname, tb in testbed.TestbedInfo(testbedfile).testbed_topo.items():
        if tb['server'] in testbeds:
            testbeds[tb['server']].append(tb)
    return testbeds


class Task(object):
    """Wrapper class to call testbed-cli.sh."""

    def __init__(self, taskname, log_save_dir=None, tbfile=None, vmfile=None, vmtype=None, dry_run=False):
        self.taskname = taskname
        self.args = ['./testbed-cli.sh']
        if tbfile:
            self.args.extend(('-t', tbfile))
        if vmfile:
            self.args.extend(('-m', vmfile))
        if vmtype:
            self.args.extend(('-k', vmtype))
        self.log_save_dir = log_save_dir or tempfile.gettempdir()
        self.dry_run = dry_run
        self.returncode = None

    def __call__(self):
        logging.info('Start running task %s', self)
        logging.debug('task %s CMD: %s', self, ' '.join(self.args))

        if not self.dry_run:
            log_file = '%s.log' % self.taskname
            log_file = os.path.join(self.log_save_dir, log_file)
            with open(log_file, 'w') as lf:
                self._p = subprocess.Popen(args=self.args, stdout=lf, stderr=lf)
                logging.debug('task %s PID: %s', self, self._p.pid)
                self._p.communicate()
                self.returncode = self._p.returncode

        if self.dry_run or self.returncode == 0:
            logging.info('Finish running task %s', self)
        else:
            logging.error('Fail to run task %s', self)

    def __str__(self):
        return self.taskname


class TaskStartTopoVMs(Task):
    """Task start-topo-vms."""

    def __init__(self, tbname, passfile, log_save_dir, tbfile=None, vmfile=None, dry_run=False):
        Task.__init__(self, tbname + '_start_topo_vms', log_save_dir=log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=dry_run)
        self.args.extend(('start-topo-vms', tbname, passfile))
        self.tbname = tbname

class TaskStartVMs(Task):
    """Task start-vm"""

    def __init__(self, server, passfile, log_save_dir, tbfile=None, vmfile=None, dry_run=False):
        Task.__init__(self, server + '_start_vms', log_save_dir=log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=dry_run)
        self.args.extend(('start-vms', server, passfile))

class TaskAddTopo(Task):
    """Task add-topo."""

    def __init__(self, tbname, passfile, log_save_dir, tbfile=None, vmfile=None, vmtype=None, dry_run=False):
        Task.__init__(self, tbname + '_add_topo', log_save_dir=log_save_dir, tbfile=tbfile,
                      vmfile=vmfile, vmtype=vmtype, dry_run=dry_run)
        self.args.extend(('add-topo', tbname, passfile))
        self.tbname = tbname


class TaskDeployMG(Task):
    """Task deploy-mg."""

    def __init__(self, tbname, inventory, passfile, log_save_dir, tbfile=None, vmfile=None, dry_run=False):
        Task.__init__(self, tbname + '_deloy_mg', log_save_dir=log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=dry_run)
        self.args.extend(('deploy-mg', tbname, inventory, passfile))
        self.tbname = tbname


class TaskCleanupVMHosts(Task):
    """Task cleanup-vmhost."""

    def __init__(self, server, passfile, log_save_dir, tbfile=None, vmfile=None, dry_run=False):
        Task.__init__(self, server + '_cleanup_vmhost', log_save_dir=log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=dry_run)
        self.args.extend(('cleanup-vmhost', server, passfile))


class JobRuntimeError(Exception):
    pass


class Job(object):
    """Runs multiple Tasks."""

    def __init__(self, jobname, **kwargs):
        self.jobname = jobname
        self.failed_task = None
        self.dry_run = kwargs.get('dry_run', False)
        passfile = kwargs['passfile']
        tbfile = kwargs.get('tbfile')
        vmfile = kwargs.get('vmfile')
        vmtype = kwargs.get('vmtype')
        log_save_dir = kwargs.get('log_save_dir')
        if jobname == 'cleanup':
            server = kwargs['server']
            self.tasks = [
                TaskCleanupVMHosts(server, passfile, log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=self.dry_run)
            ]
            self.ignore_errors = False
        elif jobname == 'start-vms':
            server = kwargs['server']
            self.tasks = [
                TaskStartVMs(server, passfile, log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=self.dry_run)
            ]
            self.ignore_errors = False
        elif jobname == 'init_testbed':
            tbname = kwargs['tbname']
            inventory = kwargs['inventory']
            self.tasks = [
                TaskAddTopo(tbname, passfile, log_save_dir, tbfile=tbfile, vmfile=vmfile, vmtype=vmtype, dry_run=self.dry_run),
                TaskDeployMG(tbname, inventory, passfile, log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=self.dry_run)
            ]
            self.ignore_errors = True
            self.tbname = tbname

    def __call__(self):
        """
        Run the tasks in the job sequentially.

        If one task failed to finish with non-zero return code, all the tasks
        after will be skipped.
        """
        for task in self.tasks:
            task()
            if not self.dry_run and task.returncode != 0:
                self.failed_task = task
                break
        if self.failed_task is not None and not self.ignore_errors:
            raise JobRuntimeError


def do_jobs(testbeds, passfile, tbfile=None, vmfile=None, vmtype=None, skip_cleanup=False, dry_run=False):

    def _print_summary(jobs):
        server = threading.current_thread().name
        HEAD_LINE = '\n============= %s recovery summary =============\n' % server
        END_LINE = '\n' + ('=' * (len(HEAD_LINE) - 2)) + '\n'
        output = [HEAD_LINE]
        if not skip_cleanup:
            if jobs[0].failed_task is not None:
                output.append('Server %s cleanup failed, skip recovery.' % server)
            jobs = jobs[1:]

        if vmtype != 'ceos':
            # start-vms output. If vmtype is ceos, start-vms is not required
            if jobs[0].failed_task is None:
                start_vms_result = 'Succeed.'
            else:
                start_vms_result = 'Failed.'
            output.append('Server %s start-vms result: %s ' % (server, start_vms_result))
            jobs = jobs[1:]

        output.append('Server %s recovery result:' % server)
        headers = [server, 'add-topo', 'deploy-mg']
        table = []
        for job in jobs:
            line = [job.tbname, ]
            for task in job.tasks:
                if task.returncode is None:
                    line.append('skipped')
                elif task.returncode == 0:
                    line.append('passed')
                else:
                    line.append('failed')
            table.append(line)
        output.append(tabulate(table, headers, tablefmt='simple'))
        output.append(END_LINE)
        print('\n'.join(output))

    def _do_jobs(jobs):
        for job in jobs:
            try:
                job()
            except JobRuntimeError:
                # if one job raises JobRunTimeRrror signaling its failure,
                # we need to skip all jobs after. This enable us to skip all
                # those tasks after the server cleanup if cleanup fails.
                break

        _print_summary(jobs)

    def _join_all(threads):
        alive_threads = collections.deque(threads)
        while True:
            for _ in range(len(alive_threads)):
                alive_thread = alive_threads.popleft()
                alive_thread.join(timeout=0)
                if alive_thread.is_alive():
                    alive_threads.append(alive_thread)
            if not alive_threads:
                break
            time.sleep(5)

    utilities = imp.load_source('utilities', os.path.join(SONIC_MGMT_DIR, 'tests/common/utilities.py'))

    curr_date = datetime.datetime.today().strftime('%Y-%m-%d_%H-%M-%S')
    log_save_dir = os.path.join(tempfile.gettempdir(), 'recover_server_' + curr_date)
    logging.info('LOG PATH: %s', log_save_dir)
    threads = []
    for server, tbs in testbeds.items():
        log_save_dir_per_server = os.path.join(log_save_dir, server)
        os.makedirs(log_save_dir_per_server)
        jobs = [
            Job(
                'init_testbed',
                server=server,
                tbname=tb['conf-name'],
                inventory=tb['inv_name'],
                passfile=passfile,
                tbfile=tbfile,
                vmfile=vmfile,
                vmtype=vmtype,
                log_save_dir=log_save_dir_per_server,
                dry_run=dry_run
            ) for tb in tbs
        ]

        # only cEOS container doesn't need to start-vm
        need_start_vms = vmtype != 'ceos'

        if need_start_vms:
            jobs = [
                Job(
                    'start-vms',
                    server=server,
                    passfile=passfile,
                    tbfile=tbfile,
                    vmfile=vmfile,
                    log_save_dir=log_save_dir_per_server,
                    dry_run=dry_run
                )
            ] + jobs
        if not skip_cleanup:
            jobs = [
                Job(
                    'cleanup',
                    server=server,
                    passfile=passfile,
                    tbfile=tbfile,
                    vmfile=vmfile,
                    log_save_dir=log_save_dir_per_server,
                    dry_run=dry_run
                )
            ] + jobs
        thread = utilities.InterruptableThread(name=server, target=_do_jobs, args=(jobs,))
        thread.start()
        threads.append(thread)

    _join_all(threads)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Recover testbed servers.')
    parser.add_argument('--testbed-servers', action='append', type=str, required=True, help='testbed server to recover')
    parser.add_argument('--testbed', default='testbed.csv', help='testbed file(default: testbed.csv)')
    parser.add_argument('--vm-file', default='veos', help='vm inventory file(default: veos)')
    parser.add_argument('--vm-type', default='veos', choices=['veos', 'ceos', 'vsonic'], help='vm type (veos|ceos|vsonic, default: veos)')
    parser.add_argument('--inventory', help='Deprecated. Inventory info is already in testbed.(csv|yaml), no need to specify in argument')
    parser.add_argument('--passfile', default='password.txt', help='Ansible vault password file(default: password.txt)')
    parser.add_argument('--skip-cleanup', action='store_true', help='Skip cleanup server')
    parser.add_argument('--dry-run', action='store_true', help='Dry run')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warn', 'error', 'critical'], default='info', help='logging output level')
    args = parser.parse_args()

    servers = args.testbed_servers
    tbfile = args.testbed
    vmfile = args.vm_file
    vmtype = args.vm_type
    passfile = args.passfile
    skip_cleanup = args.skip_cleanup
    dry_run = args.dry_run
    log_level = args.log_level

    handler.setLevel(getattr(logging, log_level.upper()))

    testbeds = parse_testbed(tbfile, servers)
    do_jobs(testbeds, passfile, tbfile=tbfile, vmfile=vmfile, vmtype=vmtype, skip_cleanup=skip_cleanup, dry_run=dry_run)
