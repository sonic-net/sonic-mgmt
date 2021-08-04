import argparse
import logging
import imp
import os
import recover_server
import sys
import collections
import datetime
import time
import tempfile

# Add tests path to syspath
sys.path.append('../')


ANSIBLE_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(ANSIBLE_DIR)


class TaskRestartPTF(recover_server.Task):
    """Task restart-ptf."""
    def __init__(self, tbname, passfile, log_save_dir, tbfile=None, vmfile=None, dry_run=False):
        recover_server.Task.__init__(self, tbname + '_restart_ptf', log_save_dir=log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=dry_run)
        self.args.extend(('restart-ptf', tbname, passfile))
        self.tbname = tbname


class JobRuntimeError(Exception):
    pass


class Job(object):
    """Runs multiple Tasks."""

    def __init__(self, jobname, **kwargs):
        self.jobname = jobname
        self.failed_task = None
        self.dry_run = kwargs.get('dry_run', False)
        self.ignore_errors = True
        passfile = kwargs['passfile']
        tbfile = kwargs.get('tbfile')
        vmfile = kwargs.get('vmfile')
        log_save_dir = kwargs.get('log_save_dir')
        tbname = kwargs['tbname']
        self.tasks = [
            TaskRestartPTF(tbname, passfile, log_save_dir, tbfile=tbfile, vmfile=vmfile, dry_run=self.dry_run)
        ]

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


def parse_testbed(testbedfile, servers):
    """Return a dictionary containing mapping from server name to nightly testbeds that need restart-ptf."""
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    all_testbeds = testbed.TestbedInfo(testbedfile).testbed_topo
    nightly_dir = os.path.join(SONIC_MGMT_DIR, ".azure-pipelines", "nightly")
    nightly_testbeds = []
    for _, _, files in os.walk(nightly_dir):
        nightly_testbeds.extend(_.split(".")[0] for _ in files if _.startswith("vms") and _.endswith("yml"))
    nightly_testbeds = list(set(nightly_testbeds))
    nightly_testbeds.sort()
    should_restart = collections.defaultdict(list)
    for tbname in set(nightly_testbeds):
        if tbname not in all_testbeds:
            logging.error("Failed to find testbed %s from testbed file %s", tbname, testbedfile)
            continue
        server = all_testbeds[tbname]["server"]
        if "ptf" in all_testbeds[tbname]["ptf_image_name"]:
            should_restart[server].append(tbname)
    if servers:
        return {s: should_restart[s] for s in servers}
    return dict(should_restart)
    


def do_jobs(testbeds, passfile, tbfile=None, vmfile=None, dry_run=False):

    def _do_jobs(jobs):
        for job in jobs:
            try:
                job()
            except JobRuntimeError:
                # if one job raises JobRunTimeRrror signaling its failure,
                # we need to skip all jobs after. This enable us to skip all
                # those tasks after the server cleanup if cleanup fails.
                break

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
    for server, tbnames in testbeds.items():
        log_save_dir_per_server = os.path.join(log_save_dir, server)
        os.makedirs(log_save_dir_per_server)
        jobs = [
            Job(
                "restart-ptf",
                server=server,
                tbname=tbname,
                passfile=passfile,
                tbfile=tbfile,
                vmfile=vmfile,
                log_save_dir=log_save_dir_per_server,
                dry_run=dry_run
            ) for tbname in tbnames
        ]
        thread = utilities.InterruptableThread(name=server, target=_do_jobs, args=(jobs,))
        thread.start()
        threads.append(thread)

    _join_all(threads)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Recover testbed servers.')
    parser.add_argument('--testbed-servers', default=[], action='append', type=str, required=True, help='testbed server to recover')
    parser.add_argument('--testbed', default='testbed.yaml', help='testbed file(default: testbed.yaml)')
    parser.add_argument('--vm-file', default='veos', help='vm inventory file(default: veos)')
    parser.add_argument('--passfile', default='password.txt', help='Ansible vault password file(default: password.txt)')
    parser.add_argument('--dry-run', action='store_true', help='Dry run')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warn', 'error', 'critical'], default='info', help='logging output level')
    args = parser.parse_args()

    servers = args.testbed_servers
    tbfile = args.testbed
    vmfile = args.vm_file
    passfile = args.passfile
    dry_run = args.dry_run
    log_level = args.log_level

    recover_server.handler.setLevel(getattr(logging, log_level.upper()))

    testbeds = parse_testbed(tbfile, servers)
    do_jobs(testbeds, passfile, tbfile=tbfile, vmfile=vmfile, dry_run=dry_run)
