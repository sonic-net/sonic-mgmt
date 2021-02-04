import pytest
import paramiko
import threading
import logging
import time
import os
import yaml

from collections import OrderedDict
from  datetime import datetime
from errors import HDDThresholdExceeded, RAMThresholdExceeded, CPUThresholdExceeded


logger = logging.getLogger(__name__)
DUT_MONITOR = "/tmp/dut_monitor.py"
DUT_CPU_LOG = "/tmp/cpu.log"
DUT_RAM_LOG = "/tmp/ram.log"
DUT_HDD_LOG = "/tmp/hdd.log"


class DUTMonitorPlugin(object):
    """
    Pytest plugin which defines:
        - pytest fixtures: 'dut_ssh' and 'dut_monitor'
        - handlers to verify that measured CPU, RAM and HDD values during each test item execution
          does not exceed defined threshold
    """
    def __init__(self, thresholds):
        self.thresholds = thresholds

    @pytest.fixture(autouse=True, scope="module")
    def dut_ssh(self, duthosts, rand_one_dut_hostname, creds):
        """Establish SSH connection with DUT"""
        duthost = duthosts[rand_one_dut_hostname]
        ssh = DUTMonitorClient(host=duthost.hostname, user=creds["sonicadmin_user"],
                               password=creds["sonicadmin_password"])
        yield ssh

    @pytest.fixture(autouse=True, scope="function")
    def dut_monitor(self, dut_ssh, localhost, duthosts, rand_one_dut_hostname):
        """
        For each test item starts monitoring of hardware resources consumption on the DUT
        """
        duthost = duthosts[rand_one_dut_hostname]
        dut_thresholds = {}
        monitor_exceptions = []
        # Start monitoring on DUT
        dut_ssh.start()

        # Read file with defined thresholds
        with open(self.thresholds) as stream:
            general_thresholds = yaml.safe_load(stream)
        dut_thresholds = general_thresholds["default"]

        dut_platform = duthost.facts["platform"]
        dut_hwsku = duthost.facts["hwsku"]
        if dut_platform in general_thresholds:
            dut_thresholds.update(general_thresholds[dut_platform]["default"])
            if dut_hwsku in general_thresholds[dut_platform]["hwsku"]:
                dut_thresholds.update(general_thresholds[dut_platform]["hwsku"][dut_hwsku])

        yield dut_thresholds

        # Stop monitoring on DUT
        dut_ssh.stop()
        # Download log files with CPU, RAM and HDD measurements data
        measurements = dut_ssh.get_log_files()
        # Verify hardware resources consumption does not exceed defined threshold
        if measurements["hdd"]:
            try:
                self.assert_hhd(hdd_meas=measurements["hdd"], thresholds=dut_thresholds)
            except HDDThresholdExceeded as err:
                monitor_exceptions.append(err)

        if measurements["ram"]:
            try:
                self.assert_ram(ram_meas=measurements["ram"], thresholds=dut_thresholds)
            except RAMThresholdExceeded as err:
                monitor_exceptions.append(err)

        if measurements["cpu"]:
            try:
                self.assert_cpu(cpu_meas=measurements["cpu"], thresholds=dut_thresholds)
            except CPUThresholdExceeded as err:
                monitor_exceptions.append(err)

        if monitor_exceptions:
            raise Exception("\n".join(item.message for item in monitor_exceptions))

    def assert_hhd(self, hdd_meas, thresholds):
        """
        Verify that free disk space on the DUT is not overutilized
        """
        overused = []
        fail_msg = "Used HDD threshold - {}\nHDD overuse:\n".format(thresholds["hdd_used"])

        for timestamp, used_hdd in hdd_meas.items():
            if used_hdd > thresholds["hdd_used"]:
                overused.append((timestamp, used_hdd))

        if overused:
            raise HDDThresholdExceeded(fail_msg + "\n".join(str(item) for item in overused))

    def assert_ram(self, ram_meas, thresholds):
        """
        Verify that RAM resources on the DUT are not overutilized
        """
        failed = False
        peak_overused = []
        fail_msg = "\nRAM thresholds: peak - {}; before/after test difference - {}%\n".format(thresholds["ram_peak"],
                                                                                            thresholds["ram_delta"])

        for timestamp, used_ram in ram_meas.items():
            if used_ram > thresholds["ram_peak"]:
                peak_overused.append((timestamp, used_ram))
        if peak_overused:
            fail_msg = fail_msg + "RAM overuse:\n{}\n".format("\n".join(str(item) for item in peak_overused))
            failed = True

        # Take first and last RAM measurements
        if len(ram_meas) >= 4:
            before = sum(ram_meas.values()[0:2]) / 2
            after = sum(ram_meas.values()[2:4]) / 2
        else:
            before = ram_meas.values()[0]
            after = ram_meas.values()[-1]

        delta = thresholds["ram_delta"] / 100. * before
        if after >= before + delta:
            fail_msg = fail_msg + "RAM was not restored\nRAM before test {}; RAM after test {}\n".format(before, after)
            failed = True

        if failed:
            raise RAMThresholdExceeded(fail_msg)

    def assert_cpu(self, cpu_meas, thresholds):
        """
        Verify that CPU resources on the DUT are not overutilized
        """
        failed = False
        total_overused = []
        process_overused = {}
        cpu_thresholds = "CPU thresholds: total - {}; per process - {}; average - {}\n".format(thresholds["cpu_total"],
                                                            thresholds["cpu_process"],
                                                            thresholds["cpu_total_average"])
        average_cpu = "\n> Average CPU consumption during test run {}; Threshold - {}\n"
        fail_msg = ""
        total_sum = 0
        t_format = "%Y-%m-%d %H:%M:%S"

        def handle_process_measurements(p_name, t_first, t_last, p_average):
            """Compose fail message if process overuse CPU durig 'cpu_measure_duration' interval."""
            msg_template = "> Process '{}'\nAverage CPU overuse {} during {} seconds\n{}"
            duration = (t_last - t_first).total_seconds()

            if duration >= thresholds["cpu_measure_duration"]:
                return msg_template.format(process_name,
                                           p_average,
                                           duration,
                                           "{} - {}\n".format(t_first.strftime(t_format),
                                                              t_last.strftime(t_format)))
            return ""

        def handle_total_measurements(overused_list):
            """Compose fail message if CPU utilization exceeds threshold during 'duration' interval."""
            fail_msg = ""
            start = datetime.strptime(overused_list[0][0], t_format)
            end = datetime.strptime(overused_list[-1][0], t_format)

            if (end - start).total_seconds() >= thresholds["cpu_measure_duration"]:
                fail_msg = "Total CPU overuse during {} seconds.\n{}\n\n".format((end - start).total_seconds(),
                "\n".join([str(item) for item in overused_list])
                )
            del overused_list[0:]
            return fail_msg

        # Calculate total CPU utilization
        for m_id, timestamp in enumerate(cpu_meas):
            # Collect total CPU utilization to calculate total average
            total_sum += cpu_meas[timestamp]["total"]
            if cpu_meas[timestamp]["total"] > thresholds["cpu_total"]:
                total_overused.append((timestamp, cpu_meas[timestamp]["total"]))
                if m_id == (len(cpu_meas) - 1):
                    fail_msg += handle_total_measurements(total_overused)
                    total_overused = []
            elif total_overused:
                fail_msg += handle_total_measurements(total_overused)
                total_overused = []

            for process_consumption, process_name in cpu_meas[timestamp]["top_consumer"].items():
                if process_consumption >= thresholds["cpu_process"]:
                    if process_name not in process_overused:
                        process_overused[process_name] = []
                    # Collect list of CPU utilization for specific process if CPU utilization exceeds threshold
                    process_overused[process_name].append((timestamp, process_consumption))

        # Handle measurements per process
        if process_overused:
            for process_name, process_consumption in process_overused.items():
                timestamps = []
                process_sum = 0
                for m_id, m_value in enumerate(process_consumption):
                    t_stamp = datetime.strptime(m_value[0], t_format)
                    process_sum += m_value[1]
                    if not timestamps:
                        timestamps.append(t_stamp)
                        continue
                    if (2 <= (t_stamp - timestamps[-1]).total_seconds() <= 3):
                            timestamps.append(t_stamp)
                            if m_id == (len(process_consumption) - 1):
                                fail_msg += handle_process_measurements(p_name=process_name,
                                                                        t_first=timestamps[0],
                                                                        t_last=timestamps[-1],
                                                                        p_average=process_sum / len(timestamps))
                    else:
                        fail_msg += handle_process_measurements(p_name=process_name,
                                                                t_first=timestamps[0],
                                                                t_last=timestamps[-1],
                                                                p_average=process_sum / len(timestamps))
                        timestamps = []
                        process_sum = 0

        # Calculate average CPU utilization
        if (total_sum / len(cpu_meas)) > thresholds["cpu_total_average"]:
            fail_msg += average_cpu.format(total_sum / len(cpu_meas), thresholds["cpu_total_average"])

        if fail_msg:
            raise CPUThresholdExceeded(cpu_thresholds + fail_msg)


class DUTMonitorClient(object):
    """
    DUTMonitorClient object establish SSH connection with DUT. Keeps SSH connection with DUT during full test run.
    Available features:
        - start/stop hardware resources monitoring on DUT
        - automatically restart monitoring script on the DUT in case of lose network connectivity (device reboot, etc.)
    """
    def __init__(self, host, user, password):
        self.running = False
        self.user = user
        self.password = password
        self.host = host
        self.init()
        self.run_channel = None
        self._thread = threading.Thread(name="Connection tracker", target=self._track_connection)
        self._thread.setDaemon(True)
        self._thread.start()

    def _track_connection(self):
        """
        @summary: Track network connectivity. Reestablish network connection in case of drop connection
        """
        while True:
            try:
                self.ssh.exec_command("true", timeout=5)
            except (paramiko.SSHException, AttributeError):
                logger.warning("SSH connection dropped")
                logger.debug("Trying to reconnect...")
                self.close()
                try:
                    self.init()
                except Exception as err:
                    logger.debug(repr(err))
                else:
                    if self.running:
                        self.start()
            else:
                time.sleep(5)

    def _upload_to_dut(self):
        """
        @summary: Upload 'dut_monitor.py' module to the DUT '/tmp' folder
        """
        logger.debug("Uploading file to the DUT...")
        with self.ssh.open_sftp() as sftp:
            sftp.put(os.path.join(os.path.split(__file__)[0], "dut_monitor.py"), DUT_MONITOR)

    def init(self):
        """
        @summary: Connect to the DUT via SSH and authenticate to it.
        """
        logger.debug("Trying to establish connection ...")
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.host, username=self.user, password=self.password, timeout=5)

    def close(self):
        """
        @summary: Close this SSHClient and its underlying Transport
        """
        logger.debug("Close SSH connection with DUT")
        self.ssh.close()

    def exec_command(self, cmd, timeout=None):
        """
        @summary: Execute a command on the DUT and track possible connectivity issues.
                  A new Channel is opened and the requested command is executed
        """
        try:
            return self.ssh.exec_command(cmd, timeout=timeout, get_pty=True)
        except Exception as err:
            logger.warning("Broken connection - {}".format(repr(err)))
            logger.warning("Skip command {}".format(cmd))
            return (None, None, None)

    def start(self):
        """
        @summary: Start HW resources monitoring on the DUT.
                  Write obtained values to the following files on the DUT: DUT_CPU_LOG, DUT_RAM_LOG, DUT_HDD_LOG
        """
        self.running = True
        self._upload_to_dut()
        logger.debug("Start HW resources monitoring on the DUT...")

        self.run_channel = self.ssh.get_transport().open_session()
        self.run_channel.get_pty()
        self.run_channel.settimeout(5)
        # Start monitoring on DUT
        self.run_channel.exec_command("python {} --start".format(DUT_MONITOR))
        # Ensure monitoring started
        output = self.run_channel.recv(1024)
        if not "Started resources monitoring ..." in output:
            raise Exception("Failed to start monitoring on DUT: {}".format(output))

    def stop(self):
        """
        @summary: Close this SSHClient and its underlying Transport
        """
        self.running = False
        logger.debug("Stop resources monitoring on the DUT...")
        if not self.run_channel.closed:
            self.run_channel.close()

    def read_yml(self, file_pointer):
        """
        @summary: Read yaml file content. Convert it to the ordered data.
        @return: OrderedDict with sorted keys by timestamp, or empty dict for empty file.
        """
        with file_pointer as fp:
            measurements = yaml.safe_load("".join(fp))
        if measurements is None:
            return {}
        # Sort json data to process logs chronologically
        keys = measurements.keys()
        keys.sort()
        key_value_pairs = [(item, measurements[item]) for item in keys]
        return OrderedDict(key_value_pairs)

    def get_log_files(self):
        """
        @summary: Fetch monitoring logs from device, parse, convert to dictionary with sorted order.
        @return: Dictionary with keys "cpu", "ram", "hdd", values contains appropriate measurements made on DUT.
        """
        logger.debug("Downloading file from the DUT...")
        cpu_log_fp = self.ssh.open_sftp().file(DUT_CPU_LOG)
        ram_log_fp = self.ssh.open_sftp().file(DUT_RAM_LOG)
        hdd_log_fp = self.ssh.open_sftp().file(DUT_HDD_LOG)

        cpu_meas = self.read_yml(cpu_log_fp)
        ram_meas = self.read_yml(ram_log_fp)
        hdd_meas = self.read_yml(hdd_log_fp)
        return {"cpu": cpu_meas, "ram": ram_meas, "hdd": hdd_meas}
