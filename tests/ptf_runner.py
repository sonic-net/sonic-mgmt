import pipes
import traceback
import logging
import allure
import json
from datetime import datetime

logger = logging.getLogger(__name__)


def ptf_collect(host, log_file, skip_pcap=False):
    pos = log_file.rfind('.')
    filename_prefix = log_file[0:pos] if pos > -1 else log_file

    pos = filename_prefix.rfind('/') + 1
    rename_prefix = filename_prefix[pos:] if pos > 0 else filename_prefix
    suffix = str(datetime.utcnow()).replace(' ', '.')
    filename_log = './logs/ptf_collect/' + rename_prefix + '.' + suffix + '.log'
    host.fetch(src=log_file, dest=filename_log, flat=True, fail_on_missing=False)
    allure.attach.file(filename_log, 'ptf_log: ' + filename_log, allure.attachment_type.TEXT)
    if skip_pcap:
        return
    pcap_file = filename_prefix + '.pcap'
    output = host.shell("[ -f {} ] && echo exist || echo null".format(pcap_file))['stdout']
    if output == 'exist':
        # Compress the file
        compressed_pcap_file = pcap_file + '.tar.gz'
        host.archive(path=pcap_file, dest=compressed_pcap_file, format='gz')
        # Copy compressed file from ptf to sonic-mgmt
        filename_pcap = './logs/ptf_collect/' + rename_prefix + '.' + suffix + '.pcap.tar.gz'
        host.fetch(src=compressed_pcap_file, dest=filename_pcap, flat=True, fail_on_missing=False)
        allure.attach.file(filename_pcap, 'ptf_pcap: ' + filename_pcap, allure.attachment_type.PCAP)


def get_dut_type(host):
    dut_type_stat = host.stat(path="/sonic/dut_type.txt")
    if dut_type_stat["stat"]["exists"]:
        dut_type = host.shell("cat /sonic/dut_type.txt")["stdout"]
        if dut_type:
            logger.info("DUT type is {}".format(dut_type))
            return dut_type.lower()
        else:
            logger.warning("DUT type file is empty.")
    else:
        logger.warning("DUT type file doesn't exist.")
    return "Unknown"


def ptf_runner(host, testdir, testname, platform_dir=None, params={},
               platform="remote", qlen=0, relax=True, debug_level="info",
               socket_recv_size=None, log_file=None, device_sockets=[], timeout=0, custom_options="",
               module_ignore_errors=False, is_python3=False, async_mode=False, pdb=False):
    # Call virtual env ptf for migrated py3 scripts.
    # ptf will load all scripts under ptftests, it will throw error for py2 scripts.
    # So move migrated scripts to seperated py3 folder avoid impacting py2 scripts.
    dut_type = get_dut_type(host)
    if dut_type == "kvm" and params.get("kvm_support", True) is False:
        logger.info("Skip test case {} for not support on KVM DUT".format(testname))
        return True

    if is_python3:
        path_exists = host.stat(path="/root/env-python3/bin/ptf")
        if path_exists["stat"]["exists"]:
            cmd = "/root/env-python3/bin/ptf --test-dir {} {}".format(testdir + '/py3', testname)
        else:
            error_msg = "Virtual environment for Python3 /root/env-python3/bin/ptf doesn't exist.\n" \
                        "Please check and update docker-ptf image, make sure to use the correct one."
            logger.error("Exception caught while executing case: {}. Error message: {}".format(testname, error_msg))
            raise Exception(error_msg)
    else:
        cmd = "ptf --test-dir {} {}".format(testdir, testname)

    if platform_dir:
        cmd += " --platform-dir {}".format(platform_dir)

    if qlen:
        cmd += " --qlen={}".format(qlen)

    if platform:
        cmd += " --platform {}".format(platform)

    if params:
        ptf_test_params = ";".join(["{}={}".format(k, repr(v)) for k, v in list(params.items())])
        cmd += " -t {}".format(pipes.quote(ptf_test_params))

    if relax:
        cmd += " --relax"

    if debug_level:
        cmd += " --debug {}".format(debug_level)

    if log_file:
        cmd += " --log-file {}".format(log_file)

    if socket_recv_size:
        cmd += " --socket-recv-size {}".format(socket_recv_size)

    if device_sockets:
        cmd += " ".join(map(" --device-socket {}".format, device_sockets))

    if timeout and not pdb:
        cmd += " --test-case-timeout {}".format(int(timeout))

    if custom_options:
        cmd += " " + custom_options

    if hasattr(host, "macsec_enabled") and host.macsec_enabled:
        if not is_python3:
            logger.error("MACsec is only available in Python3")
            raise Exception("MACsec is only available in Python3")
        host.create_macsec_info()

    try:
        if pdb:
            # Write command to file. Use short test name for simpler launch in ptf container.
            script_name = "/tmp/" + testname.split(".")[-1] + ".sh"
            with open(script_name, 'w') as f:
                f.write(cmd)
            host.copy(src=script_name, dest="/root/")
            print("Run command from ptf: sh {}".format(script_name))
            import pdb
            pdb.set_trace()
        result = host.shell(cmd, chdir="/root", module_ignore_errors=module_ignore_errors, module_async=async_mode)
        if not async_mode:
            if log_file:
                ptf_collect(host, log_file)
            if result:
                allure.attach(json.dumps(result, indent=4), 'ptf_console_result', allure.attachment_type.TEXT)
        if module_ignore_errors:
            if result["rc"] != 0:
                return result
    except Exception:
        if log_file:
            ptf_collect(host, log_file)
        traceback_msg = traceback.format_exc()
        allure.attach(traceback_msg, 'ptf_runner_exception_traceback', allure.attachment_type.TEXT)
        logger.error("Exception caught while executing case: {}. Error message: {}".format(testname, traceback_msg))
        raise
    return True
