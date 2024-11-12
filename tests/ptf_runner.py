import ast
import pathlib
import pipes
import traceback
import logging
import allure
import json
from datetime import datetime
import os
import six

logger = logging.getLogger(__name__)


def ptf_collect(host, log_file, skip_pcap=False, dst_dir='./logs/ptf_collect/'):
    '''Collect PTF log and pcap files from PTF container to sonic-mgmt container.
    Optionally, save the files to a sub-directory in the destination.'''
    pos = log_file.rfind('.')
    filename_prefix = log_file[0:pos] if pos > -1 else log_file

    pos = filename_prefix.rfind('/') + 1
    rename_prefix = filename_prefix[pos:] if pos > 0 else filename_prefix
    suffix = str(datetime.utcnow()).replace(' ', '.')
    filename_log = dst_dir + rename_prefix + '.' + suffix + '.log'
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
        filename_pcap = dst_dir + rename_prefix + '.' + suffix + '.pcap.tar.gz'
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


def get_ptf_image_type(host):
    """
    The function queries the PTF image to determine
    if the image is of type 'mixed' or 'py3only'
    """
    pyvenv = host.stat(path="/root/env-python3/pyvenv.cfg")
    if pyvenv["stat"]["exists"]:
        return "mixed"
    return "py3only"


def get_test_path(testdir, testname):
    """
    Returns two values
    - first: the complete path of the test based on testdir and testname.
    - second: True if file is in 'py3' False otherwise
    Raises FileNotFoundError if file is not found
    """
    curr_path = os.path.dirname(os.path.abspath(__file__))
    base_path = pathlib.Path(curr_path).joinpath('..').joinpath('ansible/roles/test/files').joinpath(testdir)
    idx = testname.find('.')
    test_fname = testname + '.py' if idx == -1 else testname[:idx] + '.py'
    chk_path = base_path.joinpath('py3').joinpath(test_fname)
    if chk_path.exists():
        return chk_path, True
    chk_path = base_path.joinpath(test_fname)
    if chk_path.exists():
        return chk_path, False
    raise FileNotFoundError("Testdir: {} Testname: {} File: {} not found".format(testdir, testname, chk_path))


def is_py3_compat(test_fpath):
    """
    Returns True if the test can be run in a Python 3 environment
    False otherwise.
    """
    if six.PY2:
        raise Exception("must run in a Python 3 runtime")
    with open(test_fpath, 'rb') as f:
        code = f.read()
        try:
            ast.parse(code)
        except SyntaxError:
            return False
        return True
    # shouldn't get here
    return False


def ptf_runner(host, testdir, testname, platform_dir=None, params={},
               platform="remote", qlen=0, relax=True, debug_level="info",
               socket_recv_size=None, log_file=None,
               ptf_collect_dir="./logs/ptf_collect/",
               device_sockets=[], timeout=0, custom_options="",
               module_ignore_errors=False, is_python3=None, async_mode=False, pdb=False):

    dut_type = get_dut_type(host)
    kvm_support = params.get("kvm_support", False)
    if dut_type == "kvm" and kvm_support is False:
        logger.info("Skip test case {} for not support on KVM DUT".format(testname))
        return True

    cmd = ""
    ptf_img_type = get_ptf_image_type(host)
    logger.info('PTF image type: {}'.format(ptf_img_type))
    test_fpath, in_py3 = get_test_path(testdir, testname)
    logger.info('Test file path {}, in py3: {}'.format(test_fpath, in_py3))
    is_python3 = is_py3_compat(test_fpath)

    # The logic below automatically chooses the PTF binary to execute a test script
    # based on the container type "mixed" vs. "py3only".
    #
    # For "mixed" type PTF image the global environment has Python 2 and Python 2 compatible
    # ptf binary. Python 3 is part of a virtual environment under "/root/env-python3". All
    # packages and Python 3 compatible ptf binary is in the virtual environment.
    #
    # For "py3only" type PTF image the global environment has Python 3 only in the global
    # environment. Python 2 does not exist on this image and attempt to execute any
    # Python 2 PTF tests raises an exception.

    ptf_cmd = None
    if ptf_img_type == "mixed":
        if is_python3:
            ptf_cmd = '/root/env-python3/bin/ptf'
        else:
            ptf_cmd = '/usr/bin/ptf'
    else:
        if is_python3:
            ptf_cmd = '/usr/local/bin/ptf'
        else:
            err_msg = 'cannot run Python 2 test in a Python 3 only {} {}'.format(testdir, testname)
            raise Exception(err_msg)

    if in_py3:
        tdir = pathlib.Path(testdir).joinpath('py3')
        cmd = "{} --test-dir {} {}".format(ptf_cmd, tdir, testname)
    else:
        cmd = "{} --test-dir {} {}".format(ptf_cmd, testdir, testname)

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
        logger.info('ptf command: {}'.format(cmd))
        result = host.shell(cmd, chdir="/root", module_ignore_errors=module_ignore_errors, module_async=async_mode)
        if not async_mode:
            if log_file:
                ptf_collect(host, log_file, dst_dir=ptf_collect_dir)
            if result:
                allure.attach(json.dumps(result, indent=4), 'ptf_console_result', allure.attachment_type.TEXT)
        if module_ignore_errors:
            if result["rc"] != 0:
                return result
    except Exception:
        if log_file:
            ptf_collect(host, log_file, dst_dir=ptf_collect_dir)
        traceback_msg = traceback.format_exc()
        allure.attach(traceback_msg, 'ptf_runner_exception_traceback', allure.attachment_type.TEXT)
        logger.error("Exception caught while executing case: {}. Error message: {}".format(testname, traceback_msg))
        raise
    return True
