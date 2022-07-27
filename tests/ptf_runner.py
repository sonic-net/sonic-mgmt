import pipes
import traceback
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def ptf_collect(host, log_file):
    pos = log_file.rfind('.')
    filename_prefix = log_file[0:pos] if pos > -1 else log_file

    pos = log_file.rfind('/') + 1
    rename_prefix = log_file[pos:] if pos > 0 else log_file

    host.fetch(src=log_file, dest='./logs/ptf_collect/' + rename_prefix + '.' + str(datetime.utcnow()) + '.log', flat=True, fail_on_missing=False)

    pcap_file = filename_prefix + '.pcap'
    output = host.shell("[ -f {} ] && echo exist || echo null".format(pcap_file))['stdout']
    if output == 'exist':
        host.fetch(src=pcap_file, dest='./logs/ptf_collect/' + rename_prefix + '.' + str(datetime.utcnow()) + '.pcap', flat=True, fail_on_missing=False)

def ptf_runner(host, testdir, testname, platform_dir=None, params={},
               platform="remote", qlen=0, relax=True, debug_level="info",
               socket_recv_size=None, log_file=None, device_sockets=[], timeout=0,
               module_ignore_errors=False, is_python3=False):
    # Call virtual env ptf for migrated py3 scripts.
    # ptf will load all scripts under ptftests, it will throw error for py2 scripts.
    # So move migrated scripts to seperated py3 folder avoid impacting py2 scripts.
    if is_python3:
        path_exists = host.stat(path="/root/env-python3/bin/ptf")
        if path_exists["stat"]["exists"]:
            cmd = "/root/env-python3/bin/ptf --test-dir {} {}".format(testdir+'/py3', testname)
        else:
            error_msg = "Virtual environment for Python3 /root/env-python3/bin/ptf doesn't exist.\nPlease check and update docker-ptf image, make sure to use the correct one."
            logger.error("Exception caught while executing case: {}. Error message: {}"\
            .format(testname, error_msg))
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
        ptf_test_params = ";".join(["{}={}".format(k, repr(v)) for k, v in params.items()])
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

    if timeout:
        cmd += " --test-case-timeout {}".format(int(timeout))

    if hasattr(host, "macsec_enabled") and host.macsec_enabled:
        if not is_python3:
            logger.error("MACsec is only available in Python3")
            raise Exception
        host.create_macsec_info()

    try:
        result = host.shell(cmd, chdir="/root", module_ignore_errors=module_ignore_errors)
        if log_file:
            ptf_collect(host, log_file)
        if module_ignore_errors:
            if result["rc"] != 0:
                return result
    except Exception:
        if log_file:
            ptf_collect(host, log_file)
        traceback_msg = traceback.format_exc()
        logger.error("Exception caught while executing case: {}. Error message: {}"\
            .format(testname, traceback_msg))
        raise Exception
    return True
