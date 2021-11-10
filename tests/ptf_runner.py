import pipes
import traceback
import logging

logger = logging.getLogger(__name__)


def ptf_runner(host, testdir, testname, platform_dir=None, params={},
               platform="remote", qlen=0, relax=True, debug_level="info",
               socket_recv_size=None, log_file=None, device_sockets=[], timeout=0,
               module_ignore_errors=False):

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

    try:
        result = host.shell(cmd, chdir="/root", module_ignore_errors=module_ignore_errors)
        if module_ignore_errors:
            if result["rc"] != 0:
                return result
    except Exception:
        traceback_msg = traceback.format_exc()
        logger.error("Exception caught while executing case: {}. Error message: {}"\
            .format(testname, traceback_msg))
        raise Exception
    return True
