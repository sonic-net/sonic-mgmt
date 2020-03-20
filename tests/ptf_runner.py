import pipes

def ptf_runner(host, testdir, testname, platform_dir, params={}, \
               platform="remote", qlen=0, relax=True, debug_level="info", \
               socket_recv_size=None, log_file=None):

    ptf_test_params = ";".join(["{}={}".format(k, repr(v)) for k, v in params.items()])

    cmd = "ptf --test-dir {} {} --platform-dir {}".format(testdir, testname, platform_dir)
    if qlen:
        cmd += " --qlen={}".format(qlen)
    if platform:
        cmd += " --platform {}".format(platform)
    if ptf_test_params:
        cmd += " -t {}".format(pipes.quote(ptf_test_params))
    if relax:
        cmd += " --relax"
    if debug_level:
        cmd += " --debug {}".format(debug_level)
    if log_file:
        cmd += " --log-file {}".format(log_file)
    if socket_recv_size:
        cmd += " --socket-recv-size {}".format(socket_recv_size)

    res = host.shell(cmd, chdir="/root")


