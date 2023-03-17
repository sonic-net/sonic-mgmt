
def get_sai_attributes(duthost, ptfhost, dut_port, sai_values, clear_only=False):
    if ptfhost is None:
        return
    cmd = '''ptf --test-dir ixia_saitests/saitests sai_rpc_caller.RPC_Caller --platform-dir ixia_ptftests/ptftests/ --platform remote -t 'dutport={};port_map="0@0";server="{}";sai_values=[{}];clear_only={}' --relax --debug info --log-file log_file'''.format(int(dut_port[8:]), duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'], ",".join(['"{}"'.format(x) for x in sai_values]), clear_only)

    result = ptfhost.shell(cmd, chdir="/root", module_ignore_errors=True)

    if result['rc']:
        raise RuntimeError("Ptf runner is failing. Pls check if the DUT is running syncd-rpc image. (check netstat -an | grep 9092) :{}".format(result))
    else:
        print(("Got the values: {}".format(result['stdout_lines'])))
        return result['stdout_lines']
