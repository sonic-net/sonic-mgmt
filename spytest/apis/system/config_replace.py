from spytest import st


try:
    import apis.yang.codegen.messages.file_mgmt_private.FileMgmtPrivateRpc as umf_file
    from apis.yang.codegen.yang_rpc_service import YangRpcService
except ImportError:
    pass


def config_replace(dut, src_path, **kwargs):
    '''
    Author: Chandra sekhar Reddy (chandra.vedanaparthi@broadcom.com)
    Purpose: This apis is used to replace the running config
    :param dut:
    :return:
    Example:
    config_replace(dut,"config://filename")
    config_replace(dut,"ftp://userid:passwd@hostip/filepath")
    config_replace(dut,"home://filename")
    config_replace(dut,"http://hostip/filepath")
    config_replace(dut,"scp://userid:passwd@hostip/filepath")
    config_replace(dut,"usb://filename")
    '''

    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", False)
    st.log('source path : {}'.format(src_path))
    if cli_type == 'klish' or cli_type == 'click':
        my_cmd = 'copy {} running-configuration replace\n'.format(src_path)
        output = st.config(dut, my_cmd, confirm='Y', type="klish", skip_error_check=skip_error_check)
        if "Error" in output:
            return False
        else:
            return True
    elif cli_type in ['rest-patch', 'rest-put', 'gnmi']:
        service = YangRpcService()
        rpc = umf_file.CopyRpc()
        rpc.Input.source = str(src_path)
        rpc.Input.destination = 'running-configuration'
        rpc.Input.operation = 'replace'
        # rpc.Input.operation = 'replace' if config == 'yes'
        result = service.execute(dut, rpc, timeout=60, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config Replace failed : {}'.format(result.data))
            return False
        else:
            return True
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def config_replace_in_config_session(dut, src_path, **kwargs):
    '''
    Author: Chandra sekhar Reddy (chandra.vedanaparthi@broadcom.com)
    Purpose: This apis is used to replace the running config under the config session
    Note: Need to call st.set_module_params(conf_session=1) api to enter config session and execute this API
    :param dut:
    :return:
    Example:
    config_replace_in_config_session(dut,"config://filename")
    config_replace_in_config_session(dut,"ftp://userid:passwd@hostip/filepath")
    config_replace_in_config_session(dut,"home://filename")
    config_replace_in_config_session(dut,"http://hostip/filepath")
    config_replace_in_config_session(dut,"scp://userid:passwd@hostip/filepath")
    config_replace_in_config_session(dut,"usb://filename")
    '''

    expect_mode = kwargs.get("expect_mode", "mgmt-config")
    skip_error_check = kwargs.get("skip_error_check", False)
    my_cmd = 'replace {}\n'.format(src_path)
    output = st.config(dut, my_cmd, expect_mode=expect_mode, confirm='Y', type="klish", skip_error_check=skip_error_check)
    if "Error" in output:
        return False
    else:
        return True


def copy_running_config_to_config_db_json(dut, src_path, **kwargs):
    '''
    Author: Chandra sekhar Reddy (chandra.vedanaparthi@broadcom.com)
    Purpose: This apis is used to copy the running config to config_db.json
    :param dut:
    :return:
    Example:
    copy_running_config_to_config_db_json(dut,"config://filename")
    copy_running_config_to_config_db_json(dut,"ftp://userid:passwd@hostip/filepath")
    copy_running_config_to_config_db_json(dut,"home://filename")
    copy_running_config_to_config_db_json(dut,"http://hostip/filepath")
    copy_running_config_to_config_db_json(dut,"scp://userid:passwd@hostip/filepath")
    copy_running_config_to_config_db_json(dut,"usb://filename")
    '''

    expect_mode = kwargs.get("expect_mode", "mgmt-config")
    my_cmd = 'write {}\n'.format(src_path)
    output = st.config(dut, my_cmd, expect_mode=expect_mode, type="klish")
    if "Error" in output:
        return False
    else:
        return True
