from spytest import st
from spytest.utils import filter_and_select
from utilities.utils import get_interface_number_from_name

def config_intf_diagnostics(dut, intf, mode, **kwargs):

    '''
    :param dut:
    :param intf:
    :param feature:
        value: loopback (default)
    :param mode:
        value: <media-side-output|media-side-input|host-side-output|host-side-input>
    :param action:
        value: <enable|disable>, default is enable
    :param skip_error:
    :return:

    :mode
    :
    import apis.system.cmis as cmis_api
    cmis_api.config_intf_diagnostics(dut=data.dut1, intf='Ethernet17', mode='media-side-input')
    cmis_api.config_intf_diagnostics(dut=data.dut1, intf='Ethernet17', mode='media-side-input',action='disable')
    '''

    st.log('API: config_intf_diagnostics - DUT: {}, intf: {}, mode: {}, kwargs: {}'.format(dut, intf, mode, kwargs))

    feature = kwargs.get('feature','loopback')
    action =  kwargs.get('action','enable')
    skip_error = kwargs.get('skip_error',False)
    #cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))

    intf_info = get_interface_number_from_name(intf)
    cmd = 'interface diagnostics {} {} {} {} {}'.format(feature, intf_info['type'], intf_info['number'], mode, action)
    try:
        st.config(dut, cmd, skip_error_check=skip_error, type="klish", conf=True)
    except Exception as e:
        st.log(e)
        return False
    return True


def verify_intf_diag_reporting(dut, intf, **kwargs):

    '''
	:param ms_fec:
	:param hs_fec:
	:param ms_ip_snr:
	:param hs_ip_snr:
	:param ms_ip_peak:
	:param hs_ip_peak:
	:param ber_err_count:
	:param ber_reg:
    '''
    st.log('API: verify_intf_diag_reporting - DUT: {}, intf: {}, kwargs: {}'.format(dut, intf, kwargs))
    #cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    kwargs.pop('cli_type', None)

    num_args = len(kwargs)
    intf_info = get_interface_number_from_name(intf)
    cmd = 'show interface transceiver diagnostics reporting {} {}'.format(intf_info['type'], intf_info['number'])
    cmd_output = st.show(dut, cmd, type='klish')

    for kv in kwargs.items():
        if not filter_and_select(cmd_output, None, {kv[0]: kv[1]}):
            st.error('{} is not matching on {}'.format(kv[0], dut))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def verify_intf_diag_loopback_cap(dut, intf, **kwargs):

    '''
	:param ms_hs_loopback:
	:param pl_ms_loopback:
	:param pl_hs_loopback:
	:param hs_ip_loopback:
	:param hs_op_loopback:
	:param ms_ip_loopback:
	:param ms_op_loopback:

    '''
    st.log('API: verify_intf_diag_reporting - DUT: {}, intf: {}, kwargs: {}'.format(dut, intf, kwargs))
    #cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    kwargs.pop('cli_type', None)

    num_args = len(kwargs)
    intf_info = get_interface_number_from_name(intf)
    cmd = 'show interface transceiver diagnostics loopback capability {} {}'.format(intf_info['type'], intf_info['number'])
    cmd_output = st.show(dut, cmd, type='klish')

    for kv in kwargs.items():
        if not filter_and_select(cmd_output, None, {kv[0]: kv[1]}):
            st.error('{} is not matching on {}'.format(kv[0], dut))
        else:
            num_args -= 1

    return True if num_args == 0 else False


def verify_intf_diag_loopback_controls(dut, intf, **kwargs):

    '''
	:param ms_op_lb_1:
	:param ms_op_lb_2:
	:param ms_op_lb_3:
	:param ms_op_lb_4:
	:param ms_op_lb_5:
	:param ms_op_lb_6:
	:param ms_op_lb_7:
	:param ms_op_lb_8:
	:param ms_ip_lb_1:
	:param ms_ip_lb_2:
	:param ms_ip_lb_3:
	:param ms_ip_lb_4:
	:param ms_ip_lb_5:
	:param ms_ip_lb_6:
	:param ms_ip_lb_7:
	:param ms_ip_lb_8:
	:param hs_op_lb_1:
	:param hs_op_lb_2:
	:param hs_op_lb_3:
	:param hs_op_lb_4:
	:param hs_op_lb_5:
	:param hs_op_lb_6:
	:param hs_op_lb_7:
	:param hs_op_lb_8:

    '''

    st.log('API: verify_intf_diag_reporting - DUT: {}, intf: {}, kwargs: {}'.format(dut, intf, kwargs))
    #cli_type = kwargs.pop('cli_type', st.get_ui_type(dut,**kwargs))
    kwargs.pop('cli_type', None)

    num_args = len(kwargs)
    intf_info = get_interface_number_from_name(intf)
    cmd = 'show interface transceiver diagnostics loopback controls {} {}'.format(intf_info['type'], intf_info['number'])
    cmd_output = st.show(dut, cmd, type='klish')

    for kv in kwargs.items():
        if not filter_and_select(cmd_output, None, {kv[0]: kv[1]}):
            st.error('{} is not matching on {}'.format(kv[0], dut))
        else:
            num_args -= 1

    return True if num_args == 0 else False




