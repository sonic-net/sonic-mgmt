from spytest import st

from utilities.utils import get_supported_ui_type_list

try:
    import apis.yang.codegen.messages.qos as umf_qos
except ImportError:
    pass


def config_qos_properties(dut, **kwargs):
    st.log('config_qos_properties kwargs: {}'.format(kwargs))
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', 'yes')
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos()

    qos_attr_list = {
        'watermark_refresh_interval': ['WatermarkRefreshInterval', int(kwargs['watermark_refresh_interval']) if 'watermark_refresh_interval' in kwargs else None],
        'telemetry_refresh_interval': ['TelemetryWatermarkRefreshInterval', int(kwargs['telemetry_refresh_interval']) if 'telemetry_refresh_interval' in kwargs else None],
    }

    for key, attr_value in qos_attr_list.items():
        if key in kwargs and attr_value[1] is not None:
            setattr(qos_obj, attr_value[0], attr_value[1])
    if config != 'yes':
        for key, attr_value in qos_attr_list.items():
            if key in kwargs and attr_value[1] is not None:
                target_attr = getattr(qos_obj, attr_value[0])
                result = qos_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)

    if kwargs.get('qos_type') == 'threshold':
        ts_obj = umf_qos.Threshold(Buffer=kwargs['ts_buffer'], Type=kwargs['ts_type'], Port=kwargs['ts_port'], Index=int(kwargs['ts_index']))
        if kwargs.get('ts_value'):
            ts_obj.ThresholdValue = kwargs['ts_value']
        qos_obj.add_Threshold(ts_obj)

    if config == 'yes':
        st.log('***IETF_JSON*** {}'.format(qos_obj.get_ietf_json()))
        result = qos_obj.configure(dut, cli_type=cli_type)

    if not result.ok():
        st.log('test_step_failed: Config QoS Properties {}'.format(result.message))
        return False

    return True
