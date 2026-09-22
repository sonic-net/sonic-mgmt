def init_vars(vars, port_speed):
    shaping_data = {}
    if str(port_speed) == '1000':
        pir_1G = int((100 * 1000 * 1000)//8) #pir_100M
        pir_1_18G = int((118 * 1000 * 1000)//8) #pir_118M
        pir_2G = int((200 * 1000 * 1000)//8) #pir_200M
        pir_3G = int((300 * 1000 * 1000)//8) #pir_300M
        pir_4G = int((400 * 1000 * 1000)//8) #pir_400M
        pir_5G = int((500 * 1000 * 1000)//8) #pir_500M
        pir_6G = int((600 * 1000 * 1000)//8) #pir_600M
        pir_7G = int((700 * 1000 * 1000)//8) #pir_700M
        pir_8G = int((800 * 1000 * 1000)//8) #pir_800M
        pir_8_8G = int((880 * 1000 * 1000)//8) #pir_880M
        pir_9G = int((900 * 1000 * 1000)//8) #pir_900M
        pir_10G = int((1* 1000 * 1000 * 1000)//8) #pir_1000M
    else:
        pir_1G = int((1 * 1000 * 1000 * 1000)//8)
        pir_1_18G = int((1.18 * 1000 * 1000 * 1000)//8)
        pir_2G = int((2 * 1000 * 1000 * 1000)//8)
        pir_3G = int((3 * 1000 * 1000 * 1000)//8)
        pir_4G = int((4 * 1000 * 1000 * 1000)//8)
        pir_5G = int((5 * 1000 * 1000 * 1000)//8)
        pir_6G = int((6 * 1000 * 1000 * 1000)//8)
        pir_7G = int((7 * 1000 * 1000 * 1000)//8)
        pir_8G = int((8 * 1000 * 1000 * 1000)//8)
        pir_8_8G = int((8.8 * 1000 * 1000 * 1000)//8)
        pir_9G = int((9 * 1000 * 1000 * 1000)//8)
        pir_10G = int((10 * 1000 * 1000 * 1000)//8)


    port_shaper_json_config = {'port': vars.D1T1P3, 'pir': pir_8G, 'meter_type': 'bytes', 'policy_name': 'port_qos_shaper'}
    port_shaper_json_config_10G = {'port': vars.D1T1P3, 'pir': pir_10G, 'meter_type': 'bytes', 'policy_name': 'port_qos_shaper'}
    port_shaper_json_config_1G = {'port': vars.D1T1P2, 'pir': pir_1G, 'meter_type': 'bytes', 'policy_name': 'port_qos_shaper'}
    queue_shaper_json_config_q0102 = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'shaper_data': [{'queue': 1, 'pir': pir_8G, 'meter_type': 'bytes'}, {'queue': 2, 'pir': pir_2G, 'meter_type': 'bytes'}]}
    queue_shaper_min_not_met_json_config = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'shaper_data': [{'queue': 1, 'cir': pir_8_8G, 'pir': pir_10G, 'meter_type': 'bytes'}, {'queue': 2, 'cir': pir_1_18G, 'pir': pir_10G, 'meter_type': 'bytes'}]}
    queue_scheduler_json_config_q001 = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'scheduler_data': [{'queue': 1, 'weight': '1', 'type': 'WRR'}, {'queue': 2, 'weight': '1', 'type': 'WRR'}]}
    queue_shaper_json_config_q0 = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'shaper_data': [{'queue': 0, 'pir': pir_1G, 'meter_type': 'bytes'}]}
    queue_shaper_json_config_q0102_1 = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'shaper_data': [{'queue': 1, 'pir': pir_2G, 'meter_type': 'bytes'}, {'queue': 2, 'pir': pir_8G, 'meter_type': 'bytes'}]}
    port_queue_shaper_json_config1 = {'port': vars.D1T1P3, 'pir': pir_7G, 'meter_type': 'bytes', 'policy_name': 'port_qos_shaper'}
    port_queue_shaper_json_config2 = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'shaper_data': [{'queue': 1, 'pir': pir_8G, 'meter_type': 'bytes'}, {'queue': 2, 'pir': pir_2G, 'meter_type': 'bytes'}]}
    queue_sched_shaper_json_config = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'shaper_data': [{'queue': 1, 'pir': pir_9G, 'meter_type': 'bytes'}, {'queue': 2, 'pir': pir_9G, 'meter_type': 'bytes'}]}
    queue_scheduler_json_config_q0102 = {'port': vars.D1T1P3, 'policy_name': 'port_qos_shaper', 'scheduler_data': [{'queue': 1, 'weight': '20', 'type': 'WRR'}, {'queue': 2, 'weight': '80', 'type': 'WRR'}]}
    
    shaping_data['pir_1G'] = pir_1G
    shaping_data['pir_2G'] = pir_2G
    shaping_data['pir_3G'] = pir_3G
    shaping_data['pir_4G'] = pir_4G
    shaping_data['pir_5G'] = pir_5G
    shaping_data['pir_6G'] = pir_6G
    shaping_data['pir_7G'] = pir_7G
    shaping_data['pir_8G'] = pir_8G
    shaping_data['pir_8_8G'] = pir_8_8G
    shaping_data['pir_9G'] = pir_9G
    shaping_data['pir_10G'] = pir_10G
    shaping_data['port_shaper_json_config'] = port_shaper_json_config
    shaping_data['port_shaper_json_config_10G'] = port_shaper_json_config_10G
    shaping_data['port_shaper_json_config_1G'] = port_shaper_json_config_1G
    shaping_data['queue_shaper_json_config_q0102'] = queue_shaper_json_config_q0102
    shaping_data['queue_shaper_min_not_met_json_config'] = queue_shaper_min_not_met_json_config
    shaping_data['queue_scheduler_json_config_q001'] = queue_scheduler_json_config_q001
    shaping_data['queue_shaper_json_config_q0'] = queue_shaper_json_config_q0
    shaping_data['queue_shaper_json_config_q0102_1'] = queue_shaper_json_config_q0102_1
    shaping_data['port_queue_shaper_json_config1'] = port_queue_shaper_json_config1
    shaping_data['port_queue_shaper_json_config2'] = port_queue_shaper_json_config2
    shaping_data['queue_sched_shaper_json_config'] = queue_sched_shaper_json_config
    shaping_data['queue_scheduler_json_config_q0102'] = queue_scheduler_json_config_q0102
    
    return shaping_data
