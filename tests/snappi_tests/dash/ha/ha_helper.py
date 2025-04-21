import snappi
import ipaddress
import re
import macaddress
import time
import logging

logger = logging.getLogger(__name__)

ipp = ipaddress.ip_address
maca = macaddress.MAC

ENI_START = 1
ENI_COUNT = 1# 64
ENI_MAC_STEP = '00:00:00:18:00:00'
ENI_STEP = 1
ENI_L2R_STEP = 1000

PAL = ipp("221.1.0.1")
PAR = ipp("221.2.0.1")

ACL_TABLE_MAC_STEP = '00:00:00:02:00:00'
ACL_POLICY_MAC_STEP = '00:00:00:00:00:32'

ACL_RULES_NSG = 1000  # 1000
ACL_TABLE_COUNT = 5

IP_PER_ACL_RULE = 25  # 128
IP_MAPPED_PER_ACL_RULE = IP_PER_ACL_RULE # 40
IP_ROUTE_DIVIDER_PER_ACL_RULE = 64 # 8, must be a power of 2 number

IP_STEP1 = int(ipp('0.0.0.1'))
#IP_STEP2 = int(ipp('0.0.1.0'))
#IP_STEP3 = int(ipp('0.1.0.0'))
#IP_STEP4 = int(ipp('1.0.0.0'))
IP_STEP_ENI = int(ipp('0.64.0.0')) # IP_STEP4
IP_STEP_NSG = int(ipp('0.2.0.0')) # IP_STEP3 * 4
IP_STEP_ACL = int(ipp('0.0.0.50')) # IP_STEP2 * 2
IP_STEPE = int(ipp('0.0.0.2'))


IP_L_START = ipaddress.ip_address('1.1.0.1')
IP_R_START = ipaddress.ip_address('1.4.0.1')

MAC_L_START = macaddress.MAC('00:1A:C5:00:00:01')
MAC_R_START = macaddress.MAC('00:1B:6E:00:00:01')


def run_ha_test(duthost, localhost, conn_graph_facts, fanout_graph_facts, get_snappi_ports,
                ha_test_case, config_snappi_ixl):

    test_type_dict = config_snappi_ixl['test_type_dict']
    connection_dict = config_snappi_ixl['connection_dict']

    main(connection_dict, test_type_dict['cps'], test_type_dict['test_filename'], test_type_dict['initial_cps_obj'],)

    return


def assignPorts(api, ports_list):

    communityListUrl = "ixload/test/activeTest/communityList"
    communityList = ports_list

    communityNameList = []
    for ports_name in ports_list:
        communityNameList.append(ports_name)

    portListPerCommunity = ports_list
    for communityName in portListPerCommunity:
        if communityName not in communityNameList:
            errorMsg = "Error while executing assignPorts operation. Invalid NetTraffic name: %s. This NetTraffic is not defined in the loaded rxf." % communityName
            raise Exception(errorMsg)

    for community in communityList:
        portListForCommunity = portListPerCommunity[community]
        if community == 'Traffic1@Network1':
            objectID = 0
        else:
            objectID = 1
        portListUrl = "%s/%s/network/portList" % (communityListUrl, objectID)

        for portTuple in portListForCommunity:
            chassisId, cardId, portId = portTuple
            paramDict = {"chassisId": chassisId, "cardId": cardId, "portId": portId}
            try:
                # Code that may raise an exception
                res = api.ixload_configure("post", portListUrl, paramDict)
            except Exception as e:
                # Handle any exception
                print(f"An error occurred: {e}")


    return



def build_node_ips(count, vpc, nodetype="client"):
    if nodetype in "client":
        ip = ipp(int(IP_R_START) + (IP_STEP_NSG * count) + int(ipp('0.64.0.0')) * (vpc - 1))
    if nodetype in "server":
        ip = ipp(int(IP_L_START) + int(ipp('0.64.0.0')) * (vpc - 1))

    return str(ip)


def build_node_macs(count, vpc, nodetype="client"):

    if nodetype in "client":
        #m = maca(int(MAC_R_START) + int(maca('00-00-00-30-00-00')) * (vpc - 1) + (int(maca(ACL_TABLE_MAC_STEP)) * count))
        m = maca(int(MAC_R_START) + int(maca('00-00-00-18-00-00')) * (vpc - 1) + (int(maca(ACL_TABLE_MAC_STEP)) * count))
    if nodetype in "server":
        #m = maca(int(MAC_L_START) + int(maca('00-00-00-30-00-00')) * (vpc - 1))
        m = maca(int(MAC_L_START) + int(maca('00-00-00-18-00-00')) * (vpc - 1))

    return str(m).replace('-', ':')


def build_node_vlan(index, nodetype="client"):

    hero_b2b = False

    """
    if index > 0:
        index = index + 1 * index
        #index = index + 1
    """

    if nodetype == 'client':
        vlan = ENI_L2R_STEP + index + 1
        #vlan = ENI_L2R_STEP + index
    else:
        ENI_STEP = 1
        if hero_b2b is True:
            vlan = 0
        else:
            vlan = ENI_STEP + index

    return vlan


def create_ip_list():

    ip_list = []

    for eni in range(ENI_START, ENI_COUNT + 1):
        ip_dict_temp = {}
        ip_client = build_node_ips(0, eni, nodetype="client")
        mac_client = build_node_macs(0, eni, nodetype="client")
        vlan_client = build_node_vlan(eni - 1, nodetype="client")

        ip_server = build_node_ips(0, eni, nodetype="server")
        mac_server = build_node_macs(0, eni, nodetype="server")
        vlan_server = build_node_vlan(eni - 1, nodetype="server")

        ip_dict_temp['eni'] = eni
        ip_dict_temp['ip_client'] = ip_client
        ip_dict_temp['mac_client'] = mac_client
        ip_dict_temp['vlan_client'] = vlan_client

        ip_dict_temp['ip_server'] = ip_server
        ip_dict_temp['mac_server'] = mac_server
        ip_dict_temp['vlan_server'] = vlan_server

        ip_list.append(ip_dict_temp)

    return ip_list

def edit_l1_settings(api):

    params = {'useIEEEDefaults': 'false',
              'autoNegotiate': 'false',
              'enableRSFEC': 'true',
              'enableRSFECStatistics': 'true'}

    for i in range(2):
        portl1_url = "ixload/test/activeTest/communityList/{}/network/portL1Settings".format(i)
        try:
            # Code that may raise an exception
            res = api.ixload_configure("patch", portl1_url, params)
        except Exception as e:
            # Handle any exception
            print(f"An error occurred: {e}")

    return


def find_test_role(test_type, server_vlan):

    test_role = ""
    if test_type == 'all':
        test_role = 'all'
    else:
        if (server_vlan - 1) % 4 == 3:
            # TCP BG
            test_role = "tcpbg"
        else:
            # CPS
            test_role = "cps"

    return test_role

def get_objectIDs(api, url):

    objectIDs = []
    payload = {}
    res = api.ixload_configure("get", url, payload)
    for r in res:
        objectIDs.append(r['objectID'])

    return objectIDs

def set_rangeList(api):
    """
    Adjust both rangeList, macRange, and vlanRange as needed
    """
    clientList_url = "ixload/test/activeTest/communityList/0/network/stack/childrenList/2/childrenList/3/rangeList"

    serverList_url = "ixload/test/activeTest/communityList/1/network/stack/childrenList/5/childrenList/6/rangeList"

   # get all the IDs
    client_objectIDs = get_objectIDs(api, clientList_url)
    server_objectIDs = get_objectIDs(api, serverList_url)

    # Adjust client side
    dict1 = {'doubleIncrement': True}
    dict2 = {
        'firstCount': '10',
        'firstIncrementBy': '0.2.0.0',
        'secondCount': '25000',
        'secondIncrementBy': '0.0.0.2'
    }
    vlan_dict = {'uniqueCount': 1}

    c_res_results = []
    for i,cid in enumerate(client_objectIDs):
        try:
            # Code that may raise an exception
            res1 = api.ixload_configure("patch", "{}/{}".format(clientList_url, cid), dict1)
            res2 = api.ixload_configure("patch", "{}/{}".format(clientList_url, cid), dict2)
            res3 = api.ixload_configure("patch", "{}/{}/vlanRange".format(clientList_url, cid), vlan_dict)
        except Exception as e:
            # Handle any exception
            print(f"An error occurred: {e}")

    s_res_results = []
    for i, sid in enumerate(server_objectIDs):
        try:
            # Code that may raise an exception
            res1 = api.ixload_configure("patch", "{}/{}/vlanRange".format(serverList_url, sid), vlan_dict)
        except Exception as e:
            # Handle any exception
            print(f"An error occurred: {e}")

    return

def set_trafficMapProfile(api):

    # Make Traffic Map Settings
    portMapPolicy_json = {'portMapPolicy': 'customMesh'}
    destination_url = "ixload/test/activeTest/communityList/0/activityList/0/destinations/0"
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", destination_url, portMapPolicy_json)
    except Exception as e:
        # Handle any exception
        print(f"An error occurred: {e}")

    # meshType
    meshType_json = {'meshType': 'vlanRangePairs'}
    submapsIpv4_url = "ixload/test/activeTest/communityList/0/activityList/0/destinations/0/customPortMap/submapsIPv4/0"
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", submapsIpv4_url, meshType_json)
    except Exception as e:
        # Handle any exception
        print(f"An error occurred: {e}")

    return

def set_tcpCustom(api):

    tcp_agent_url = "ixload/test/activeTest/communityList/0/activityList/0/agent"
    #url = "{}/{}".format(base_url, tcp_agent_url)

    param_json = {'maxPersistentRequests': 1}
    #response = requests.patch(url, json=param_json)
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", tcp_agent_url, param_json)
    except Exception as e:
        # Handle any exception
        print(f"An error occurred: {e}")

    return

def set_timelineCustom(api, initial_cps_value):

    activityList_url = "ixload/test/activeTest/communityList/0/activityList/0"
    timelineObjectives_url = "ixload/test/activeTest/communityList/0/activityList/0/timeline"
    #url_activityList = "{}/{}".format(base_url, activityList_url)
    #url_timeline = "{}/{}".format(base_url, timelineObjectives_url)

    """
    activityList_json = {
        'constraintType': 'ConnectionRateConstraint',
        'constraintValue': 6000000,
        'enableConstraint': True,
        'userObjectiveType': 'simulatedUsers',
        'userObjectiveValue': ENI_COUNT*250000
    }
    """
    activityList_json = {
        'constraintType': 'ConnectionRateConstraint',
        'constraintValue': initial_cps_value,
        'enableConstraint': True,
        'userObjectiveType': 'simulatedUsers',
        'userObjectiveValue': 64500
    }

    timeline_json = {
        'rampUpValue': 1000000,
        'sustainTime': 180
    }
    #response = requests.patch(url_activityList, json=activityList_json)
    """
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", activityList_url, activityList_json)
    except Exception as e:
        # Handle any exception
        print(f"An error occurred: {e}")
    """
    try:
        # Code that may raise an exception
        res = api.ixload_configure("patch", timelineObjectives_url, timeline_json)
    except Exception as e:
        # Handle any exception
        print(f"An error occurred: {e}")

    return

def run_cps_search(api, initial_cps_value):

    MAX_CPS = 5000000
    MIN_CPS = 0
    threshold = 100000
    test_iteration = 1
    test_value = initial_cps_value
    activityList_url = "ixload/test/activeTest/communityList/0/activityList/0"
    releaseConfig_url = "ixload/test/operations/abortAndReleaseConfigWaitFinish"

    while ((MAX_CPS - MIN_CPS) > threshold):
        test_result = ""
        print(
            "----Test Iteration %d------------------------------------------------------------------"
            % test_iteration)
        old_value = test_value
        print("Testing CPS Objective = %d" % test_value)
        """
        activityList_json = {
            'constraintType': 'ConnectionRateConstraint',
            'constraintValue': 6000000,
            'enableConstraint': True,
            'userObjectiveType': 'simulatedUsers',
            'userObjectiveValue': ENI_COUNT*250000
        }
        """
        activityList_json = {
            'constraintType': 'ConnectionRateConstraint',
            'constraintValue': test_value,
            'enableConstraint': True,
            'userObjectiveType': 'simulatedUsers',
            'userObjectiveValue': 64500
        }
        print("Updating CPS objective value settings...")
        try:
            # Code that may raise an exception
            res = api.ixload_configure("patch", activityList_url, activityList_json)
        except Exception as e:
            # Handle any exception
            print(f"An error occurred: {e}")
        print("CPS objective value updated.")

        print("Applying config...")
        print("Starting Traffic")
        cs = api.control_state()
        cs.app.state = 'start'  # cs.app.state.START
        response1 = api.set_control_state(cs)
        print(response1)
        req = api.metrics_request()

        # HTTP client
        stats_client = []
        req.choice = "httpclient"
        req.httpclient.stat_name = ["Connection Rate"]
        # req.httpclient.stat_name = ["HTTP Simulated Users", "HTTP Concurrent Connections", "HTTP Connect Time (us)", "TCP Connections Established", "HTTP Bytes Received"]
        # req.httpclient.all_stats = True # for  all stats

        res = api.get_metrics(req).httpclient_metrics
        print("**** res = {} ****".format(res))
        stats_client.append(res)
        time.sleep(60)

        res = api.get_metrics(req).httpclient_metrics
        print("**** res = {} ****".format(res))
        stats_client.append(res)
        time.sleep(60)

        res = api.get_metrics(req).httpclient_metrics
        print("**** res = {} ****".format(res))
        stats_client.append(res)
        time.sleep(60)

        # req1 = api.metrics_request()
        # req1.choice= "httpserver"
        # req1.httpserver.stat_name = ["TCP Connections in ESTABLISHED State", "TCP FIN Received","HTTP Bytes Received"]
        # #req1.httpserver.all_stats=True # for all stats - True
        # res1 = api.get_metrics(req1).httpserver_metrics
        # print("#### res1 = {} ####".format(res1))

        cps_max = 0
        client_stat_values = []
        for stat in stats_client:
            tmp = re.findall(r"value: '(\d+)'", str((stat)))
            client_stat_values += tmp
            client_stat_values = [int(item) for item in client_stat_values]
        cps_max = max(client_stat_values)
        print("Max value from test run{}: {}".format(test_iteration, cps_max))

        if cps_max < test_value:
            test = False
        else:
            test = True

        if test:
            print('Test Iteration Pass')
            test_result = "Pass"
            MIN_CPS = test_value
            test_value = (MAX_CPS + MIN_CPS) / 2
        else:
            print('Test Iteration Fail')
            test_result = "Fail"
            MAX_CPS = test_value
            test_value = (MAX_CPS + MIN_CPS) / 2
        print("Iteration Ended...")
        print('MIN_CPS = %d' % MIN_CPS)
        print('Current MAX_CPS = %d' % MAX_CPS)
        print('Previous CPS Objective value = %d' % old_value)
        print(' ')
        test_iteration += 1
        print("Releasing config...")
        try:
            # Code that may raise an exception
            param = {}
            res = api.ixload_configure("post", releaseConfig_url, param)
        except Exception as e:
            # Handle any exception
            print(f"An error occurred: {e}")
        print("Releasing config completed..")

        print("Changing app state to stop")
        cs.app.state = 'stop'  # cs.app.state.START
        api.set_control_state(cs)

    return

def test_saveAs(api, test_filename):

    saveAs_operation = 'ixload/test/operations/saveAs'
    #url = "{}/{}".format(base_url, saveAs_operation)
    paramDict = {
        'fullPath': "C:\\automation\\{}.rxf".format(test_filename),
        'overWrite': True
    }

    #response = requests.post(url, data=json.dumps(paramDict), headers=headers)
    try:
        # Code that may raise an exception
        res = api.ixload_configure("post", saveAs_operation, paramDict)
    except Exception as e:
        # Handle any exception
        print(f"An error occurred: {e}")

    return

def main(connection_dict, test_type, test_filename, initial_cps_value):

    ####### Start Here ######
    main_start_time = time.time()
    gw_ip = connection_dict['gw_ip']
    port = connection_dict['port']
    chassis_ip = connection_dict['chassis_ip']
    api = snappi.api(location="{}:{}".format(gw_ip, port), ext="ixload", verify=False, version="10.10.100.2")
    config = api.config()

    port_1 = config.ports.port(name="p1", location="{}/1/1".format(chassis_ip))[-1]
    port_2 = config.ports.port(name="p2", location="{}/1/2".format(chassis_ip))[-1]

    # client/server IP ranges created here
    ip_list = create_ip_list()

    print("Setting devices")
    time_device_time = time.time()
    (d1, d2) = config.devices.device(name="d1").device(name="d2")
    time_device_finish = time.time()
    print("Devices completed: {}".format(time_device_finish - time_device_time))


    print("Building Network traffic")
    #for eni in range(ENI_COUNT):
    for eni, eni_info  in enumerate(ip_list):
        test_role = find_test_role(test_type, eni_info['vlan_server'])

        ####### client ######
        if test_role == 'cps' or test_role == 'all':
            de_tmp = "d1.e1"
            d1.name = de_tmp

            # ethernet section
            eth = d1.ethernets.add()
            eth.name = "e1"
            eth.connection.port_name = "p1"
            eth.mac = eni_info['mac_client']
            eth.step = "00:00:00:00:00:02"

            # ip section
            ip1 = eth.ipv4_addresses.ipv4()[-1]
            ip1.name = "{}.ipv4".format(eth.name)
            ip1.address = eni_info['ip_client']
            ip1.prefix = 10
            ip1.gateway = "0.0.0.0"
            # ip1.count = ACL_RULES_NSG * ACL_TABLE_COUNT * IP_PER_ACL_RULE * 2
            ip1.count = 1

            # vlan section
            vlan = eth.vlans.vlan()[-1]
            vlan.name = "{}.vlan".format(eth.name)
            vlan.id = eni_info['vlan_client']
            vlan.priority = 1
            vlan.count = 1
            vlan.tpid = "x8100"


            ###### SERVER ######
            de_tmp_server = "d2.e2"
            d2.name = de_tmp_server

            # ethernet section
            eth2 = d2.ethernets.add()
            eth2.name = "e2"
            eth2.connection.port_name = "p2"
            eth2.mac = eni_info['mac_server']
            eth2.step = "00:00:00:00:00:02"

            # ip section
            ip2 = eth2.ipv4_addresses.ipv4()[-1]
            ip2.name = "{}.ipv4".format(eth2.name)
            ip2.address = eni_info['ip_server']
            ip2.prefix = 10
            ip2.gateway = "0.0.0.0"
            ip2.count = 1

            # vlan section
            vlan2 = eth2.vlans.vlan()[-1]
            vlan2.name = "{}.vlan".format(eth2.name)
            vlan2.id = eni_info['vlan_server']
            vlan2.priority = 1
            vlan2.count = 1
            vlan2.tpid = "x8100"

    print("Net Traffic completed:")
    #eth.connection.port_name = "p1"
    #eth2.connection.port_name = "p2"
    # tcp/http client settings
    print("Configuring TCP client settings")
    (t1,) = d1.tcps.tcp(name="Tcp1")
    t1.ip_interface_name = ip1.name
    t1.adjust_tcp_buffers = False
    t1.receive_buffer_size = 1024
    t1.transmit_buffer_size = 1024
    t1.keep_alive_time = 7200
    t1.keep_alive_interval = 75
    t1.keep_alive_probes = 9
    t1.retransmission_minimum_timeout = 200
    t1.retransmission_maximum_timeout = 120000
    t1.minimum_source_port = 1024
    t1.maximum_source_port = 65530
    t1.inter_packet_gap = 8
    t1.inter_packet_delay = 0
    t1.ip_fragment_time = 30
    t1.fin_timeout = 60
    t1.syn_retries = 5
    t1.synack_retries = 5
    t1.retansmit_retries1 = 3
    t1.retransmit_retries2 = 5
    t1.packet_reordering = 3
    t1.delayed_acks_segments = 0
    t1.delayed_acks_timeout = 0
    t1.disable_path_mtu = True
    t1.window_scaling = False
    t1.selective_ack = True
    t1.time_wait_reuse = False
    t1.time_wait_recycle = True
    t1.time_wait_rfc1323_strict = False
    t1.packet_timestamps = True
    t1.explicit_congestion_notification = False
    t1.fragment_reassembly_timer = 30
    print("TCP completed")

    # http
    print("Configuring HTTP client settings")
    (http_1,) = d1.https.http(name="HTTP1")
    http_1.tcp_name = t1.name  # UDP configs can be mapped http.transport = udp_1.name
    http_1.url_stats_count = 10
    http_1.time_to_live_value = 64
    http_1.high_perf_with_simulated_user = False
    (http_client,) = http_1.clients.client()
    http_client.name = "http_client1"
    http_client.cookie_jar_size = 10
    http_client.version = "1"
    http_client.cookie_reject_probability = True
    http_client.enable_cookie_support = False
    http_client.command_timeout = 600
    http_client.command_timeout_ms = 0
    http_client.keep_alive = False
    http_client.max_persistent_requests = 1
    http_client.max_sessions = 1
    http_client.max_streams = 1
    http_client.max_pipeline = 1
    http_client.piggy_back_ack = True
    http_client.tcp_fast_open = False
    http_client.content_length_deviation_tolerance = 0

    (get_a, delete_a) = http_client.methods.method().method()
    (get1,) = get_a.get.get()
    #get1.destination = "Traffic2_HTTPServer1:80"
    get1.destination = "Traffic2_http_server1:80"
    get1.page = "./1b.html"
    get1.name_value_args = ""
    #(delete1,) = delete_a.delete.delete()
    #delete1.destination = "Traffic2_Http1Server1:80"
    #delete1.page = "./1b.html"
    print("HTTP client completed")

    # tcp/http server settings
    # tcp
    print("Configuring TCP server settings")
    (t2,) = d2.tcps.tcp(name="Tcp2")
    t2.ip_interface_name = ip2.name
    t2.adjust_tcp_buffers = False
    t2.receive_buffer_size = 1024
    t2.transmit_buffer_size = 1024
    t2.time_wait_recycle = False
    t2.time_wait_rfc1323_strict = True
    t2.keep_alive_time = 600
    print("TCP server completed")

    # http
    print("Configuring HTTP server settings")
    (http_2,) = d2.https.http(name="HTTP2")
    http_2.tcp_name = t2.name  # UDP configs can be mapped http.transport = udp_2.name
    http_2.enable_tos = False
    http_2.url_stats_count = 10
    http_2.time_to_live_value = 64
    http_2.high_perf_with_simulated_user = False  # UDP configs can be mapped http.transport = udp_2.name
    (http_server,) = http_2.servers.server()
    http_server.name = "http_server1"
    http_server.rst_timeout = 100
    http_server.enable_http2 = False
    http_server.port = 80
    http_server.request_timeout = 5
    http_server.maximum_response_delay = 0
    http_server.minimum_response_delay = 0
    http_server.url_page_size = 1024
    print("HTTP server completed")

    ## Traffic Profile
    print("Configuring Traffic Profile settings")
    (tp1,) = config.trafficprofile.trafficprofile()
    # # # # # traffic_profile = config.TrafficProfiles.TrafficProfile(name = "traffic_profile_1")
    tp1.app = [http_client.name,
                   http_server.name]  # traffic_profile_cps.app - "app" using it for reference can be some generic name for traffic profile on which traffic has to flow
    tp1.objective_type = ["connection_per_sec", "simulated_user"]
    tp1.objective_value = [6000000, ENI_COUNT*250000]
    (obj_type,) = tp1.objectives.objective()
    obj_type.connection_per_sec.enable_controlled_user_adjustment = True
    obj_type.connection_per_sec.sustain_time=14
    obj_type.connection_per_sec.ramp_down_time=12
    obj_type.connection_per_sec.time_to_first_iter = 3
    obj_type.connection_per_sec.iteration = 4
    (segment1, segment2) = tp1.segment.segment().segment()
    segment1.name = "Linear segment1"
    segment1.start = 0
    segment1.duration = 10
    #segment1.rate = int((ENI_COUNT*25000)*.10)
    # segment1.target = 100
    segment2.name = "Linear segment2"
    #segment2.start = 0
    segment2.duration = 1000
    segment2.rate = 10
    segment2.target = ENI_COUNT*250000
    # tp1.timeline = [segment1.name, segment2.name]
    #tp1.timeline = ['Timeline5']
    print("Traffic profile completed")

    # ## Traffic Maps
    """
    print("Configuring Traffic Maps settings")
    tm1 = tp1.trafficmap.trafficmap()
    tm1[0].port_map_policy_name  = "custom"
    cust1 = tm1[0].custom.custom()
    cust1[0].name = "vlanRangePairs"
    mt1 = cust1[0].mapping_type
    mt1.vlan_range_pairs.enable = True
    #mt1.vlan_range_pairs.destination_id = 2
    end_trafficmaps_time = time.time()
    print("Traffic map completed: {}".format(end_trafficmaps_time - start_time))
    """

    ##### Set config
    print("Configuring custom settings")
    time_custom_time = time.time()
    response = api.set_config(config)
    port = connection_dict['port']

    time_custom_finish = time.time()
    print("Custom settings completed: {}".format(time_custom_finish - time_custom_time))

    print("Configuring custom port settings")
    """
    ports_list = {
        'Traffic1@Network1': [(1,1,1), (1,2,1), (1,3,1), (1,4,1), (1,5,1), (1,6,1), (1,7,1), (1,8,1)],
        'Traffic2@Network2': [(1,1,2), (1,2,2), (1,3,2), (1,4,2), (1,5,2), (1,6,2), (1,7,2), (1,8,2)]
    }
    """
    ports_list = {
        'Traffic1@Network1': [(1,1,1)],
        'Traffic2@Network2': [(1,1,2)]
    }

    time_assignPort_time = time.time()
    assignPorts(api,ports_list)
    time_assignPort_finish = time.time()
    print("Custom port settings completed: {}".format(time_assignPort_finish - time_assignPort_time))

    print("Configuring port L1 settings")
    time_customl1_time = time.time()
    edit_l1_settings(api)
    time_customl1_finished = time.time()
    print("Custom port L1 settings completed: {}".format(time_customl1_finished - time_customl1_time))

    # Here adjust Double Increment and vlanRange unique number
    print("Configuring rangeList settings for client and server")
    test_rangeList_time = time.time()
    #set_rangeList(api)
    test_rangeList_finish_time = time.time()
    print("rangeList settings completed {}".format(test_rangeList_finish_time-test_rangeList_time))

    # Adjust Traffic Profile
    print("Custom trafficmaps")
    test_trafficmaps_time = time.time()
    set_trafficMapProfile(api)
    test_trafficmaps_finish = time.time()
    print("Finished traffic maps configuration {}".format(test_trafficmaps_finish - test_trafficmaps_time))

    # Set custom TCP parameters
    print("Custom TCP settings")
    test_tcp_time = time.time()
    set_tcpCustom(api)
    test_tcp_finish_time = time.time()
    print("Finished TCP configuration {}".format(test_tcp_finish_time - test_tcp_time))


    print("Custom timeline settings")
    test_timeline_time = time.time()
    set_timelineCustom(api, initial_cps_value)
    test_timeline_finish = time.time()
    print("Finished timeline configurations {}".format(test_timeline_finish - test_timeline_time))

    # save file
    print("Saving Test File")
    test_save_time = time.time()
    test_saveAs(api, test_filename)
    test_save_finish_time = time.time()
    print("Finished saving: {}".format(test_save_finish_time - test_save_time))

    # Traffic Starts
    cs = run_cps_search(api, initial_cps_value)
    #cs.app.state = 'stop' #cs.app.state.START
    #api.set_control_state(cs)
    main_finish_time = time.time()
    print("Main app finished in {}".format(main_finish_time-main_start_time))
    print("Test Ending")
