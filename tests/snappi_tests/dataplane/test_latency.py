from tests.snappi_tests.dataplane.imports import *

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]

import pytest
import snappi
import numpy as np
import matplotlib.pyplot as plt
import os
import json

@pytest.fixture(scope="function", autouse=True)
def setup_and_teardown(snappi_api, snappi_testbed_config):
    """
    Fixture to initialize and cleanup resources for the test.
    """
    # Setup: Initialize session_assistant and ixnet
    logger.info("Starting IxNetwork Session")
    session_assistant = SessionAssistant(IpAddress=snappi_api._address,
                                         RestPort=snappi_api._port,
                                         UserName=snappi_api._username,
                                         Password=snappi_api._password)
    ixnet = session_assistant.Ixnetwork
    logger.info("Session and ixnetwork initialized.")
    testbed_config, port_config_list = snappi_testbed_config
    logger.info("Connect the virtual ports to test ports")
    port_list = [
        {'xpath': f'/vport[{i+1}]', 'location': port.location, 'name': f'Port-{i:02d}'}
        for i, port in enumerate(port_config_list)
    ]

    # Import configuration and assign ports
    ixnet.ResourceManager.ImportConfig(json.dumps(port_list), False)
    connected_ports = ixnet.AssignPorts(True)

    # Assign IP addresses and gateways
    def assign_addresses(ipv4_device, ips, gateways):
        ipv4_device.Address.ValueList(ips)
        ipv4_device.GatewayIp.ValueList(gateways)
    
    vports, half_ports = ixnet.Vport.find(), len(port_config_list)// 2
    logger.info("Creating IxNetwork Topology")
    ipv4_w = ixnet.Topology.add(Vports=vports[:half_ports]).DeviceGroup.add(Name='Device West', Multiplier='1').Ethernet.add().Ipv4.add(Name=f'Ipv4 West')
    ipv4_e = ixnet.Topology.add(Vports=vports[half_ports:]).DeviceGroup.add(Name='Device East', Multiplier='1').Ethernet.add().Ipv4.add(Name=f'Ipv4 East')

    ip,gw = map(list, zip(*[[pc.ip,pc.gateway] for pc in port_config_list]))

    assign_addresses(ipv4_w, ip[:half_ports], gw[:half_ports])
    assign_addresses(ipv4_e, ip[half_ports:], gw[half_ports:])


    def createTrafficItem():
        print('Create Traffic Item')
        trafficItem = ixnet.Traffic.TrafficItem.add(Name='TestTraffic', BiDirectional=True, TrafficType='ipv4')
        print('Add endpoint flow group')
        trafficItem.EndpointSet.add(Sources=ipv4_w.parent.parent.parent, Destinations=ipv4_e.parent.parent.parent)
        print('Configuring config elements')
        configElement = trafficItem.ConfigElement.find()[0]
        configElement.FrameRate.update(Rate = 100,Type = 'percentLineRate')
        configElement.TransmissionControl.update(Duration = 20,Type = 'continous')
        configElement.FrameRateDistribution.PortDistribution = 'applyRateToAll'
        configElement.FrameSize.FixedSize = 512
        trafficItem.Tracking.find()[0].TrackBy = ['sourceDestEndpointPair0']

    logger.info("Creating Traffic")
    createTrafficItem()
    # Yielding the resources so that they can be used in the test function
    yield ixnet, session_assistant

    # Teardown: Cleanup after the test
    print("Teardown initiated...")
    # Clean up ixnetwork configuration
    # Remove session
    try:
        session_assistant.Session.remove()
        print("Session removed.")
    except Exception as e:
        print(f"Error removing session: {e}")

pytestmark = [pytest.mark.topology('tgen')]
def test_latency_measurement(request,
                            snappi_api,                       # noqa F811
                            snappi_testbed_config,
                            conn_graph_facts,             # noqa F811
                            fanout_graph_facts,           # noqa F811
                            duthosts,
                            get_snappi_ports,
                            rand_one_dut_hostname,
                            dut_portnames_oper_up,
                            setup_and_teardown
        ):
    """
    Test to measure latency introduced by the switch under fully loaded conditions.
    """
    dut_hostname,dut_port  = dut_portnames_oper_up[0].split('|')
    dut_port = [dp.split('|')[1] for dp in dut_portnames_oper_up]
    pytest_require(rand_one_dut_hostname == dut_hostname,"Port is not mapped to the expected DUT")
    ixnet, session_assistant = setup_and_teardown
    duthost = duthosts[rand_one_dut_hostname]
    #pytest_assert(testbed_config is not None, 'Fail to get L2/3 testbed config')

    snappi_extra_params = SnappiTestParams()
    # ixnetwork.Vport.find().L1Config.find().CurrentType = 'aresOneM'
    ixnet.StartAllProtocols()
    time.sleep(10)

    # Start the traffic
    ixnet.Traffic.TrafficItem.find()[0].Generate()
    print('Start Traffic')
    ixnet.Traffic.Apply()
    ixnet.Traffic.Start()
    # Wait for the traffic to complete
    #time.sleep(12)
    tiStatistics = StatViewAssistant(ixnet, 'Traffic Item Statistics')
    # Create the DataFrame
    tdf = pd.DataFrame(tiStatistics.Rows.RawData, columns=tiStatistics.ColumnHeaders)
    # Ensure 'Store-Forward Avg Latency (ns)' column is numeric
    tdf['Store-Forward Avg Latency (ns)'] = pd.to_numeric(tdf['Store-Forward Avg Latency (ns)'], errors='coerce')
    # Compute RTT as 2 * Avg Latency
    tdf['RTT (ns)'] = tdf['Store-Forward Avg Latency (ns)'] * 2

    flowStatistics = StatViewAssistant(ixnet, 'Flow Statistics')
    # Number of iterations (adjust as needed)
    num_iterations = 50

    all_iterations = []
    selected_columns = ['Iteration','Tx Port', 'Rx Port', 'Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %', 'Store-Forward Avg Latency (ns)','Store-Forward Min Latency (ns)', 'Store-Forward Max Latency (ns)']
    
    for i in range(1, num_iterations + 1):
        logger.info("Featching Stats Iteration:%d" % i)
        df = pd.DataFrame(flowStatistics.Rows.RawData, columns=flowStatistics.ColumnHeaders)
        df['Iteration'] = i
        tmp = df[selected_columns]
        all_iterations.append(tmp.copy())
        logger.info('Dumping Iteration: {}\n{}'.format(i, tabulate(tmp, headers='keys', tablefmt='psql')))
        time.sleep(10)

    selected_columns = ['Iteration','Pair Key','Tx Port', 'Rx Port', 'Loss %', 'Store-Forward Avg Latency (ns)','Store-Forward Min Latency (ns)', 'Store-Forward Max Latency (ns)']

    # Concatenate all iterations into one DataFrame
    multi_iteration_df = pd.concat(all_iterations, ignore_index=True)
    # Generate Pair Key for bidirectional matching (Tx Port and Rx Port as a set)
    multi_iteration_df['Pair Key'] = multi_iteration_df.apply(lambda row: frozenset([row['Tx Port'], row['Rx Port']]), axis=1)
    # Display the DataFrame for multiple iterations
    logger.info('Dumping all Iteration Stats.\n{}'.format(tabulate(multi_iteration_df[selected_columns], headers='keys', tablefmt='psql')))

    # Ensure 'Store-Forward Avg Latency (ns)' is numeric
    multi_iteration_df['Store-Forward Avg Latency (ns)'] = pd.to_numeric(multi_iteration_df['Store-Forward Avg Latency (ns)'], errors='coerce')
    # Group by 'Pair Key' to calculate the average latency across all iterations for each pair
    avg_latency_df = multi_iteration_df.groupby('Pair Key')['Store-Forward Avg Latency (ns)'].mean().reset_index()
    # Sort by the average RTT in nanoseconds
    avg_latency_df_sorted = avg_latency_df.sort_values(by='Store-Forward Avg Latency (ns)', ascending=True)
    # Display the result

    logger.info('Displaying Result\n{}'.format(tabulate(avg_latency_df_sorted, headers='keys', tablefmt='psql')))
    
    pivot_df = multi_iteration_df.pivot_table(index='Tx Port', columns='Iteration', values='Store-Forward Avg Latency (ns)', aggfunc='mean')
    logger.info('Displaying Pivot\n{}'.format(tabulate(pivot_df, headers='keys', tablefmt='psql')))

    # Creating the heatmap
    plt.figure(figsize=(48, 12))
    sns.heatmap(pivot_df, annot=True, cmap='viridis', fmt='.0f', linewidths=0.5)

    # Adding labels and title
    plt.title('Store-Forward Avg Latency Heatmap')
    plt.xlabel('Iteration')
    plt.ylabel('Tx Port')

    # Show the heatmap
    plt.show() 
    plt.savefig("Latency.png", dpi=300, bbox_inches='tight')




