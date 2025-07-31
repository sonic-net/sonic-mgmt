#!/bin/bash

# This script is a wrapper or helper script for used in Cisco internal VPP CI/CD
# Usage: ./run_tests_vpp_wrapper.sh <topo> <timestamp> <build number> <custom flag>
# eg: ./run_tests_vpp_wrapper.sh t1_lag_azure 20250508_bgp_only # parameter 2 and beyond are optional

if [ "$2" = "" ]; then
    echo "No timestamp passed in, populating timestamp locally"
    timestamp=`date +%Y%m%d_%H%M%S`    
else
    echo "Timestamp passed in, using it"
    timestamp=$2
fi
echo "Timestamp: ${timestamp}"

if [[ $# -lt 1 || ("$1" != "t1" && "$1" != "t1_lag" && "$1" != "t1_lag_azure" && "$1" != "t1_azure") ]]; then
    echo "ERROR: not enough or invalid topo argument"
    echo "Usage: ${FUNCNAME[0]} <t1|t1_lag|t1_lag_azure|t1_azure> (timestamp) (build number) (custom flag)"
    exit 1
fi

topo=$1
build_number=$3
# Custom flag. Note that superpositioning $4 only when these custom run are on mutual exclusive "topo", otherwise will overwrite
custom_acl=$4
custom_bgp=$4

echo "Topo: ${topo}"
echo "Timestamp: ${timestamp}"
echo "Build number: ${build_number}"
echo "custom_acl: ${custom_acl} custom_bgp: ${custom_bgp}"

nightly_archive_dir="/auto/ott_jenkins/jenkins/vpp/nightly/nightly_${topo}_${build_number}_${timestamp}"

# Core:
tests_pretest="test_pretest.py"
tests_posttest="test_posttest.py"
# tests_vxlan="vxlan/test_vxlan_ecmp.py vxlan/test_vxlan_ecmp_switchover.py"
# tests_bgp="bgp/test_bgp_speaker.py bgp/test_bgp_sentinel.py bgp/test_reliable_tsa.py bgp/test_bgp_session.py bgp/test_bgp_queue.py bgp/test_bgp_session_flap.py bgp/test_ipv6_nlri_over_ipv4.py bgp/test_bgp_allow_list.py bgp/test_bgpmon.py bgp/test_bgp_multipath_relax.py bgp/test_passive_peering.py bgp/test_bgp_bbr.py bgp/test_seq_idf_isolation.py bgp/test_bgp_suppress_fib.py bgp/test_bgp_bounce.py bgp/test_bgp_command.py bgp/test_startup_tsa_tsb_service.py bgp/test_bgp_route_neigh_learning.py bgp/test_bgp_slb.py bgp/test_bgp_dual_asn.py bgp/test_bgp_update_timer.py bgp/test_bgp_azng_migration.py bgp/test_bgp_peer_shutdown.py bgp/test_bgp_authentication.py bgp/test_bgp_bbr_default_state.py bgp/test_bgp_fact.py bgp/test_bgp_port_disable.py bgp/test_bgp_gr_helper.py bgp/test_bgpmon_v6.py bgp/test_traffic_shift_sup.py bgp/test_bgp_stress_link_flap.py bgp/test_traffic_shift.py"
# if [ "${topo}" = "t1_lag_azure" -o "${topo}" = "t1_azure" ]; then
#     tests_ip="ip/test_ip_packet.py ip/test_mgmt_ipv6_only.py"
# else
#     tests_ip="ip/test_ip_packet.py" # test_mgmt_ipv6_only.py is not supported for VXR 
# fi
# tests_ipfwd="ipfwd/test_dir_bcast.py ipfwd/test_nhop_group.py ipfwd/test_mtu.py ipfwd/test_dip_sip.py"
# tests_arp="arp/test_neighbor_mac_noptf.py arp/test_arpall.py arp/test_arp_update.py arp/test_unknown_mac.py arp/test_arp_extended.py arp/test_tagged_arp.py arp/test_neighbor_mac.py arp/test_wr_arp.py arp/test_arp_dualtor.py arp/test_stress_arp.py"
# tests_route="route/test_default_route.py route/test_static_route.py route/test_forced_mgmt_route.py route/test_route_flow_counter.py route/test_duplicate_route.py route/test_route_consistency.py route/test_route_flap.py route/test_route_perf.py route/test_route_bgp_ecmp.py"
# tests_bfd="bfd/test_bfd.py bfd/test_bfd_static_route.py bfd/test_bfd_traffic.py"
# tests_pc="pc/test_lag_2.py pc/test_lag_member.py pc/test_lag_member_forwarding.py pc/test_po_cleanup.py pc/test_po_update.py pc/test_po_voq.py pc/test_retry_count.py"
# tests_fib="fib/test_fib.py"
tests_interfaces="test_interfaces.py" # Without folder

# # Secondary:
# tests_acl="acl/test_acl.py acl/custom_acl_table/test_custom_acl_table.py acl/test_stress_acl.py acl/test_acl_outer_vlan.py acl/null_route/test_null_route_helper.py"
# tests_mpls="mpls/test_mpls.py"
# tests_snmp="snmp/test_snmp_link_local.py snmp/test_snmp_psu.py snmp/test_snmp_queue.py snmp/test_snmp_loopback.py snmp/test_snmp_pfc_counters.py snmp/test_snmp_v2mib.py snmp/test_snmp_queue_counters.py snmp/test_snmp_cpu.py snmp/test_snmp_phy_entity.py snmp/test_snmp_interfaces.py snmp/test_snmp_memory.py snmp/test_snmp_default_route.py snmp/test_snmp_fdb.py snmp/test_snmp_lldp.py"
# tests_read_mac="read_mac/test_read_mac_metadata.py" # VS doesn't test this
# tests_portstat="portstat/test_portstat.py"

# # VS-compatible:
# ## Already covered by VPP tests above
# # tests_acl="acl/test_acl.py acl/test_stress_acl.py"
# # tests_arp="arp/test_arpall.py arp/test_neighbor_mac_noptf.py arp/test_neighbor_mac.py"
# # tests_bgp="bgp/test_bgp_allow_list.py bgp/test_bgp_bbr_default_state.py bgp/test_bgp_bbr.py bgp/test_bgp_bounce.py bgp/test_bgp_command.py bgp/test_bgp_fact.py bgp/test_bgp_gr_helper.py bgp/test_bgpmon.py bgp/test_bgp_multipath_relax.py bgp/test_bgp_peer_shutdown.py bgp/test_bgp_queue.py bgp/test_bgp_sentinel.py bgp/test_bgp_session_flap.py bgp/test_bgp_session.py bgp/test_bgp_stress_link_flap.py bgp/test_bgp_suppress_fib.py bgp/test_bgp_update_timer.py bgp/test_traffic_shift.py"
# # tests_fib="fib/test_fib.py"
# # tests_ipfwd="ipfwd/test_dip_sip.py ipfwd/test_mtu.py ipfwd/test_nhop_group.py"
# # tests_ip="ip/test_ip_packet.py"
# tests_lldp="lldp/test_lldp.py lldp/test_lldp_syncd.py"
# # tests_mpls="mpls/test_mpls.py"
# # tests_pc="pc/test_lag_2.py pc/test_lag_member_forwarding.py pc/test_po_cleanup.py pc/test_po_update.py pc/test_retry_count.py"
# # tests_portstat="portstat/test_portstat.py"
# # tests_route="route/test_default_route.py route/test_route_consistency.py route/test_route_flap.py route/test_route_perf.py"
# # tests_snmp="snmp/test_snmp_cpu.py snmp/test_snmp_default_route.py snmp/test_snmp_interfaces.py snmp/test_snmp_link_local.py snmp/test_snmp_lldp.py snmp/test_snmp_loopback.py snmp/test_snmp_memory.py snmp/test_snmp_pfc_counters.py snmp/test_snmp_psu.py snmp/test_snmp_queue_counters.py snmp/test_snmp_queue.py snmp/test_snmp_v2mib.py"
# # tests_sub_port_interfaces="sub_port_interfaces/test_show_subinterface.py sub_port_interfaces/test_sub_port_interfaces.py"
# # tests_vxlan="vxlan/test_vxlan_bfd_tsa.py vxlan/test_vxlan_crm.py vxlan/test_vxlan_ecmp.py vxlan/test_vxlan_ecmp_switchover.py vxlan/test_vxlan_route_advertisement.py"

# ## Not supported:
# # tests_everflow="everflow/test_everflow_ipv6.py everflow/test_everflow_per_interface.py everflow/test_everflow_testbed.py"
# # tests_pfcwd="pfcwd/test_pfc_config.py pfcwd/test_pfcwd_all_port_storm.py pfcwd/test_pfcwd_cli.py pfcwd/test_pfcwd_function.py pfcwd/test_pfcwd_timer_accuracy.py"
# # tests_qos="qos/test_buffer.py qos/test_pfc_counters.py qos/test_qos_dscp_mapping.py"
# tests_k8s="k8s/k8s_test_utilities.py k8s/test_config_reload.py k8s/test_join_available_master.py k8s/test_disable_flag.py"
# tests_mpls="mpls/test_mpls.py"

# ## High Fail/Error:
# tests_copp="copp/test_copp.py"
# tests_crm="crm/test_crm.py"
# tests_decap="decap/test_decap.py"
# tests_drop_packets="drop_packets/test_drop_counters.py"
# tests_dut_console="dut_console/test_console_baud_rate.py dut_console/test_escape_character.py dut_console/test_idle_timeout.py"
tests_platform_tests="platform_tests/broadcom/test_ser.py platform_tests/cli/test_show_platform.py platform_tests/counterpoll/test_counterpoll_watermark.py platform_tests/fwutil/test_fwutil.py platform_tests/link_flap/test_cont_link_flap.py platform_tests/link_flap/test_link_flap.py platform_tests/sfp/test_sfpshow.py platform_tests/sfp/test_sfputil.py platform_tests/sfp/test_show_intf_xcvr.py platform_tests/test_auto_negotiation.py platform_tests/test_cpu_memory_usage.py platform_tests/test_first_time_boot_password_change/test_first_time_boot_password_change.py platform_tests/test_kdump.py platform_tests/test_link_down.py platform_tests/test_link_down.py platform_tests/test_memory_exhaustion.py platform_tests/test_platform_info.py platform_tests/test_port_toggle.py platform_tests/test_power_off_reboot.py platform_tests/test_reboot.py platform_tests/test_reload_config.py platform_tests/test_secure_upgrade.py platform_tests/test_sensors.py platform_tests/test_sequential_restart.py platform_tests/test_xcvr_info_in_db.py" # There are lot of unsupported in platform_tests but just have them all in one tests_platform_tests variable and let skip markers to skip it on Azure. For VXR, just not to run platform_tests at all since it may cause DUT down
# tests_syslog="syslog/test_logrotate.py syslog/test_syslog.py syslog/test_syslog_rate_limit.py syslog/test_syslog_source_ip.py"
# tests_sub_port_interfaces="sub_port_interfaces/test_sub_port_l2_forwarding.py sub_port_interfaces/test_show_subinterface.py sub_port_interfaces/test_sub_port_interfaces.py"

# tests_autorestart="autorestart/test_container_autorestart.py"
# tests_cacl="cacl/test_cacl_application.py"
# tests_clock="clock/test_clock.py"
# tests_configlet="configlet/test_add_rack.py"
# tests_console="console/test_console_availability.py console/test_console_driver.py console/test_console_loopback.py console/test_console_reversessh.py console/test_console_udevrule.py"
# tests_container_checker="container_checker/test_container_checker.py"
# tests_container_hardening="container_hardening/test_container_hardening.py"
# tests_database="database/test_db_config.py database/test_db_scripts.py"
# tests_dhcp_relay="dhcp_relay/test_dhcp_pkt_fwd.py"
# tests_disk="disk/test_disk_exhaustion.py"
# tests_dns="dns/static_dns/test_static_dns.py dns/test_dns_resolv_conf.py" 
# tests_fdb="fdb/test_fdb_flush.py"
# tests_generic_config_updater="generic_config_updater/test_aaa.py generic_config_updater/test_bgp_prefix.py generic_config_updater/test_bgp_sentinel.py generic_config_updater/test_cacl.py generic_config_updater/test_cacl.py generic_config_updater/test_ecn_config_update.py generic_config_updater/test_eth_interface.py generic_config_updater/test_ip_bgp.py generic_config_updater/test_kubernetes_config.py generic_config_updater/test_mmu_dynamic_threshold_config_update.py generic_config_updater/test_monitor_config.py generic_config_updater/test_ntp.py generic_config_updater/test_pfcwd_status.py generic_config_updater/test_pg_headroom_update.py generic_config_updater/test_syslog.py"
# tests_gnmi="gnmi/test_gnmi_appldb.py gnmi/test_gnmi_configdb.py gnmi/test_gnmi_countersdb.py gnmi/test_gnmi.py gnmi/test_gnmi_smartswitch.py gnmi/test_gnoi_killprocess.py"
# tests_golden_config_infra="golden_config_infra/test_config_reload_with_rendered_golden_config.py"
# tests_hash="hash/test_generic_hash.py"
# tests_http="http/test_http_copy.py"
# tests_iface_loopback_action="iface_loopback_action/test_iface_loopback_action.py"
# tests_iface_namingmode="iface_namingmode/test_iface_namingmode.py"
# tests_log_fidelity="log_fidelity/test_bgp_shutdown.py"
# tests_memory_checker="memory_checker/test_memory_checker.py"
# tests_minigraph="minigraph/test_masked_services.py"
# tests_monit="monit/test_monit_status.py"
# tests_ntp="ntp/test_ntp.py"
# tests_override_config_table="override_config_table/test_override_config_table_masic.py override_config_table/test_override_config_table.py"
# tests_passw_hardening="passw_hardening/test_passw_hardening.py"
# tests_process_monitoring="process_monitoring/test_critical_process_monitoring.py"
# tests_radv="radv/test_radv_restart.py"
# tests_reset_factory="reset_factory/test_reset_factory.py"
# tests_restapi="restapi/test_restapi_vxlan_ecmp.py"
# tests_scp="scp/test_scp_copy.py"
# tests_show_techsupport="show_techsupport/test_auto_techsupport.py show_techsupport/test_techsupport_no_secret.py show_techsupport/test_techsupport.py"
# tests_srv6="srv6/test_srv6_basic_sanity.py"
# tests_ssh="ssh/test_ssh_ciphers.py ssh/test_ssh_default_password.py ssh/test_ssh_limit.py ssh/test_ssh_stress.py"
tests_stress="stress/test_stress_routes.py"
# tests_system_health="system_health/test_system_status.py system_health/test_watchdog.py"
# tests_tacacs="tacacs/test_ro_disk.py"
# tests_telemetry="telemetry/test_events.py telemetry/test_telemetry_cert_rotation.py telemetry/test_telemetry.py"
# Without folder
tests_features="test_features.py"
tests_nbr_health="test_nbr_health.py"
tests_pktgen="test_pktgen.py"
tests_procdockerstatsd="test_procdockerstatsd.py"

#20250718:
tests_acl="acl/test_acl.py acl/custom_acl_table/test_custom_acl_table.py acl/test_stress_acl.py acl/test_acl_outer_vlan.py acl/null_route/test_null_route_helper.py"
tests_arp="arp/test_neighbor_mac_noptf.py arp/test_arpall.py arp/test_arp_update.py arp/test_unknown_mac.py arp/test_arp_extended.py arp/test_tagged_arp.py arp/test_neighbor_mac.py arp/test_wr_arp.py arp/test_arp_dualtor.py arp/test_stress_arp.py"
tests_auditd="auditd/test_auditd.py"
tests_autorestart="autorestart/test_container_autorestart.py"
tests_bfd="bfd/test_bfd_static_route.py bfd/test_bfd.py bfd/test_bfd_traffic.py"
tests_bgp="bgp/test_bgp_speaker.py bgp/test_bgp_stress_link_flap.py bgp/test_bgp_sentinel.py bgp/test_traffic_shift.py bgp/test_ping_bgp_neighbor.py bgp/test_bgp_session.py bgp/test_bgp_operation_in_ro.py bgp/test_bgp_queue.py bgp/test_bgp_session_flap.py bgp/test_ipv6_nlri_over_ipv4.py bgp/test_bgp_allow_list.py bgp/test_bgpmon.py bgp/test_bgp_multipath_relax.py bgp/test_passive_peering.py bgp/test_bgp_bbr.py bgp/reliable_tsa/test_reliable_tsa_flaky.py bgp/reliable_tsa/test_reliable_tsa_stable.py bgp/test_seq_idf_isolation.py bgp/test_ipv6_bgp_scale.py bgp/test_bgp_suppress_fib.py bgp/test_bgp_bounce.py bgp/test_bgp_command.py bgp/test_startup_tsa_tsb_service.py bgp/test_bgp_route_neigh_learning.py bgp/test_bgp_slb.py bgp/test_bgp_update_replication.py bgp/test_bgp_dual_asn.py bgp/test_bgp_update_timer.py bgp/test_bgp_azng_migration.py bgp/test_bgp_peer_shutdown.py bgp/test_bgp_authentication.py bgp/test_bgp_bbr_default_state.py bgp/test_bgp_fact.py bgp/test_bgp_router_id.py bgp/test_bgp_port_disable.py bgp/test_bgp_gr_helper.py bgp/test_bgp_vnet.py bgp/test_bgpmon_v6.py bgp/test_traffic_shift_sup.py"
tests_bmp="bmp/test_bmp_configdb.py bmp/test_docker_restart.py bmp/test_bmp_statedb.py bmp/test_bmp_redis_instance.py bmp/test_frr_bmp_sanity.py"
tests_cacl="cacl/test_cacl_application.py cacl/test_ebtables_application.py cacl/test_cacl_function.py"
tests_clock="clock/test_clock.py"
tests_configlet="configlet/util/run_test_in_switch.py configlet/test_add_rack.py"
tests_console="console/test_console_availability.py console/test_console_loopback.py console/test_console_udevrule.py console/test_console_reversessh.py console/test_console_driver.py"
tests_container_checker="container_checker/test_container_checker.py"
tests_container_hardening="container_hardening/test_container_hardening.py"
tests_container_upgrade="container_upgrade/test_container_upgrade.py"
tests_copp="copp/test_copp.py"
tests_crm="crm/test_crm_available.py crm/test_crm.py"
tests_dash="dash/test_dash_privatelink.py dash/test_relaxed_match_negative.py dash/test_dash_smartswitch_vnet.py dash/crm/test_dash_crm.py dash/test_dash_vnet.py dash/test_dash_acl.py dash/test_dash_disable_enable_eni.py"
tests_database="database/test_db_scripts.py database/test_db_config.py"
tests_db_migrator="db_migrator/test_migrate_dns.py"
tests_decap="decap/test_subnet_decap.py decap/test_decap.py"
tests_dhcp_relay="dhcp_relay/test_dhcp_pkt_recv.py dhcp_relay/test_dhcp_counter_stress.py dhcp_relay/test_dhcpv6_relay.py dhcp_relay/test_dhcp_relay_stress.py dhcp_relay/test_dhcp_pkt_fwd.py dhcp_relay/test_dhcp_relay.py"
tests_dhcp_server="dhcp_server/test_dhcp_server_stress.py dhcp_server/test_dhcp_server.py dhcp_server/test_dhcp_server_multi_vlans.py dhcp_server/dhcp_server_test_common.py"
tests_disk="disk/test_disk_exhaustion.py"
tests_dns="dns/test_dns_resolv_conf.py dns/static_dns/test_static_dns.py"
tests_drop_packets="drop_packets/test_drop_counters.py drop_packets/test_configurable_drop_counters.py"
tests_dut_console="dut_console/test_escape_character.py dut_console/test_idle_timeout.py dut_console/test_non_ascii_output.py dut_console/test_console_chassis_conn.py dut_console/test_console_baud_rate.py"
tests_ecmp="ecmp/test_fgnhg.py ecmp/test_ecmp_sai_value.py ecmp/inner_hashing/test_inner_hashing_lag.py ecmp/inner_hashing/test_wr_inner_hashing_lag.py ecmp/inner_hashing/test_inner_hashing.py ecmp/inner_hashing/test_wr_inner_hashing.py"
tests_fdb="fdb/test_fdb_mac_learning.py fdb/test_fdb_mac_move.py fdb/test_fdb_flush.py fdb/test_fdb_mac_expire.py fdb/test_fdb.py"
tests_fib="fib/test_fib.py"
tests_fips="fips/test_fips.py"
tests_generic_config_updater="generic_config_updater/test_bgp_speaker.py generic_config_updater/test_packet_trimming_config.py generic_config_updater/test_ntp.py generic_config_updater/test_bgp_sentinel.py generic_config_updater/test_syslog.py generic_config_updater/test_multiasic_addcluster.py generic_config_updater/test_pg_headroom_update.py generic_config_updater/test_mgmt_interface.py generic_config_updater/test_kubernetes_config.py generic_config_updater/test_ip_bgp.py generic_config_updater/test_cacl.py generic_config_updater/test_mmu_dynamic_threshold_config_update.py generic_config_updater/test_incremental_qos.py generic_config_updater/test_static_route.py generic_config_updater/test_dynamic_acl.py generic_config_updater/test_aaa.py generic_config_updater/test_pfcwd_status.py generic_config_updater/test_multiasic_linkcrc.py generic_config_updater/test_vlan_interface.py generic_config_updater/test_portchannel_interface.py generic_config_updater/test_lo_interface.py generic_config_updater/test_ecn_config_update.py generic_config_updater/test_srv6.py generic_config_updater/test_multiasic_idf.py generic_config_updater/test_bgp_prefix.py generic_config_updater/test_bgpl.py generic_config_updater/test_dhcp_relay.py generic_config_updater/test_pfcwd_interval.py generic_config_updater/test_eth_interface.py generic_config_updater/test_monitor_config.py"
tests_gnmi="gnmi/test_gnoi_system.py gnmi/test_gnoi_system_grpc.py gnmi/test_gnoi_system_reboot.py gnmi/test_gnoi_killprocess.py gnmi/test_gnmi_countersdb.py gnmi/test_gnmi_smartswitch.py gnmi/test_mimic_hwproxy_cert_rotation.py gnmi/test_gnmi_appldb.py gnmi/test_gnmi_configdb.py gnmi/test_gnoi_os.py gnmi/test_gnmi.py"
tests_golden_config_infra="golden_config_infra/test_config_reload_with_rendered_golden_config.py"
tests_hash="hash/test_generic_hash.py"
tests_http="http/test_http_copy.py"
tests_iface_loopback_action="iface_loopback_action/test_iface_loopback_action.py"
tests_iface_namingmode="iface_namingmode/test_iface_namingmode.py"
tests_ip="ip/test_ip_packet.py ip/test_mgmt_ipv6_only.py"
tests_ipfwd="ipfwd/test_dir_bcast.py ipfwd/test_nhop_group.py ipfwd/test_mtu.py ipfwd/test_dip_sip.py"
tests_ixia="ixia/ecn/test_red_accuracy.py ixia/ecn/test_dequeue_ecn.py ixia/test_ixia_traffic.py ixia/pfcwd/test_pfcwd_a2a.py ixia/pfcwd/test_pfcwd_burst_storm.py ixia/pfcwd/test_pfcwd_m2o.py ixia/pfcwd/test_pfcwd_basic.py ixia/pfcwd/test_pfcwd_runtime_traffic.py ixia/pfc/test_global_pause.py ixia/pfc/test_pfc_pause_lossy.py ixia/pfc/test_pfc_pause_lossless.py ixia/pfc/test_pfc_congestion.py ixia/ixanvl/test_bgp_conformance.py ixia/test_tgen.py"
# tests_k8s="k8s/k8s_test_utilities.py k8s/test_config_reload.py k8s/test_join_available_master.py k8s/test_disable_flag.py"
tests_kubesonic="kubesonic/test_k8s_join_disjoin.py"
tests_l2="l2/test_l2_configure.py"
tests_layer1="layer1/test_port_error.py"
tests_lldp="lldp/test_lldp.py lldp/test_lldp_syncd.py"
tests_log_fidelity="log_fidelity/test_bgp_shutdown.py"
tests_macsec="macsec/test_docker_restart.py macsec/test_deployment.py macsec/test_interop_protocol.py macsec/test_interop_wan_isis.py macsec/test_controlplane.py macsec/test_fault_handling.py macsec/test_dataplane.py"
tests_mclag="mclag/test_mclag_l3.py"
tests_memory_checker="memory_checker/test_memory_checker.py"
tests_minigraph="minigraph/test_masked_services.py"
tests_monit="monit/test_monit_status.py"
tests_mvrf="mvrf/test_mgmtvrf.py"
tests_nat="nat/test_dynamic_nat.py nat/test_static_nat.py"
tests_ntp="ntp/test_ntp.py"
tests_ospf="ospf/test_ospf.py ospf/test_ospf_bfd.py"
tests_override_config_table="override_config_table/test_override_config_table_masic.py override_config_table/test_override_config_table.py"
tests_packet_trimming="packet_trimming/test_packet_trimming.py"
tests_passw_hardening="passw_hardening/test_passw_hardening.py"
tests_pc="pc/test_po_voq.py pc/test_lag_member.py pc/test_po_update.py pc/test_po_cleanup.py pc/test_lag_member_forwarding.py pc/test_lag_2.py pc/test_retry_count.py"
tests_performance_meter="performance_meter/test_performance.py"
tests_pfc_asym="pfc_asym/test_pfc_asym.py"
# tests_platform_tests="platform_tests/test_idle_driver.py platform_tests/test_reboot.py platform_tests/test_memory_exhaustion.py platform_tests/test_first_time_boot_password_change/test_first_time_boot_password_change.py platform_tests/cli/test_show_chassis_module.py platform_tests/cli/test_show_platform.py platform_tests/test_process_reboot_cause.py platform_tests/test_reload_config.py platform_tests/test_secure_upgrade.py platform_tests/sfp/test_sfpshow.py platform_tests/sfp/test_show_intf_xcvr.py platform_tests/sfp/test_sfputil.py platform_tests/api/test_thermal.py platform_tests/api/test_module.py platform_tests/api/platform_api_test_base.py platform_tests/api/test_component.py platform_tests/api/test_chassis_fans.py platform_tests/api/test_fan_drawer.py platform_tests/api/test_chassis.py platform_tests/api/test_psu_fans.py platform_tests/api/test_sfp.py platform_tests/api/test_fan_drawer_fans.py platform_tests/api/test_psu.py platform_tests/api/test_watchdog.py platform_tests/test_sensors.py platform_tests/counterpoll/test_counterpoll_watermark.py platform_tests/test_intf_fec.py platform_tests/test_service_warm_restart.py platform_tests/test_power_budget_info.py platform_tests/test_kdump.py platform_tests/mellanox/test_check_sfp_eeprom.py platform_tests/mellanox/test_hw_management_service.py platform_tests/mellanox/test_check_sysfs.py platform_tests/mellanox/test_psu_power_threshold.py platform_tests/mellanox/test_reboot_cause.py platform_tests/mellanox/test_check_sfp_presence.py platform_tests/mellanox/test_check_sfp_using_ethtool.py platform_tests/daemon/test_fancontrol.py platform_tests/daemon/test_psud.py platform_tests/daemon/test_ledd.py platform_tests/daemon/test_chassisd.py platform_tests/daemon/test_sensord.py platform_tests/daemon/test_syseepromd.py platform_tests/daemon/test_pcied.py platform_tests/test_sequential_restart.py platform_tests/test_cont_warm_reboot.py platform_tests/test_xcvr_info_in_db.py platform_tests/test_link_down.py platform_tests/test_auto_negotiation.py platform_tests/test_advanced_reboot.py platform_tests/test_port_toggle.py platform_tests/fwutil/test_fwutil.py platform_tests/link_flap/test_link_flap.py platform_tests/link_flap/test_cont_link_flap.py platform_tests/test_platform_info.py platform_tests/test_thermal_state_db.py platform_tests/broadcom/test_ser.py platform_tests/test_chassis_reboot.py platform_tests/test_cpu_memory_usage.py platform_tests/test_power_off_reboot.py" #TODO:need identify which not supported, just old one first
tests_portstat="portstat/test_portstat.py"
tests_process_monitoring="process_monitoring/test_critical_process_monitoring.py"
tests_radv="radv/test_radv_ipv6_ra.py radv/test_radv_restart.py radv/test_radv_run.py"
tests_read_mac="read_mac/test_read_mac_metadata.py"
tests_reset_factory="reset_factory/test_reset_factory.py"
tests_restapi="restapi/test_restapi_vxlan_ecmp.py restapi/test_restapi.py"
tests_route="route/test_default_route.py route/test_static_route.py route/test_forced_mgmt_route.py route/test_route_flow_counter.py route/test_duplicate_route.py route/test_route_consistency.py route/test_route_flap.py route/test_route_perf.py route/test_route_bgp_ecmp.py"
tests_sai_qualify="sai_qualify/setup_test_env.py sai_qualify/test_community.py sai_qualify/test_sai_t0_warm_reboot.py sai_qualify/test_sai_ptf.py sai_qualify/test_brcm_t0.py sai_qualify/test_sai_ptf_warm_reboot.py"
tests_scp="scp/test_scp_copy.py"
tests_sflow="sflow/test_sflow.py"
tests_show_techsupport="show_techsupport/test_auto_techsupport.py show_techsupport/test_techsupport_no_secret.py show_techsupport/test_techsupport.py"
# tests_smartswitch="smartswitch/platform_tests/test_platform_dpu.py smartswitch/platform_tests/test_reload_dpu.py" #TODO: need identify if supported
tests_snappi_tests="snappi_tests/ecn/test_ecn_marking_with_pfc_quanta_variance_with_snappi.py snappi_tests/ecn/test_dequeue_ecn_with_snappi.py snappi_tests/ecn/test_ecn_marking_with_snappi.py snappi_tests/ecn/test_red_accuracy_with_snappi.py snappi_tests/ecn/test_ecn_marking_cisco8000.py snappi_tests/ecn/test_bp_fabric_ecn_marking_with_snappi.py snappi_tests/test_snappi.py snappi_tests/pfcwd/test_pfcwd_basic_with_snappi.py snappi_tests/pfcwd/test_pfcwd_mixed_speed.py snappi_tests/pfcwd/test_pfcwd_burst_storm_with_snappi.py snappi_tests/pfcwd/test_pfcwd_m2o_with_snappi.py snappi_tests/pfcwd/test_pfcwd_a2a_with_snappi.py snappi_tests/pfcwd/test_pfcwd_actions.py snappi_tests/pfcwd/test_pfcwd_runtime_traffic_with_snappi.py snappi_tests/pfc/warm_reboot/test_pfc_pause_lossless_warm_reboot.py snappi_tests/pfc/test_m2o_oversubscribe_lossless_lossy.py snappi_tests/pfc/test_m2o_oversubscribe_lossless.py snappi_tests/pfc/test_valid_pfc_frame_with_snappi.py snappi_tests/pfc/test_pfc_pause_lossy_with_snappi.py snappi_tests/pfc/test_pfc_mixed_speed.py snappi_tests/pfc/test_lossless_response_to_external_pause_storms.py snappi_tests/pfc/test_global_pause_with_snappi.py snappi_tests/pfc/test_tx_drop_counter_with_snappi.py snappi_tests/pfc/test_valid_src_mac_pfc_frame.py snappi_tests/pfc/test_pfc_pause_lossless_with_snappi.py snappi_tests/pfc/test_pfc_port_congestion.py snappi_tests/pfc/test_lossless_response_to_throttling_pause_storms.py snappi_tests/pfc/test_m2o_oversubscribe_lossy.py snappi_tests/pfc/test_pfc_pause_zero_mac.py snappi_tests/pfc/test_pfc_pause_unset_bit_enable_vector.py snappi_tests/pfc/test_pfc_no_congestion_throughput.py snappi_tests/pfc/test_pfc_pause_response_with_snappi.py snappi_tests/pfc/test_m2o_fluctuating_lossless.py snappi_tests/reboot/test_warm_reboot.py snappi_tests/reboot/test_cold_reboot.py snappi_tests/reboot/test_fast_reboot.py snappi_tests/reboot/test_soft_reboot.py snappi_tests/qos/test_ipip_packet_reorder_with_snappi.py snappi_tests/bgp/test_bgp_outbound_uplink_po_flap.py snappi_tests/bgp/test_bgp_remote_link_failover.py snappi_tests/bgp/test_bgp_outbound_downlink_port_flap.py snappi_tests/bgp/test_bgp_outbound_tsa.py snappi_tests/bgp/test_bgp_outbound_uplink_po_member_flap.py snappi_tests/bgp/test_bgp_convergence_performance.py snappi_tests/bgp/test_bgp_local_link_failover.py snappi_tests/bgp/test_bgp_rib_in_convergence.py snappi_tests/bgp/test_bgp_outbound_uplink_process_crash.py snappi_tests/bgp/test_bgp_rib_in_capacity.py snappi_tests/bgp/test_bgp_outbound_ungraceful_restart.py snappi_tests/bgp/files/bgp_test_gap_helper.py snappi_tests/bgp/test_bgp_scalability.py snappi_tests/bgp/test_bgp_outbound_uplink_multi_po_flap.py snappi_tests/bgp/test_bgp_outbound_downlink_process_crash.py snappi_tests/lacp/test_add_remove_link_physically.py snappi_tests/lacp/test_lacp_timers_effect.py snappi_tests/lacp/test_add_remove_link_from_dut.py snappi_tests/test_multidut_snappi.py"
tests_snmp="snmp/test_snmp_link_local.py snmp/test_snmp_psu.py snmp/test_snmp_queue.py snmp/test_snmp_loopback.py snmp/test_snmp_pfc_counters.py snmp/test_snmp_v2mib.py snmp/test_snmp_queue_counters.py snmp/test_snmp_cpu.py snmp/test_snmp_phy_entity.py snmp/test_snmp_interfaces.py snmp/test_snmp_memory.py snmp/test_snmp_default_route.py snmp/test_snmp_fdb.py snmp/test_snmp_lldp.py"
tests_span="span/test_port_mirroring.py"
tests_srv6="srv6/test_srv6_dataplane.py srv6/test_srv6_vlan_forwarding.py srv6/test_srv6_basic_sanity.py srv6/test_srv6_static_config.py"
tests_ssh="ssh/test_ssh_default_password.py ssh/test_ssh_stress.py ssh/test_ssh_limit.py ssh/test_ssh_ciphers.py"
tests_sub_port_interfaces="sub_port_interfaces/test_sub_port_l2_forwarding.py sub_port_interfaces/test_show_subinterface.py sub_port_interfaces/test_sub_port_interfaces.py"
tests_syslog="syslog/test_syslog_rate_limit.py syslog/test_syslog.py syslog/test_logrotate.py syslog/test_syslog_source_ip.py"
tests_system_health="system_health/test_system_status.py system_health/test_system_health.py system_health/test_watchdog.py"
tests_tacacs="tacacs/test_ro_user.py tacacs/test_jit_user.py tacacs/test_authorization.py tacacs/test_accounting.py tacacs/test_ro_disk.py tacacs/test_rw_user.py"
tests_telemetry="telemetry/test_telemetry_poll.py telemetry/test_events.py telemetry/test_telemetry_cert_rotation.py telemetry/test_telemetry.py"
tests_testbed_setup="testbed_setup/test_populate_fdb.py"
tests_transceiver="transceiver/cli/sfputil/test_sfputil.py transceiver/cli/show/test_transceiver_info_cli.py transceiver/transceiver_test_base.py"
tests_upgrade_path="upgrade_path/test_upgrade_path.py upgrade_path/test_multi_hop_upgrade_path.py"
tests_vlan="vlan/test_autostate_disabled.py vlan/test_vlan_ports_down.py vlan/test_host_vlan.py vlan/test_secondary_subnet.py vlan/test_vlan_ping.py vlan/test_vlan.py"
tests_voq="voq/test_voq_ipfwd.py voq/test_fabric_reach.py voq/test_voq_init.py voq/test_voq_nbr.py voq/test_voq_counter.py voq/test_voq_chassis_app_db_consistency.py voq/test_voq_fabric_capacity.py voq/test_voq_fabric_status_all.py voq/test_fabric_cli_and_db.py voq/test_voq_disrupts.py voq/test_voq_fabric_isolation.py voq/test_voq_intfs.py"
tests_vrf="vrf/test_vrf.py vrf/test_vrf_attr.py"
# tests_vxlan="vxlan/test_vxlan_decap.py vxlan/test_vxlan_crm.py vxlan/test_vnet_decap.py vxlan/test_vnet_bgp_route_precedence.py vxlan/test_vxlan_ecmp_switchover.py vxlan/test_vnet_vxlan.py vxlan/test_vxlan_route_advertisement.py vxlan/test_vxlan_ecmp.py vxlan/test_vxlan_bfd_tsa.py vxlan/test_vnet_route_leak.py"
# tests_vxlan="vxlan/test_vxlan_ecmp.py vxlan/test_vxlan_decap.py vxlan/test_vnet_decap.py vxlan/test_vnet_bgp_route_precedence.py vxlan/test_vxlan_ecmp_switchover.py vxlan/test_vnet_vxlan.py vxlan/test_vxlan_route_advertisement.py vxlan/test_vxlan_bfd_tsa.py vxlan/test_vnet_route_leak.py vxlan/test_vxlan_crm.py vxlan/test_vxlan_bfd_tsa.py" #todo: moved crm and tsa at last, ecmp at frist to see if ecmp still fail =>this order only 12 bfd_tsa failed on yang validation somehow when just running one tc along was failed before running this full vxlan folder. anyway it seems likely that crm was causing the issue for vxlan_ecmp. move crm to last to see if tsa will pass
tests_vxlan="vxlan/test_vxlan_ecmp.py vxlan/test_vxlan_decap.py vxlan/test_vnet_decap.py vxlan/test_vnet_bgp_route_precedence.py vxlan/test_vxlan_ecmp_switchover.py vxlan/test_vnet_vxlan.py vxlan/test_vxlan_route_advertisement.py vxlan/test_vxlan_bfd_tsa.py vxlan/test_vnet_route_leak.py vxlan/test_vxlan_bfd_tsa.py vxlan/test_vxlan_crm.py" #todo: crm to last =>tsa just 12 yang validation failure, but ecmp has lot of those 0 interfaces error. ecmp run first so can't be affected by vxlan test. but it's using 7/6 image so suppose no baseline issue, unless topo is affected by other new latest tests folders
# tests_vxlan="vxlan/test_vxlan_ecmp.py vxlan/test_vxlan_ecmp_switchover.py" #todo: has this original to make sure baseline is still good =>has to be good. so let add skip marker to all core tests and see if it's affected by latest core tests. also don't run long test since taking too much time
tests_wan="wan/lldp/test_wan_lldp.py wan/traffic_test/test_traffic.py wan/lacp/test_wan_lag_member.py wan/lacp/test_wan_lacp.py wan/lacp/test_wan_lag_min_link.py wan/isis/test_isis_neighbor.py wan/isis/test_isis_database.py wan/isis/test_isis_lsp_refresh.py wan/isis/test_isis_holdtime.py wan/isis/test_isis_ecmp.py wan/isis/test_isis_redistribute.py wan/isis/test_isis_log_adjacency_change.py wan/isis/test_isis_csnp_interval.py wan/isis/test_isis_lsp_lifetime.py wan/isis/test_isis_overload_bit.py wan/isis/test_isis_dynamic_hostname.py wan/isis/test_isis_lsp_gen_interval.py wan/isis/test_isis_lsp_fragment.py wan/isis/test_isis_level_capacity.py wan/isis/test_isis_hello_interval.py wan/isis/test_isis_hello_pad.py wan/isis/test_isis_spf_ietf_interval.py wan/isis/test_isis_spf_default_interval.py wan/isis/test_isis_intf_passive.py wan/isis/test_isis_authentication.py wan/isis/test_isis_metric_wide.py"
tests_wol="wol/test_wol.py"
tests_zmq="zmq/test_gnmi_zmq.py"

# declare test_set="tests_acl tests_arp tests_auditd tests_autorestart tests_bfd tests_bgp tests_bmp tests_cacl tests_clock tests_configlet tests_console tests_container_checker tests_container_hardening tests_container_upgrade tests_copp tests_crm tests_dash tests_database tests_db_migrator tests_decap tests_dhcp_relay tests_dhcp_server tests_disk tests_dns tests_drop_packets tests_dut_console tests_ecmp tests_fdb tests_fib tests_fips tests_generic_config_updater tests_gnmi tests_golden_config_infra tests_hash tests_http tests_iface_loopback_action tests_iface_namingmode tests_ip tests_ipfwd tests_ixia tests_k8s tests_kubesonic tests_l2 tests_layer1 tests_lldp tests_log_fidelity tests_macsec tests_mclag tests_memory_checker tests_minigraph tests_monit tests_mvrf tests_nat tests_ntp tests_ospf tests_override_config_table tests_packet_trimming tests_passw_hardening tests_pc tests_performance_meter tests_pfc_asym tests_platform_tests tests_portstat tests_process_monitoring tests_radv tests_read_mac tests_reset_factory tests_restapi tests_route tests_sai_qualify tests_scp tests_sflow tests_show_techsupport tests_smartswitch tests_snappi_tests tests_snmp tests_span tests_srv6 tests_ssh tests_sub_port_interfaces tests_syslog tests_system_health tests_tacacs tests_telemetry tests_testbed_setup tests_transceiver tests_upgrade_path tests_vlan tests_voq tests_vrf tests_vxlan tests_wan tests_wol tests_zmq"



# Test set
if [ "${topo}" = "t1_lag_azure" -o "${topo}" = "t1_azure" ]; then
    declare test_set="tests_pretest tests_bgp tests_vxlan tests_acl tests_arp tests_autorestart tests_bfd tests_cacl tests_clock tests_configlet tests_console tests_container_checker tests_container_hardening tests_copp tests_crm tests_database tests_decap tests_dhcp_relay tests_disk tests_dns tests_drop_packets tests_dut_console tests_fdb tests_features tests_fib tests_generic_config_updater tests_gnmi tests_golden_config_infra tests_hash tests_http tests_iface_loopback_action tests_iface_namingmode tests_interfaces tests_ip tests_ipfwd tests_log_fidelity tests_memory_checker tests_minigraph tests_monit tests_nbr_health tests_ntp tests_override_config_table tests_passw_hardening tests_pc tests_pktgen tests_platform_tests tests_portstat tests_procdockerstatsd tests_process_monitoring tests_radv tests_read_mac tests_reset_factory tests_restapi tests_route tests_scp tests_show_techsupport tests_snmp tests_srv6 tests_ssh tests_stress tests_sub_port_interfaces tests_syslog tests_system_health tests_tacacs tests_telemetry tests_lldp tests_posttest" # Alphabetic sorted. Vxlan moved to front so has a good known (eg to verify combined libsai). LLDP moved to end to avoid corrupting topo if any
    

    #20250718: make sure not commented out single test folder (add at the end to be easier) and add them in, also add pretest and posttest, move bgp and vxlan at first, lldp at last
    declare test_set="tests_pretest tests_vxlan tests_bgp tests_acl tests_arp tests_auditd tests_autorestart tests_bfd  tests_bmp tests_cacl tests_clock tests_configlet tests_console tests_container_checker tests_container_hardening tests_container_upgrade tests_copp tests_crm tests_dash tests_database tests_db_migrator tests_decap tests_dhcp_relay tests_dhcp_server tests_disk tests_dns tests_drop_packets tests_dut_console tests_ecmp tests_fdb tests_fib tests_fips tests_generic_config_updater tests_gnmi tests_golden_config_infra tests_hash tests_http tests_iface_loopback_action tests_iface_namingmode tests_ip tests_ipfwd tests_ixia tests_kubesonic tests_l2 tests_layer1 tests_log_fidelity tests_macsec tests_mclag tests_memory_checker tests_minigraph tests_monit tests_mvrf tests_nat tests_ntp tests_ospf tests_override_config_table tests_packet_trimming tests_passw_hardening tests_pc tests_performance_meter tests_pfc_asym tests_platform_tests tests_portstat tests_process_monitoring tests_radv tests_read_mac tests_reset_factory tests_restapi tests_route tests_sai_qualify tests_scp tests_sflow tests_show_techsupport tests_smartswitch tests_snappi_tests tests_snmp tests_span tests_srv6 tests_ssh tests_sub_port_interfaces tests_syslog tests_system_health tests_tacacs tests_telemetry tests_testbed_setup tests_transceiver tests_upgrade_path tests_vlan tests_voq tests_vrf  tests_wan tests_wol tests_zmq  tests_interfaces tests_features tests_nbr_health tests_pktgen tests_procdockerstatsd  tests_lldp tests_posttest" # full #move vxlan before bgp since some bgp failed may cause topo not ready yet

    declare test_set="tests_pretest tests_vxlan tests_bgp tests_arp tests_bfd tests_fib tests_interfaces tests_ip tests_ipfwd tests_pc tests_route tests_srv6 tests_posttest" # Core only #move vxlan before bgp since some bgp failed may cause topo not ready yet

    # declare test_set="tests_acl tests_auditd tests_autorestart tests_bmp tests_cacl tests_clock tests_configlet tests_console tests_container_checker tests_container_hardening tests_container_upgrade tests_copp tests_crm tests_dash tests_database tests_db_migrator tests_decap tests_dhcp_relay tests_dhcp_server tests_disk tests_dns tests_drop_packets tests_dut_console tests_ecmp tests_fdb tests_fips tests_generic_config_updater tests_gnmi tests_golden_config_infra tests_hash tests_http tests_iface_loopback_action tests_iface_namingmode tests_ixia tests_kubesonic tests_l2 tests_layer1 tests_log_fidelity tests_macsec tests_mclag tests_memory_checker tests_minigraph tests_monit tests_mvrf tests_nat tests_ntp tests_ospf tests_override_config_table tests_packet_trimming tests_passw_hardening tests_performance_meter tests_pfc_asym tests_platform_tests tests_portstat tests_process_monitoring tests_radv tests_read_mac tests_reset_factory tests_restapi tests_sai_qualify tests_scp tests_sflow tests_show_techsupport tests_smartswitch tests_snappi_tests tests_snmp tests_span tests_ssh tests_sub_port_interfaces tests_syslog tests_system_health tests_tacacs tests_telemetry tests_testbed_setup tests_transceiver tests_upgrade_path tests_vlan tests_voq tests_vrf tests_wan tests_wol tests_zmq tests_features tests_nbr_health tests_pktgen tests_procdockerstatsd tests_lldp" # vs-compatible only

else # VXR can't even run some of the high fail test even is pre-test routine with skip markers otherwise may cause the DUT down
    declare test_set="tests_pretest tests_vxlan tests_bgp tests_acl tests_arp tests_autorestart tests_bfd tests_cacl tests_clock tests_configlet tests_console tests_container_checker tests_container_hardening tests_database tests_dhcp_relay tests_disk tests_dns tests_fdb tests_features tests_fib tests_generic_config_updater tests_gnmi tests_golden_config_infra tests_hash tests_iface_loopback_action tests_iface_namingmode tests_interfaces tests_ip tests_ipfwd tests_log_fidelity tests_memory_checker tests_minigraph tests_monit tests_nbr_health tests_ntp tests_override_config_table tests_passw_hardening tests_pc tests_pktgen tests_portstat tests_procdockerstatsd tests_process_monitoring tests_radv tests_read_mac tests_reset_factory tests_restapi tests_route tests_scp tests_show_techsupport tests_snmp tests_srv6 tests_ssh tests_stress tests_system_health tests_tacacs tests_telemetry tests_lldp tests_posttest" # Alphabetic sorted. Vxlan moved to front so has a good known (eg to verify combined libsai). LLDP moved to end to avoid corrupting topo if any # TODO: without tests_http since latest merged master VXR may hang #move vxlan before bgp since some bgp failed may cause topo not ready yet
    declare test_set="tests_pretest tests_vxlan tests_bgp tests_arp tests_fib tests_interfaces tests_ip tests_ipfwd tests_pc tests_route tests_srv6 tests_posttest" # Core only #move vxlan before bgp since some bgp failed may cause topo not ready yet #todo: no bfd which seems cuasing run forever
fi


if [ "${topo}" = "t1" ]; then
    # TODO: below tests are corrupting topo on T1
    tests_cacl="" 
    tests_fib=""
    tests_dns=""
    tests_generic_config_updater=""

    # tests_srv6="srv6/test_srv6_basic_sanity.py srv6/test_srv6_static_config.py" # TODO: uncomment this once mater merged. also need to add the rest of all srv6 tests
fi


if [ "${custom_acl}" = "1" ]; then
    echo "custom acl detected, running test for custom acl..."
    tests_acl="acl/test_acl.py"
    declare test_set="tests_acl"
fi

if [ "${custom_bgp}" = "2" ]; then
    echo "Custom bgp run detected, running test for custom bgp..."
    tests_bgp="bgp/test_bgp_speaker.py bgp/test_bgp_sentinel.py"
    declare test_set="tests_pretest tests_bgp"
fi

rm -f /home/tester/.ssh/known_hosts # this remove somehow only has effect for docker when run inside docker

if [ "${topo}" = "t1_lag_azure" -o "${topo}" = "t1_azure" ]; then
    log_dir="/data/sonic-mgmt/tests/logs/logs_full_tests"
    cd /data/sonic-mgmt/tests/
    # Get image version
    echo "Getting image version info info file..."
    dut=`grep 'vlab-vpp-01' -A 2 /data/sonic-mgmt/ansible/veos_vtb |grep ansible_host: |awk -F ': ' '{print \$2}'`
    sshpass -p cisco123 ssh -o 'StrictHostKeyChecking no' cisco@${dut} 'show version' >| version

    #tmp:
    # tests_bgp="bgp/test_bgp_fact.py"
    # declare test_set="tests_bgp"
    # tests_vxlan="vxlan/test_vxlan_ecmp.py"
    # declare test_set="tests_bgp tests_vxlan"
else
    log_dir="/data/tests/logs/logs_full_tests"
    cd /data/tests
fi

# export for proxy
export HTTP_PROXY=http://jusherma-dev.cisco.com:3128/
export HTTPS_PROXY=http://jusherma-dev.cisco.com:3128/
export NO_PROXY=".cisco.com,.webex.com,localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
export http_proxy=http://jusherma-dev.cisco.com:3128/
export https_proxy=http://jusherma-dev.cisco.com:3128/
export no_proxy=".cisco.com,.webex.com,localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

rm -rf ${log_dir}
mkdir -p ${log_dir}

echo "Start time: `date`" |& tee -a ${log_dir}/logs_full_tests.log
start_time_full_test=`date +%s`
bfd_flag=""
include_long_tests=""

rm -f ${log_dir}/stop_test
stop_test=0


if [ "${topo}" = "t1_lag_azure" -o "${topo}" = "t1_azure" ]; then
    test_folders="acl auditd autorestart bmp cacl clock configlet console container_checker container_hardening container_upgrade copp crm dash database db_migrator decap dhcp_relay dhcp_server disk dns drop_packets dualtor dualtor_io dualtor_mgmt dut_console ecmp everflow fdb fips generic_config_updater gnmi golden_config_infra hash http iface_loopback_action iface_namingmode ixia k8s kubesonic l2 layer1 log_fidelity macsec mclag memory_checker minigraph monit mpls mvrf nat ntp ospf override_config_table packet_trimming passw_hardening performance_meter pfc_asym pfcwd platform_tests portstat process_monitoring qos radv read_mac reset_factory restapi sai_qualify saitests scp sflow show_techsupport smartswitch snappi_tests snmp span ssh stress sub_port_interfaces syslog system_health tacacs telemetry testbed_setup transceiver upgrade_path vlan voq vrf wan wol zmq test_features.py test_nbr_health.py test_parallel_modes test_pktgen.py test_procdockerstatsd.py test_vs_chassis_setup.py lldp" # vs-compatible only
    test_folders="acl auditd autorestart bmp cacl clock configlet console container_checker container_hardening container_upgrade copp crm dash database db_migrator decap dhcp_relay dhcp_server disk dns drop_packets dualtor dualtor_io dualtor_mgmt dut_console ecmp everflow fdb fips generic_config_updater gnmi golden_config_infra hash http iface_loopback_action iface_namingmode ixia kubesonic l2 layer1 log_fidelity macsec mclag memory_checker minigraph monit mpls mvrf nat ntp ospf override_config_table packet_trimming passw_hardening performance_meter pfc_asym pfcwd portstat process_monitoring qos radv read_mac reset_factory restapi scp sflow show_techsupport smartswitch snappi_tests snmp span ssh stress sub_port_interfaces syslog system_health tacacs telemetry testbed_setup transceiver upgrade_path vlan voq vrf wan wol zmq test_features.py test_nbr_health.py test_pktgen.py test_procdockerstatsd.py test_vs_chassis_setup.py lldp" # vs-compatible only #no platform_tests, k8s, sai_qualify, saitests, test_parallel_modes

    test_folders="test_pretest.py vxlan bgp arp bfd fib test_interfaces.py ip ipfwd pc route srv6  acl auditd autorestart bmp cacl clock configlet console container_checker container_hardening container_upgrade copp crm dash database db_migrator decap dhcp_relay dhcp_server disk dns drop_packets dualtor dualtor_io dualtor_mgmt dut_console ecmp everflow fdb fips generic_config_updater gnmi golden_config_infra hash http iface_loopback_action iface_namingmode ixia kubesonic l2 layer1 log_fidelity macsec mclag memory_checker minigraph monit mpls mvrf nat ntp ospf override_config_table packet_trimming passw_hardening performance_meter pfc_asym pfcwd portstat process_monitoring qos radv read_mac reset_factory restapi scp sflow show_techsupport smartswitch snappi_tests snmp span ssh stress sub_port_interfaces syslog system_health tacacs telemetry testbed_setup transceiver upgrade_path vlan voq vrf wan wol zmq test_features.py test_nbr_health.py test_pktgen.py test_procdockerstatsd.py test_vs_chassis_setup.py lldp test_posttest.py" # full #no platform_tests, k8s, sai_qualify, saitests, test_parallel_modes (k8s, sai_qualify, saitests, test_parallel_modes will cause option unknown)
    
    test_folders="test_pretest.py vxlan bgp arp bfd fib test_interfaces.py ip ipfwd pc route srv6 test_posttest.py" # core only
fi
if [ -n "${test_folders}" ]; then
    echo "test folder run detected..."
    for tfo in ${test_folders}; do
        echo "Start time for test feature (${tfo}): `date`" |& tee -a ${log_dir}/logs_full_tests.log
        start_time_test_feature=`date +%s`
        if [ "${stop_test}" -eq 1 ]; then
            echo "Stop test flag detected, stoping test..."
            break
        fi
        
        echo "### Running test folder: ${tfo} ###" |& tee -a ${log_dir}/logs_full_tests.log
        # if [ "${py}" = "vxlan/test_vxlan_ecmp.py" ]; then #n/a
        #     echo "vxlan/test_vxlan_ecmp.py test detected, setting desired test run option..."
        #     bfd_flag="--bfd=True"
        #     include_long_tests="--include_long_tests=True"
        # else
        #     bfd_flag=""
        #     include_long_tests=""
        # fi

        if [ "${topo}" = "t1_lag_azure" -o "${topo}" = "t1_azure" ]; then
            if [ "${topo}" = "t1_lag_azure" ]; then
                tb_name="vms-kvm-vpp-t1-lag"
            elif [ "${topo}" = "t1_azure" ]; then
                tb_name="vms-kvm-vpp-t1"
            fi
            
            ## run_tests.sh in HW run will nuke the log dir prior to each (.py) run. 
            ## Thus need to create a separated feature's tmp log dir and also a outside 
            ## of tmp log dir's runtime console output log. Once run_tests.sh done (for this .py) 
            ## then copy the feature's tmp log dir (which has .xml) into the base log dir, and also
            ## appended the tmp runtime console output log into the base runtime console output log
            # Determine if single or not single .py
            #todo: need to find out how to invoke and handle non folder tests
            # feature=`echo ${py} |xargs dirname` # eg vxlan
            # if [ "${feature}" = "." ]; then # single. create single log dir for it
            #     echo "Single .py without test folder detected..."
            #     feature="`echo ${py} |sed 's:.py$::g'`_single" # eg test_interfaces_single
            #     py_name="${feature}_${py}" # eg test_interfaces_single_test_interfaces.py
            #     target_base_log_dir="${log_dir}/${feature}" # need to create single dir for it
            #     echo "Making single dir (${target_base_log_dir})..."
            #     mkdir -p ${target_base_log_dir} # eg data/sonic-mgmt/tests/logs/logs_full_tests/vxlan or /data/sonic-mgmt/tests/logs/logs_full_tests/test_interfaces_single
            # else
            #     echo "Normal .py within test folder detected..."
            #     py_name=`echo ${py} |sed 's:/:_:g'` # eg vxlan_test_vxlan_ecmp.py
            #     target_base_log_dir="${log_dir}" # run_tests.sh already will gen feature folder. Just normal base log dir
            # fi
            ##
            extension=`echo ${tfo} |cut -d'.' -f2`
            if [ "${extension}" = "py" ]; then # single. create single log dir for it
                echo "Single .py instead of test folder detected..."
                feature="`echo ${tfo} |sed 's:.py$::g'`_single" # eg test_interfaces_single
                py_name="${feature}" # eg test_interfaces_single
                target_base_log_dir="${log_dir}/${feature}" # need to create single dir for it
                echo "Making single dir (${target_base_log_dir})..."
                mkdir -p ${target_base_log_dir} # eg data/sonic-mgmt/tests/logs/logs_full_tests/vxlan or /data/sonic-mgmt/tests/logs/logs_full_tests/test_interfaces_single
            else
                echo "Normal test folder detected..."
                # py_name=`echo ${tfo} |sed 's:/:_:g'` # eg vxlan_test_vxlan_ecmp.py
                py_name=${tfo}
                target_base_log_dir="${log_dir}" # run_tests.sh already will gen feature folder. Just normal base log dir
            fi

            # Create tmp feature's log dir
            mkdir -p ${log_dir}_${py_name} # the tmp feature log dir which the content will be then copoied and appended to the base log dir and log. eg /data/sonic-mgmt/tests/logs/logs_full_tests_vxlan_test_vxlan_ecmp.py

            # Log output into this extra location since run_tests.sh in HW run will nuke the log dir prior to run.
            # Somehow the log dir nuking includes the on-going tee output (eg ${log_dir}/logs_full_tests_${py_name}.log),
            # thus have the tmp runtime console logs output to /data/sonic-mgmt/tests/logs dir which also won't be 
            # having a lot of tmp logs in base log dir 
            # time ./run_tests.sh -n ${tb_name} -d vlab-vpp-01 -O -u -l debug -e -s -e "--disable_loganalyzer --skip_sanity" -m individual -t t1,any -f vtestbed.yaml -i ../ansible/veos_vtb -p ${log_dir}_${py_name} -I ${tfo} |& tee -a ${log_dir}/../logs_full_tests_${py_name}.log
            time ./run_tests.sh -n ${tb_name} -d vlab-vpp-01 -O -u -l debug -e -s -e "--disable_sai_validation --disable_loganalyzer" -m individual -t t1,any -f vtestbed.yaml -i ../ansible/veos_vtb -p ${log_dir}_${py_name} -I ${tfo} |& tee -a ${log_dir}/../logs_full_tests_${py_name}.log

            # Check if .py has any error/fail, if so sleep for sometime to allow TB state to recover before proceeding to subsequent .py test
            #todo: also pause for test folder may not be menaingful
            # echo "Checking if .py under test folder (${tfo}) has any error/fail..."
            # py_xml_name="`echo ${py} |sed 's:.py$:.xml:g'`" #eg bgp/test_bgp_fact.py. Thus for single test it has no feature folder
            # # test_file=`ls ${log_dir}_${py_name}/${feature}/*.xml 2>/dev/null` #can't use this since single test has no feature folder
            # test_file=`ls ${log_dir}_${py_name}/${py_xml_name} 2>/dev/null`
            # if [ -z "${test_file}" ]; then
            #     echo "ERROR: test file (${log_dir}_${py_name}/${py_xml_name}) doesn't exist, stop testing..."
            #     stop_test=1 # need this for upper loop

            #     ## Retrieve tmp feature's log artifact and runtime console output
            #     # Copy the feature's tmp log dir (which has .xml) into the base log dir
            #     cp ${log_dir}/../logs_full_tests_${py_name}.log ${log_dir}_${py_name} # have this individual log as well for quick check
            #     cp -rp ${log_dir}_${py_name}/* ${target_base_log_dir} # -rp since need copy the feature dir altogether
            #     # Append runtime log output into main runtime log output
            #     cat ${log_dir}/../logs_full_tests_${py_name}.log >> ${log_dir}/logs_full_tests.log # put it back into base log
            #     chmod 777 -R ${log_dir}_${py_name} # to allow deletion in case in future copied into logs nightly archive
            #     break
            # else
            #     echo "Get error/fail cnt for test file (${test_file})..."
            #     errors_cnt=$(egrep "errors=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
            #     failures_cnt=$(egrep "failures=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
            #     tests_cnt=$(egrep "tests=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
            #     skipped_cnt=$(egrep "skipped=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
            #     echo "errors_cnt=${errors_cnt}, failures_cnt=${failures_cnt}, tests_cnt=${tests_cnt}, skipped_cnt=${skipped_cnt}"
            #     if [ "$errors_cnt" -gt 0 -o "$failures_cnt" -gt 0 ]; then
            #         echo "WARNING: test file (${test_file}) has errors/failures ($errors_cnt/$failures_cnt), sleep for a while..."
            #         sleep 300
            #     else
            #         echo "No errors/failures in test file (${test_file}), continue testing without sleep..."
            #     fi
            # fi

            ## Retrieve tmp feature's log artifact and runtime console output
            # Copy the feature's tmp log dir (which has .xml) into the base log dir
            cp ${log_dir}/../logs_full_tests_${py_name}.log ${log_dir}_${py_name} # have this individual log as well for quick check
            cp -rp ${log_dir}_${py_name}/* ${target_base_log_dir} # -rp since need copy the feature dir altogether
            # Append runtime log output into main runtime log output
            cat ${log_dir}/../logs_full_tests_${py_name}.log >> ${log_dir}/logs_full_tests.log # put it back into base log
            chmod 777 -R ${log_dir}_${py_name} # to allow deletion in case in future copied into logs nightly archive


        fi #azure
        echo "### Done running test folder: ${tfo} ###" |& tee -a ${log_dir}/logs_full_tests.log
        echo "End time for test feature (${tfo}): `date`" |& tee -a ${log_dir}/logs_full_tests.log
        end_time_test_feature=`date +%s`
        elapse_time=$((${end_time_test_feature} - ${start_time_test_feature}))
        echo "Elapse time for test feature (${tfo}): (`date -ud \"@${elapse_time}\" +\"$((${elapse_time}/3600/24))d:%Hh:%Mm:%Ss\"`)" |& tee -a ${log_dir}/logs_full_tests.log

        sleep 60 #for each folder to have a bit nap
    done
    echo "End time: `date`" |& tee -a ${log_dir}/logs_full_tests.log
    end_time_full_test=`date +%s`
    elapse_time=$((${end_time_full_test} - ${start_time_full_test}))
    echo "Elapse time for full test: (`date -ud \"@${elapse_time}\" +\"$((${elapse_time}/3600/24))d:%Hh:%Mm:%Ss\"`)" |& tee -a ${log_dir}/logs_full_tests.log
else


for tf in ${test_set}; do
    echo "Start time for test feature (${tf}): `date`" |& tee -a ${log_dir}/logs_full_tests.log
    start_time_test_feature=`date +%s`
    if [ "${stop_test}" -eq 1 ]; then
        echo "Stop test flag detected, stoping test..."
        break
    fi
    for py in ${!tf}; do
        # feature=`echo ${py} |xargs dirname`
        # if [ "${feature}" = "bgp" ]; then
        #     echo "bgp .py detected, sleep for 150 first"
        #     sleep 150
        # fi
        echo "Start time for test file (${py}): `date`" |& tee -a ${log_dir}/logs_full_tests.log
        start_time_test_file=`date +%s`
        echo "### Running test file: ${py} ###" |& tee -a ${log_dir}/logs_full_tests.log
        if [ "${py}" = "vxlan/test_vxlan_ecmp.py" ]; then
            echo "vxlan/test_vxlan_ecmp.py test detected, setting desired test run option..."
            bfd_flag="--bfd=True"
            include_long_tests="--include_long_tests=True"
        else
            bfd_flag=""
            include_long_tests=""
        fi

        # if [ "${py}" = "bgp/test_bgp_fact.py" ]; then
        #     echo "bgp/test_bgp_fact.py test detected, setting pretest run option..."
        #     pretest="test_pretest.py"
        # else
        #     pretest=""
        # fi

        if [ "${topo}" = "t1_lag_azure" -o "${topo}" = "t1_azure" ]; then
            if [ "${topo}" = "t1_lag_azure" ]; then
                tb_name="vms-kvm-vpp-t1-lag"
            elif [ "${topo}" = "t1_azure" ]; then
                tb_name="vms-kvm-vpp-t1"
            fi
            
            ## run_tests.sh in HW run will nuke the log dir prior to each (.py) run. 
            ## Thus need to create a separated feature's tmp log dir and also a outside 
            ## of tmp log dir's runtime console output log. Once run_tests.sh done (for this .py) 
            ## then copy the feature's tmp log dir (which has .xml) into the base log dir, and also
            ## appended the tmp runtime console output log into the base runtime console output log
            # Determine if single or not single .py
            feature=`echo ${py} |xargs dirname` # eg vxlan
            if [ "${feature}" = "." ]; then # single. create single log dir for it
                echo "Single .py without test folder detected..."
                feature="`echo ${py} |sed 's:.py$::g'`_single" # eg test_interfaces_single
                py_name="${feature}_${py}" # eg test_interfaces_single_test_interfaces.py
                target_base_log_dir="${log_dir}/${feature}" # need to create single dir for it
                echo "Making single dir (${target_base_log_dir})..."
                mkdir -p ${target_base_log_dir} # eg data/sonic-mgmt/tests/logs/logs_full_tests/vxlan or /data/sonic-mgmt/tests/logs/logs_full_tests/test_interfaces_single
            else
                echo "Normal .py within test folder detected..."
                py_name=`echo ${py} |sed 's:/:_:g'` # eg vxlan_test_vxlan_ecmp.py
                target_base_log_dir="${log_dir}" # run_tests.sh already will gen feature folder. Just normal base log dir
            fi
            # Create tmp feature's log dir
            mkdir -p ${log_dir}_${py_name} # the tmp feature log dir which the content will be then copoied and appended to the base log dir and log. eg /data/sonic-mgmt/tests/logs/logs_full_tests_vxlan_test_vxlan_ecmp.py

            # Log output into this extra location since run_tests.sh in HW run will nuke the log dir prior to run.
            # Somehow the log dir nuking includes the on-going tee output (eg ${log_dir}/logs_full_tests_${py_name}.log),
            # thus have the tmp runtime console logs output to /data/sonic-mgmt/tests/logs dir which also won't be 
            # having a lot of tmp logs in base log dir 
            time ./run_tests.sh -n ${tb_name} -d vlab-vpp-01 -O -u -l debug -e -s -e "--disable_loganalyzer --skip_sanity ${pretest} ${bfd_flag} ${include_long_tests}" -e -m individual -t t1,any -f vtestbed.yaml -i ../ansible/veos_vtb -p ${log_dir}_${py_name} -c ${py} |& tee -a ${log_dir}/../logs_full_tests_${py_name}.log

            # Check if no passed in test_bgp_sentinel.py, if so will stop test for debugging
            # if [ "${py}" = "bgp/test_bgp_sentinel.py" ]; then
            if [ "${py}" = "bgp/test_bgp_sentinel.py.disable_stop_test" ]; then # check against invalid .py name to disable stop test
                echo "bgp/test_bgp_sentinel.py detected, check if 0 passed, if so will stop the tests..."
                cwd=`pwd`
                test_file=`ls ${log_dir}_${py_name}/bgp/test_bgp_sentinel.xml 2>/dev/null`
                if [ -z "${test_file}" ]; then
                    echo "ERROR: test file (bgp/test_bgp_sentinel.xml) doesn't exist, stop testing..."
                    stop_test=1 # need this for upper loop
                    break
                else
                    echo "Get pass testcases for test file (${test_file})..."
                    rm -f ${cwd}/testcases_bgp_sentinel
                    grep "<testcase .*</testcase>" -o ${test_file} |sed 's:</testcase>:</testcase>\n:g' >| ${cwd}/testcases_bgp_sentinel
                    if [ -f "${cwd}/testcases_bgp_sentinel" ]; then 
                        echo "Found testcase tag for test file (${test_file}) and testcases file populated, generating passed_testcases file..."
                        sed -i '$ d' ${cwd}/testcases_bgp_sentinel # remove the extra ending newline
                        rm -f ${cwd}/passed_testcases_bgp_sentinel
                        while read f; do
                            echo $f | grep -q "Failed\|error\|skipped"
                            if [ $? -ne 0 ]; then # not found, tc pass
                                testcase_name=`echo $f |grep "name=\"test_.*\" " -o -m 1 |awk -F ' ' '{print $1}' | sed 's:name="::g' | sed 's:"::g'`
                                if [ -n "${testcase_name}" ]; then # not sure why via testcase_name var will have some emtpy line
                                    echo "PASSED ${testcase_name}" >> ${cwd}/passed_testcases_bgp_sentinel
                                fi
                            fi
                        done < ${cwd}/testcases_bgp_sentinel
                        if [ -f "${cwd}/passed_testcases_bgp_sentinel" ]; then
                            echo
                            echo "Passed testcases for test file (${test_file}), will proceed to subsequence tsets if any:"
                            cat ${cwd}/passed_testcases_bgp_sentinel
                        else
                            echo
                            echo "INFO: no passed testcases found (ie all testcases either fail/error/skip) for test file (${test_file}), stop testing"
                            stop_test=1
                            ## Retrieve tmp feature's log artifact and runtime console output
                            # Copy the feature's tmp log dir (which has .xml) into the base log dir
                            cp ${log_dir}/../logs_full_tests_${py_name}.log ${log_dir}_${py_name} # have this individual log as well for quick check
                            cp -rp ${log_dir}_${py_name}/* ${target_base_log_dir} # -rp since need copy the feature dir altogether
                            # Append runtime log output into main runtime log output
                            cat ${log_dir}/../logs_full_tests_${py_name}.log >> ${log_dir}/logs_full_tests.log # put it back into base log
                            chmod 777 -R ${log_dir}_${py_name} # to allow deletion in case in future copied into logs nightly archive
                            break
                        fi
                    else
                        echo "ERROR: No testcase tag found for test file (${test_file}), won't be able to check for whether has passed testcases, stop testing..."
                        stop_test=1
                        ## Retrieve tmp feature's log artifact and runtime console output
                        # Copy the feature's tmp log dir (which has .xml) into the base log dir
                        cp ${log_dir}/../logs_full_tests_${py_name}.log ${log_dir}_${py_name} # have this individual log as well for quick check
                        cp -rp ${log_dir}_${py_name}/* ${target_base_log_dir} # -rp since need copy the feature dir altogether
                        # Append runtime log output into main runtime log output
                        cat ${log_dir}/../logs_full_tests_${py_name}.log >> ${log_dir}/logs_full_tests.log # put it back into base log
                        chmod 777 -R ${log_dir}_${py_name} # to allow deletion in case in future copied into logs nightly archive
                        break
                    fi
                fi
            fi

            # Check if .py has any error/fail, if so sleep for sometime to allow TB state to recover before proceeding to subsequent .py test
            echo "Checking if .py (${py}) has any error/fail..."
            py_xml_name="`echo ${py} |sed 's:.py$:.xml:g'`" #eg bgp/test_bgp_fact.py. Thus for single test it has no feature folder
            # test_file=`ls ${log_dir}_${py_name}/${feature}/*.xml 2>/dev/null` #can't use this since single test has no feature folder
            test_file=`ls ${log_dir}_${py_name}/${py_xml_name} 2>/dev/null`
            if [ -z "${test_file}" ]; then
                echo "ERROR: test file (${log_dir}_${py_name}/${py_xml_name}) doesn't exist, stop testing..."
                stop_test=1 # need this for upper loop

                ## Retrieve tmp feature's log artifact and runtime console output
                # Copy the feature's tmp log dir (which has .xml) into the base log dir
                cp ${log_dir}/../logs_full_tests_${py_name}.log ${log_dir}_${py_name} # have this individual log as well for quick check
                cp -rp ${log_dir}_${py_name}/* ${target_base_log_dir} # -rp since need copy the feature dir altogether
                # Append runtime log output into main runtime log output
                cat ${log_dir}/../logs_full_tests_${py_name}.log >> ${log_dir}/logs_full_tests.log # put it back into base log
                chmod 777 -R ${log_dir}_${py_name} # to allow deletion in case in future copied into logs nightly archive
                break
            else
                echo "Get error/fail cnt for test file (${test_file})..."
                errors_cnt=$(egrep "errors=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
                failures_cnt=$(egrep "failures=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
                tests_cnt=$(egrep "tests=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
                skipped_cnt=$(egrep "skipped=\"[0-9]{1}[0-9]*\"" -o ${test_file} |awk -F "=" '{print $2}' |sed 's:"::g')
                echo "errors_cnt=${errors_cnt}, failures_cnt=${failures_cnt}, tests_cnt=${tests_cnt}, skipped_cnt=${skipped_cnt}"
                if [ "$errors_cnt" -gt 0 -o "$failures_cnt" -gt 0 ]; then
                    echo "WARNING: test file (${test_file}) has errors/failures ($errors_cnt/$failures_cnt), sleep for a while..."
                    sleep 300
                else
                    echo "No errors/failures in test file (${test_file}), continue testing without sleep..."
                fi
            fi

            ## Retrieve tmp feature's log artifact and runtime console output
            # Copy the feature's tmp log dir (which has .xml) into the base log dir
            cp ${log_dir}/../logs_full_tests_${py_name}.log ${log_dir}_${py_name} # have this individual log as well for quick check
            cp -rp ${log_dir}_${py_name}/* ${target_base_log_dir} # -rp since need copy the feature dir altogether
            # Append runtime log output into main runtime log output
            cat ${log_dir}/../logs_full_tests_${py_name}.log >> ${log_dir}/logs_full_tests.log # put it back into base log
            chmod 777 -R ${log_dir}_${py_name} # to allow deletion in case in future copied into logs nightly archive
        else
            time ./run_tests.sh -n docker-ptf -d vpp-01 -O -u -l debug -e -s -e "--disable_loganalyzer --skip_sanity ${pretest} ${bfd_flag} ${include_long_tests}" -m individual -t t1,any -p ${log_dir} -c ${py} |& tee -a ${log_dir}/logs_full_tests.log

            # Check if no passed in test_bgp_sentinel.py, if so will stop test for debugging
            # if [ "${py}" = "bgp/test_bgp_sentinel.py" ]; then
            if [ "${py}" = "bgp/test_bgp_sentinel.py.disable_stop_test" ]; then # check against invalid .py name to disable stop test
                echo "bgp/test_bgp_sentinel.py detected, check if 0 passed, if so will stop the tests..."
                cwd=`pwd`
                test_file=`ls ${log_dir}/bgp/test_bgp_sentinel_202*.xml 2>/dev/null`
                if [ -z "${test_file}" ]; then
                    echo "ERROR: test file (bgp/test_bgp_sentinel_202*.xml) doesn't exist, stop testing..."
                    stop_test=1
                    break
                else
                    echo "Get pass testcases for test file (${test_file})..."
                    rm -f ${cwd}/testcases_bgp_sentinel
                    grep "<testcase .*</testcase>" -o ${test_file} |sed 's:</testcase>:</testcase>\n:g' >| ${cwd}/testcases_bgp_sentinel
                    if [ -f "${cwd}/testcases_bgp_sentinel" ]; then 
                        echo "Found testcase tag for test file (${test_file}) and testcases file populated, generating passed_testcases file..."
                        sed -i '$ d' ${cwd}/testcases_bgp_sentinel # remove the extra ending newline
                        rm -f ${cwd}/passed_testcases_bgp_sentinel
                        while read f; do
                            echo $f | grep -q "Failed\|error\|skipped"
                            if [ $? -ne 0 ]; then # not found, tc pass
                                testcase_name=`echo $f |grep "name=\"test_.*\" " -o -m 1 |awk -F ' ' '{print $1}' | sed 's:name="::g' | sed 's:"::g'`
                                if [ -n "${testcase_name}" ]; then # not sure why via testcase_name var will have some emtpy line
                                    echo "PASSED ${testcase_name}" >> ${cwd}/passed_testcases_bgp_sentinel
                                fi
                            fi
                        done < ${cwd}/testcases_bgp_sentinel
                        if [ -f "${cwd}/passed_testcases_bgp_sentinel" ]; then
                            echo
                            echo "Passed testcases for test file (${test_file}), will proceed to subsequence tsets if any:"
                            cat ${cwd}/passed_testcases_bgp_sentinel
                        else
                            echo
                            echo "INFO: no passed testcases found (ie all testcases either fail/error/skip) for test file (${test_file}), stop testing"
                            stop_test=1
                            break
                        fi
                    else
                        echo "ERROR: No testcase tag found for test file (${test_file}), won't be able to check for whether has passed testcases, stop testing..."
                        stop_test=1
                        break
                    fi
                fi
            fi

            # Check if too many errors in test_acl.py, if so will stop test for debugging
            if [ "${py}" = "acl/test_acl.py" ]; then
                echo "acl/test_acl.py detected, check if error more than 10, if so will stop the tests..."
                cwd=`pwd`
                test_file=`ls ${log_dir}/acl/test_acl_202*.xml 2>/dev/null`
                if [ -z "${test_file}" ]; then
                    echo "ERROR: test file (acl/test_acl_202*.xml) doesn't exist, stop testing..."
                    stop_test=1
                    break
                else
                    echo "Get error testcases counts for test file (${test_file})..."
                    err_cnt=`egrep "errors=\"[0-9]{1}[0-9]*\"" ${test_file} -o |awk -F "=" '{print $2}' |sed 's:"::g'`
                    if [ -n "{$err_cnt}" ]; then
                        if [ "{$err_cnt}" -gt 10 ]; then
                            echo "Error testcases (${err_cnt}) for test file (${test_file}) is more than 10, stop testing"
                            stop_test=1
                            break
                        else
                            echo "Error testcases (${err_cnt}) for test file (${test_file}) is not more than 10, will proceed to subsequence tests if any:"
                        fi
                    else
                        echo "ERROR: No errors counts string found for test file (${test_file}), won't be able to determine whether has error, stop testing..."
                        stop_test=1
                        break
                    fi
                fi
            fi
        fi
        echo "### Done running test file: ${py} ###" |& tee -a ${log_dir}/logs_full_tests.log
        echo
        echo "End time for test file (${py}): `date`" |& tee -a ${log_dir}/logs_full_tests.log
        end_time_test_file=`date +%s`
        elapse_time=$((${end_time_test_file} - ${start_time_test_file}))
        echo "Elapse time for test file (${py}): (`date -ud \"@${elapse_time}\" +\"$((${elapse_time}/3600/24))d:%Hh:%Mm:%Ss\"`)" |& tee -a ${log_dir}/logs_full_tests.log
    done
    echo "End time for test feature (${tf}): `date`" |& tee -a ${log_dir}/logs_full_tests.log
    end_time_test_feature=`date +%s`
    elapse_time=$((${end_time_test_feature} - ${start_time_test_feature}))
    echo "Elapse time for test feature (${tf}): (`date -ud \"@${elapse_time}\" +\"$((${elapse_time}/3600/24))d:%Hh:%Mm:%Ss\"`)" |& tee -a ${log_dir}/logs_full_tests.log
done
echo "End time: `date`" |& tee -a ${log_dir}/logs_full_tests.log
end_time_full_test=`date +%s`
elapse_time=$((${end_time_full_test} - ${start_time_full_test}))
echo "Elapse time for full test: (`date -ud \"@${elapse_time}\" +\"$((${elapse_time}/3600/24))d:%Hh:%Mm:%Ss\"`)" |& tee -a ${log_dir}/logs_full_tests.log

fi #


# If stop test flag detected then touch this file so host will immediately send a fail email without waiting on report processing to avoid topo bad state restored
if [ "${stop_test}" -eq 1 ]; then
    touch ${log_dir}/stop_test
    chmod 777 ${log_dir}/stop_test
fi

# Copy out log
echo
echo "Copying out logs to (${nightly_archive_dir})..."
# Need to make sure make dir first in case not called by wrapper script
sshpass -p foo123 ssh -o "StrictHostKeyChecking no" foo@10.85.202.68 "mkdir -p ${nightly_archive_dir} && chmod 777 -R ${nightly_archive_dir}"
# Need to chmod 777 otherwise will be limited permission under user cloud-user
chmod 777 -R ${log_dir}
sshpass -p foo123 scp -o "StrictHostKeyChecking no" -rp ${log_dir} foo@10.85.202.68:${nightly_archive_dir}/logs_full_tests.nightly_${timestamp}

echo
echo "Done run_tests_vpp_wrapper.sh script"