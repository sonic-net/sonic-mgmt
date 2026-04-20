int get_cosq_shaper(bcm_port_t port, bcm_cos_queue_t cosq, uint32 kbits_sec_min, uint32 kbits_sec_max, uint32 flags)
{
    int rv=0;
    int rv_gport=0;
    bcm_gport_t gport=0;

    /* Try gport-based API first (works on both DNX and XGS) */
    BCM_GPORT_LOCAL_SET(gport, port);
    rv_gport = bcm_cosq_gport_bandwidth_get(0, gport, cosq, &kbits_sec_min, &kbits_sec_max, &flags);
    if (rv_gport == 0) {
        printf("bcm_cosq_gport_bandwidth_get for port=%d, cos=%d pps_max=%d\n", port, cosq, kbits_sec_max);
        return 0;
    }
    /* Fall back to port-based API (works on XGS only) */
    kbits_sec_min = 0;
    kbits_sec_max = 0;
    flags = 0;
    rv = bcm_cosq_port_bandwidth_get(0, port, cosq, &kbits_sec_min, &kbits_sec_max, &flags);
    if (rv == 0) {
        printf("bcm_cosq_port_bandwidth_get for port=%d, cos=%d pps_max=%d\n", port, cosq, kbits_sec_max);
        return 0;
    }
    /* Both APIs failed, log both return codes for debugging */
    printf("All cosq bandwidth APIs failed for port=%d, cos=%d: gport_rv=%d, legacy_rv=%d\n", port, cosq, rv_gport, rv);
    return rv;
}

print get_cosq_shaper(0, 0, 0, 0, 0);
print get_cosq_shaper(0, 7, 0, 0, 0);
