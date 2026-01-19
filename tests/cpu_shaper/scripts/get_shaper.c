int get_cosq_shaper(bcm_port_t port, bcm_cos_queue_t cosq, uint32 kbits_sec_min, uint32 kbits_sec_max, uint32 flags)
{
    int rv=0;
    rv = bcm_cosq_port_bandwidth_get(0,port,cosq, &kbits_sec_min, &kbits_sec_max, &flags);
    if (rv < 0) {
        printf("bcm_cosq_port_bandwidth_get failed for port=%d, cos=%d, pps_max=%d, rv=%d\n", port, cosq, kbits_sec_max,rv);
        return rv;
    }
    printf("bcm_cosq_port_bandwidth_get for port=%d, cos=%d pps_max=%d\n", port, cosq, kbits_sec_max);
    return 0;
}

print get_cosq_shaper(0, 0, 0, 0, 0);
print get_cosq_shaper(0, 7, 0, 0, 0);
