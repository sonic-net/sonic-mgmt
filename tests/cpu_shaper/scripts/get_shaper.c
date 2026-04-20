int get_cosq_shaper(bcm_port_t port, bcm_cos_queue_t cosq,
                    uint32 kbits_sec_min, uint32 kbits_sec_max,
                    uint32 flags)
{
    int rv = 0;
    bcm_gport_t gport;

    /* Try gport-based API first */
    rv = bcm_port_gport_get(0, port, &gport);
    if (rv == BCM_E_NONE) {
        rv = bcm_cosq_gport_bandwidth_get(0, gport, cosq,
                                          &kbits_sec_min,
                                          &kbits_sec_max,
                                          &flags);
        if (rv == BCM_E_NONE) {
            printf("bcm_cosq_gport_bandwidth_get for port=%d, cos=%d pps_max=%d\n",
                   port, cosq, kbits_sec_max);
            return 0;
        }

        if (rv != BCM_E_UNAVAIL) {
            printf("bcm_cosq_gport_bandwidth_get failed for port=%d, cos=%d, rv=%d\n",
                   port, cosq, rv);
            return rv;
        }
    }

    /* Fallback to legacy port API */
    rv = bcm_cosq_port_bandwidth_get(0, port, cosq,
                                     &kbits_sec_min,
                                     &kbits_sec_max,
                                     &flags);
    if (rv < 0) {
        printf("bcm_cosq_port_bandwidth_get failed for port=%d, cos=%d, pps_max=%d, rv=%d\n",
               port, cosq, kbits_sec_max, rv);
        return rv;
    }

    printf("bcm_cosq_port_bandwidth_get for port=%d, cos=%d pps_max=%d\n",
           port, cosq, kbits_sec_max);
    return 0;
}

print get_cosq_shaper(0, 0, 0, 0, 0);
print get_cosq_shaper(0, 7, 0, 0, 0);
