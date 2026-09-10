/*
 * BCM Q3D CINT script to disable a trap by clearing its trap and snoop strengths.
 * Intended to suppress predefined traps on the fanout that may interrupt traffic
 * flow between the test server and the DUT.
 */
void disable_trap(int unit, bcm_rx_trap_t trap_type, char *trap_name)
{
    int rv;
    int trap_id;
    bcm_rx_trap_config_t config;

    printf("Disabling trap: %s\n", trap_name);

    rv = bcm_rx_trap_type_create(unit, 0, trap_type, &trap_id);
    if (rv == BCM_E_EXISTS) {
        rv = bcm_rx_trap_type_get(unit, 0, trap_type, &trap_id);
        if (rv != BCM_E_NONE) {
            printf("WARN: bcm_rx_trap_type_get failed for %s, rv=%d\n",
                   trap_name, rv);
            return;
        }
    } else if (rv != BCM_E_NONE) {
        printf("WARN: bcm_rx_trap_type_create failed for %s, rv=%d\n",
               trap_name, rv);
        return;
    }

    /* Read the current config first, then only modify strengths */
    bcm_rx_trap_config_t_init(&config);
    rv = bcm_rx_trap_get(unit, trap_id, &config);
    if (rv != BCM_E_NONE) {
        printf("WARN: bcm_rx_trap_get failed for trap_id=0x%x (%s), rv=%d\n",
               trap_id, trap_name, rv);
        return;
    }

    /* Zero the strengths so this trap loses in action resolution */
    config.trap_strength = 0;
    config.snoop_strength = 0;

    rv = bcm_rx_trap_set(unit, trap_id, &config);
    if (rv != BCM_E_NONE) {
        printf("WARN: bcm_rx_trap_set failed for trap_id=0x%x (%s), rv=%d\n",
               trap_id, trap_name, rv);
    }
}

int unit = 0;
disable_trap(unit, bcmRxTrapIpCompMcInvalidIp, "IpCompMcInvalidIp");
