#!/bin/bash
set -e

# docker-sonic-vs bakes a monolithic supervisor config using stock metadata. A
# converged CONFIG_DB uses the generic per-VRF BGP tables, which are owned by
# frrcfgd. Switch that program and add frrcfgd's required FRR daemons before
# supervisord parses the baked config; re-rendering from the BGP-container
# template would drop the other cSONiC daemons from this all-in-one image.
config=/var/sonic/config_db.json
supervisor=/etc/supervisor/conf.d/supervisord.conf
if grep -q '"frr_mgmt_framework_config"[[:space:]]*:[[:space:]]*"true"' "$config"; then
    sed -i \
        -e 's/^\[program:bgpcfgd\]$/[program:frrcfgd]/' \
        -e 's#^command=/usr/local/bin/bgpcfgd$#command=/usr/local/bin/frrcfgd#' \
        "$supervisor"
    cp /var/sonic/csonic_frr_daemons.conf \
        /etc/supervisor/conf.d/csonic_frr_daemons.conf
fi

# Reuse the FRR image's startup environment contract when available. Older
# docker-sonic-vs images do not contain the helper, so retain the safe default.
if [[ -r /usr/bin/frr_startup_init.sh ]]; then
    source /usr/bin/frr_startup_init.sh
    initialize_frr_startup_environment --normal-start
else
    export BGPD_GRACEFUL_RESTART_ARG="${BGPD_GRACEFUL_RESTART_ARG:-}"
fi

exec /usr/local/bin/supervisord "$@"
