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

exec /usr/local/bin/supervisord "$@"
