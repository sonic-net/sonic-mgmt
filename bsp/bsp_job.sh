# exec
pytest bsp.py \
    --topology-file bsp_topo.json \
    --tb=short \
    --test-input-file="./../gd_input_file.json" \
    --mail-to=nivin@cisco.com \
    --mail-from=no-reply@cisco.com \
    --debug-enable \
    -m 'not Future' \
    -p no:cacheprovider
