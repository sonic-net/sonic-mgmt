# exec
pytest -s sflow_ap.py \
    --selective-test-file=selective_test_file.txt \
    --topology-file "./../th3_4_topo.json" \
    --tb=short \
    --test-input-file="./../gd_input_file.json" \
    --mail-to=pevenkat@cisco.com \
    --mail-from=no-reply@cisco.com \
    --debug-enable \
    -m 'not Future' \
    -p no:cacheprovider