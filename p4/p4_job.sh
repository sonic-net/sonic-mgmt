# exec
pytest p4_ap.py \
    --selective-test-file=selective_test_file.txt \
    --topology-file p4_topo.json \
    --tb=short \
    --test-input-file="./../gd_input_file.json" \
    --mail-to=pevenkat@cisco.com \
    --mail-from=no-reply@cisco.com \
    --debug-enable \
    -m 'not Future' \
    -p no:cacheprovider