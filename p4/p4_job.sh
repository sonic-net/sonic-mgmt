# exec
skip=false
if $skip ; then
pytest -s p4_ap.py \
    --selective-test-file=selective_test_file.txt \
    --topology-file p4_topo.json \
    --tb=short \
    --test-input-file="./../gd_input_file.json" \
    --mail-to=nivin@cisco.com \
    --mail-from=no-reply@cisco.com \
    --debug-enable \
    -m 'not Future' \
    -p no:cacheprovider

pytest -s p4_ap.py \
    --selective-test-file=p4_negative_tc.txt \
    --topology-file p4_topo.json \
    --tb=short \
    --test-input-file="./../gd_input_file.json" \
    --mail-to=pevenkat@cisco.com \
    --mail-from=no-reply@cisco.com \
    --debug-enable \
    -m 'not Future' \
    -p no:cacheprovider
fi

for value in {1..2}
do
    pytest -s p4_ap.py \
        --selective-test-file=failed_test_file.txt \
        --topology-file p4_topo.json \
        --tb=short \
        --test-input-file="./../gd_input_file.json" \
        --mail-to=pevenkat@cisco.com \
        --mail-from=no-reply@cisco.com \
        --debug-enable \
        -m 'not Future' \
        -p no:cacheprovider
done