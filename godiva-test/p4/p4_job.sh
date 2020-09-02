# exec
test_type="func"
topo_file="./../th3_5_topo.json"
email="pevenkat@cisco.com"
func=false;neg=false;stress=false;failed=false

while getopts ":t:f:m:" flag
do
    case "${flag}" in
        t) test_type=${OPTARG};;
        f) topo_file=${OPTARG};;
        m) email=${OPTARG};;
        ?)
            echo "script usage: $(basename $0) [-t all|func|neg|stress|failed|test] [-f topo_file] [-m user email]" >&2
            exit 1;;
    esac
done

case "$test_type" in
    *"all"*)
        func=true
        neg=true
        stress=true
        failed=true
        test=false
    ;;
    *"func"*)
        func=true
    ;;
    *"neg"*)
        neg=true
    ;;
    *"stress"*)
        stress=true
    ;;
    *"failed"*)
        failed=true
    ;;
    *"test"*)
        test=true
    ;;
    *"none"*)
        func=false
        neg=false
        stress=false
        failed=false
        test=false
    ;;
esac

if $func ; then
    pytest -s p4_ap.py \
        --selective-test-file=selective_test_file.txt \
        --topology-file $topo_file \
        --tb=short \
        --test-input-file="./../gd_input_file.json" \
        --mail-to=$email \
        --mail-from=no-reply@cisco.com \
        --debug-enable \
        -m 'not Future' \
        -p no:cacheprovider
fi

if $neg ; then
    pytest -s p4_ap.py \
        --selective-test-file=p4_negative_tc.txt \
        --topology-file $topo_file \
        --tb=short \
        --test-input-file="./../gd_input_file.json" \
        --mail-to=$email \
        --mail-from=no-reply@cisco.com \
        --debug-enable \
        -m 'not Future' \
        -p no:cacheprovider
fi

if $stress ; then
    pytest -s p4_ap.py \
        --selective-test-file=stress_scale_test_file.txt \
        --topology-file $topo_file \
        --tb=short \
        --test-input-file="./../gd_input_file.json" \
        --mail-to=$email \
        --mail-from=no-reply@cisco.com \
        --debug-enable \
        -m 'not Future' \
        -p no:cacheprovider
fi

if $failed ; then
    pytest -s p4_ap.py \
        --selective-test-file=failed_test_file.txt \
        --topology-file $topo_file \
        --tb=short \
        --test-input-file="./../gd_input_file.json" \
        --mail-to=$email \
        --mail-from=no-reply@cisco.com \
        --debug-enable \
        -m 'not Future' \
        -p no:cacheprovider
fi

if $test ; then
    pytest -s p4_ap.py \
        --selective-test-file=test_file.txt \
        --topology-file $topo_file \
        --tb=short \
        --test-input-file="./../gd_input_file.json" \
        --mail-to=$email \
        --mail-from=no-reply@cisco.com \
        --debug-enable \
        -m 'not Future' \
        -p no:cacheprovider
fi

repeat=false
if $repeat ; then
    for value in {1..2}
        do
            pytest -s p4_ap.py \
                --selective-test-file=failed_test_file.txt \
                --topology-file $topo_file \
                --tb=short \
                --test-input-file="./../gd_input_file.json" \
                --mail-to=$email \
                --mail-from=no-reply@cisco.com \
                --debug-enable \
                -m 'not Future' \
                -p no:cacheprovider
        done
fi
