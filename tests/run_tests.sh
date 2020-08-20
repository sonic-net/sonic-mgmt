#!/bin/bash

function show_help_and_exit()
{
    echo "Usage ${SCRIPT} [options]"
    echo "    options with (*) must be provided"
    echo "    -h -?          : get this help"
    echo "    -a <True|False>: specify if autu-recover is allowed (default: True)"
    echo "    -c <testcases> : specify test cases to execute (default: none, executed all matched)"
    echo "    -d <dut name>  : specify DUT name (*)"
    echo "    -e <parameters>: specify extra parameter(s) (default: none)"
    echo "    -f <tb file>   : specify testbed file (default testbed.csv)"
    echo "    -i <inventory> : specify inventory name"
    echo "    -k <file log>  : specify file log level: error|warning|info|debug (default debug)"
    echo "    -l <cli log>   : specify cli log level: error|warning|info|debug (default warning)"
    echo "    -m <method>    : specify test method group|individual|debug (default group)"
    echo "    -n <testbed>   : specify testbed name (*)"
    echo "    -o             : omit the file logs"
    echo "    -p <path>      : specify log path (default: logs)"
    echo "    -q <n>         : test will stop after <n> failures (default: not stop on failure)"
    echo "    -r             : retain individual file log for suceeded tests (default: remove)"
    echo "    -s <tests>     : specify list of tests to skip (default: none)"
    echo "    -t <topology>  : specify toplogy: t0|t1|any|combo like t0,any (*)"
    echo "    -u             : bypass util group"
    echo "    -x             : print commands and their arguments as they are executed"

    exit $1
}

function validate_parameters()
{
    RET=0

    if [[ -z ${DUT_NAME} ]]; then
        echo "DUT name (-d) is not set.."
        RET=1
    fi

    if [[ -z ${TESTBED_NAME} ]]; then
        echo "Testbed name (-n) is not set.."
        RET=2
    fi

    if [[ -z ${TOPOLOGY} && -z ${TEST_CASES} ]]; then
        echo "Neither TOPOLOGY (-t) nor test case list (-c) is set.."
        RET=3
    fi

    if [[ ${RET} != 0 ]]; then
        show_help_and_exit ${RET}
    fi
}

function setup_environment()
{
    SCRIPT=$0
    FULL_PATH=$(realpath ${SCRIPT})
    SCRIPT_PATH=$(dirname ${FULL_PATH})
    BASE_PATH=$(dirname ${SCRIPT_PATH})
    LOG_PATH="logs"

    AUTO_RECOVER="True"
    BYPASS_UTIL="False"
    CLI_LOG_LEVEL='warning'
    EXTRA_PARAMETERS=""
    FILE_LOG_LEVEL='debug'
    INVENTORY="${BASE_PATH}/ansible/lab,${BASE_PATH}/ansible/veos"
    OMIT_FILE_LOG="False"
    RETAIN_SUCCESS_LOG="False"
    SKIP_SCRIPTS=""
    SKIP_FOLDERS="ptftests acstests saitests scripts"
    TESTBED_FILE="${BASE_PATH}/ansible/testbed.csv"
    TEST_CASES=""
    TEST_METHOD='group'
    TEST_MAX_FAIL=0

    export ANSIBLE_CONFIG=${BASE_PATH}/ansible
    export ANSIBLE_LIBRARY=${BASE_PATH}/ansible/library/
}

function setup_test_options()
{
    PYTEST_COMMON_OPTS="--inventory ${INVENTORY} \
                      --host-pattern ${DUT_NAME} \
                      --testbed ${TESTBED_NAME} \
                      --testbed_file ${TESTBED_FILE} \
                      --log-cli-level ${CLI_LOG_LEVEL} \
                      --log-file-level ${FILE_LOG_LEVEL} \
                      --showlocals \
                      --assert plain \
                      --show-capture no \
                      -rav"

    if [[ x"${AUTO_RECOVER}" == x"True" ]]; then
        PYTEST_COMMON_OPTS="${PYTEST_COMMON_OPTS} --allow_recover"
    fi

    for skip in ${SKIP_SCRIPTS} ${SKIP_FOLDERS}; do
        PYTEST_COMMON_OPTS="${PYTEST_COMMON_OPTS} --ignore=${skip}"
    done

    if [[ -d ${LOG_PATH} ]]; then
        rm -rf ${LOG_PATH}
    fi

    if [[ x"${OMIT_FILE_LOG}" == x"True" ]]; then
        PRET_LOGGING_OPTIONS=""
        POST_LOGGING_OPTIONS=""
        TEST_LOGGING_OPTIONS=""
    else
        mkdir -p ${LOG_PATH}

        PRET_LOGGING_OPTIONS="--junit-xml=${LOG_PATH}/pretest.xml --log-file=${LOG_PATH}/pretest.log"
        POST_LOGGING_OPTIONS="--junit-xml=${LOG_PATH}/posttest.xml --log-file=${LOG_PATH}/posttest.log"
        TEST_LOGGING_OPTIONS="--junit-xml=${LOG_PATH}/tr.xml --log-file=${LOG_PATH}/test.log"
    fi
    UTIL_TOPOLOGY_OPTIONS="--topology util"
    if [[ -z ${TOPOLOGY} ]]; then
        TEST_TOPOLOGY_OPTIONS=""
    else
        TEST_TOPOLOGY_OPTIONS="--topology ${TOPOLOGY}"
    fi

    PYTEST_UTIL_OPTS=${PYTEST_COMMON_OPTS}
    # Max failure only applicable to the test session. Not the preparation and cleanup session.
    if [[ ${TEST_MAX_FAIL} != 0 ]]; then
        PYTEST_COMMON_OPTS="${PYTEST_COMMON_OPTS} --maxfail=${TEST_MAX_FAIL}"
    fi
}

function run_debug_tests()
{
    echo "=== Show test settings ==="
    echo "SCRIPT:                ${SCRIPT}"
    echo "FULL_PATH:             ${FULL_PATH}"
    echo "SCRIPT_PATH:           ${SCRIPT_PATH}"
    echo "BASE_PATH:             ${BASE_PATH}"

    echo "ANSIBLE_CONFIG:        ${ANSIBLE_CONFIG}"
    echo "ANSIBLE_LIBRARY:       ${ANSIBLE_LIBRARY}"
    echo "AUTO_RECOVER:          ${AUTO_RECOVER}"
    echo "BYPASS_UTIL:           ${BYPASS_UTIL}"
    echo "CLI_LOG_LEVEL:         ${CLI_LOG_LEVEL}"
    echo "EXTRA_PARAMETERS:      ${EXTRA_PARAMETERS}"
    echo "FILE_LOG_LEVEL:        ${FILE_LOG_LEVEL}"
    echo "INVENTORY:             ${INVENTORY}"
    echo "LOG_PATH:              ${LOG_PATH}"
    echo "OMIT_FILE_LOG:         ${OMIT_FILE_LOG}"
    echo "RETAIN_SUCCESS_LOG:    ${RETAIN_SUCCESS_LOG}"
    echo "SKIP_SCRIPTS:          ${SKIP_SCRIPTS}"
    echo "SKIP_FOLDERS:          ${SKIP_FOLDERS}"
    echo "TEST_CASES:            ${TEST_CASES}"
    echo "TEST_MAX_FAIL:         ${TEST_MAX_FAIL}"
    echo "TEST_METHOD:           ${TEST_METHOD}"
    echo "TESTBED_FILE:          ${TESTBED_FILE}"
    echo "TEST_LOGGING_OPTIONS:  ${TEST_LOGGING_OPTIONS}"
    echo "TEST_TOPOLOGY_OPTIONS: ${TEST_TOPOLOGY_OPTIONS}"
    echo "PRET_LOGGING_OPTIONS:  ${PRET_LOGGING_OPTIONS}"
    echo "POST_LOGGING_OPTIONS:  ${POST_LOGGING_OPTIONS}"
    echo "UTIL_TOPOLOGY_OPTIONS: ${UTIL_TOPOLOGY_OPTIONS}"

    echo "PYTEST_COMMON_OPTS:    ${PYTEST_COMMON_OPTS}"
}

function prepare_dut()
{
    echo "=== Preparing DUT for subsequent tests ==="
    pytest ${PYTEST_UTIL_OPTS} ${PRET_LOGGING_OPTIONS} ${UTIL_TOPOLOGY_OPTIONS} ${EXTRA_PARAMETERS} -m pretest

    # Give some delay for the newly announced routes to propagate.
    sleep 120
}

function cleanup_dut()
{
    echo "=== Cleaning up DUT after tests ==="
    pytest ${PYTEST_UTIL_OPTS} ${POST_LOGGING_OPTIONS} ${UTIL_TOPOLOGY_OPTIONS} ${EXTRA_PARAMETERS} -m posttest
}

function run_group_tests()
{
    echo "=== Running tests in groups ==="
    pytest ${PYTEST_COMMON_OPTS} ${TEST_LOGGING_OPTIONS} ${TEST_TOPOLOGY_OPTIONS} ${EXTRA_PARAMETERS} ${TEST_CASES}
}

function run_individual_tests()
{
    if [[ -n ${TEST_CASES} ]] ;then
        test_scripts=${TEST_CASES}
    else
        SKIP_SCRIPTS="${SKIP_SCRIPTS} test_announce_routes.py test_nbr_health.py"

        ignores=$(python -c "print '|'.join('''$SKIP_FOLDERS'''.split())")

        all_scripts=$(find ./ -name 'test_*.py' | sed s:^./:: | grep -vE "^(${SKIP_FOLDERS})")
        test_scripts=$(python -c "print '\n'.join(set('''$all_scripts'''.split()) - set('''$SKIP_SCRIPTS'''.split()))" | sort)
    fi

    EXIT_CODE=0

    echo "=== Running tests individually ==="
    for test_script in ${test_scripts}; do
        if [[ x"${OMIT_FILE_LOG}" != x"True" ]]; then
            test_dir=$(dirname ${test_script})
            script_name=$(basename ${test_script})
            test_name=${script_name%.py}
            if [[ ${test_dir} != "." ]]; then
                mkdir -p ${LOG_PATH}/${test_dir}
            fi
            TEST_LOGGING_OPTIONS="--log-file ${LOG_PATH}/${test_dir}/${test_name}.log --junitxml=${LOG_PATH}/${test_dir}/${test_name}.xml"
        fi

        pytest ${PYTEST_COMMON_OPTS} ${TEST_LOGGING_OPTIONS} ${TEST_TOPOLOGY_OPTIONS} ${test_script} ${EXTRA_PARAMETERS}
        ret_code=$?

        # If test passed, no need to keep its log.
        if [ ${ret_code} -eq 0 ]; then
            if [[ x"${OMIT_FILE_LOG}" != x"True" && x"${RETAIN_SUCCESS_LOG}" == x"False" ]]; then
                rm -f ${LOG_PATH}/${test_dir}/${test_name}.log
            fi
        else
            EXIT_CODE=1
            if [[ ${TEST_MAX_FAIL} != 0 ]]; then
                return ${EXIT_CODE}
            fi
        fi

    done

    return ${EXIT_CODE}
}

setup_environment

while getopts "h?a:c:d:e:f:i:k:l:m:n:op:q:rs:t:ux" opt; do
    case ${opt} in
        h|\? )
            show_help_and_exit 0
            ;;
        a )
            AUTO_RECOVER=${OPTARG}
            ;;
        c )
            TEST_CASES="${TEST_CASES} ${OPTARG}"
            ;;
        d )
            DUT_NAME=${OPTARG}
            ;;
        e )
            EXTRA_PARAMETERS="${EXTRA_PARAMETERS} ${OPTARG}"
            ;;
        f )
            TESTBED_FILE=${OPTARG}
            ;;
        i )
            INVENTORY=${OPTARG}
            ;;
        k )
            FILE_LOG_LEVEL=${OPTARG}
            ;;
        l )
            CLI_LOG_LEVEL=${OPTARG}
            ;;
        m )
            TEST_METHOD=${OPTARG}
            ;;
        n )
            TESTBED_NAME=${OPTARG}
            ;;
        o )
            OMIT_FILE_LOG="True"
            ;;
        p )
            LOG_PATH=${OPTARG}
            ;;
        q )
            TEST_MAX_FAIL=${OPTARG}
            ;;
        r )
            RETAIN_SUCCESS_LOG="True"
            ;;
        s )
            SKIP_SCRIPTS="${SKIP_SCRIPTS} ${OPTARG}"
            ;;
        t )
            TOPOLOGY=${OPTARG}
            ;;
        u )
            BYPASS_UTIL="True"
            ;;
        x )
            set -x
            ;;
    esac
done

if [[ x"${TEST_METHOD}" != x"debug" ]]; then
    validate_parameters
fi
setup_test_options

if [[ x"${TEST_METHOD}" != x"debug" && x"${BYPASS_UTIL}" == x"False" ]]; then
    prepare_dut
fi

RC=0
run_${TEST_METHOD}_tests || RC=$?

if [[ x"${TEST_METHOD}" != x"debug" && x"${BYPASS_UTIL}" == x"False" ]]; then
    cleanup_dut
fi

exit ${RC}
