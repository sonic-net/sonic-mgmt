PYTHON := python3
BIN := pyats/bin
TESTFILE ?= sanity-scripts/sanity_scripts.txt
GOLDENBRANCH ?= 202012
GOLDENCODE ?= http://172.29.93.10/sonic-images/golden-code/golden_code_$(GOLDENBRANCH).tar.gz
TEMP_TESTFILE := $(shell mktemp)
PIPELINE_TYPE ?= "manual_sanity"
BUILD_ID ?= "${USER}_$(date +%Y%m%d%H%M%S)"
REPORT_REPO ?= /auto/mb/sonic/workspace/sonic-cicd/sanity_logs/${PIPELINE_TYPE}
DUT_USERNAME ?= "cisco"
DUT_PASSWORD ?= "cisco123"

DISABLE_ZTP ?= false

ifeq ($(DISABLE_ZTP),true)
  DISABLE_ZTP_COMMAND := --disable-ztp
else
  DISABLE_ZTP_COMMAND :=
endif

.PHONY: init t0_run t1_run collect

init:
ifeq (, $(shell which $(PYTHON)))
	$(error $(PYTHON) is not present in $$PATH)
endif
	cd infra && \
	$(PYTHON) -m venv pyats && \
	$(BIN)/pip install --upgrade pip && \
	$(BIN)/pip install -r requirements.txt --no-cache-dir

create_sonic_topo:
	echo "creating SIM sonic topology..."
	bash -c "${PYTHON} update_topo.py -t ${TOPOLOGY} -p ${PLATFORM} --dut-username=${DUT_USERNAME} --goldencode=$(GOLDENCODE) --dut-password=${DUT_PASSWORD} ${DISABLE_ZTP_COMMAND}"
	bash -c " \
	 cd infra; \
	 source pyats/bin/activate; \
	 ${PYTHON} -u ./create_sonic_topo.py \
		--dut_uname ${DUT_USERNAME} \
		--dut_passwd ${DUT_PASSWORD} \
		--topo_type ${TOPOLOGY} \
		--device_type ${PLATFORM} \
		--script_file $(TESTFILE) \
		--tar_ball $(GOLDENCODE) \
		--clean_sim \
		--cicd \
		--test_tag '${TEST_TAG}' \
		--add_sim_patches \
		$(SIM_ADDITIONAL_PARAMS) \
	"

clear_sim:
	echo "clearing SIM sonic topology..."
	bash -c " \
	 cd infra; \
	 source pyats/bin/activate; \
	 ${PYTHON} /auto/vxr/pyvxr/pyvxr-latest/vxr.py clean"

run_sanity_using_cfg_file:
	echo "run sanity on HW..."
	bash -c "cd infra; ${PYTHON} -u run_scripts_remote.py  \
	--sim_config_file=${SIM_CONFIG_FILE} \
	--script_file=${TESTFILE} \
	--create_allure_report \
	--additional_tests="${ADDITIONAL_TESTS}"

run_sanity:
	echo "run sanity..."
	bash -c " \
		cd infra; \
		source pyats/bin/activate; \
		${PYTHON} -u run_scripts_remote.py  \
		--script_file=${TESTFILE} \
		--device_type=${PLATFORM} \
		--topo_type=${TOPOLOGY} \
		--create_allure_report \
		--additional_tests='${ADDITIONAL_TESTS}' \
		--test_tag '${TEST_TAG}' \
		--add_sim_patches  \
		$(SIM_ADDITIONAL_PARAMS) \
	"

run_tortuga_controller_sanity:
	echo "run spytest sanity..."
	bash -c " \
		${PYTHON} update_topo.py -t ${TOPOLOGY} -p ${PLATFORM} --dut-username=${DUT_USERNAME} --goldencode=$(GOLDENCODE) --dut-password=${DUT_PASSWORD} ${DISABLE_ZTP_COMMAND}; \
		cd infra; \
		source pyats/bin/activate; \
		${PYTHON} ./create_tortuga_topo.py \
		--topo_type ${TOPOLOGY} \
		--device_type ${PLATFORM} \
		--tar_ball $(GOLDENCODE) \
		-c --fabric_name sonic-test-${PIPELINE_TYPE}-${BUILD_ID} \
		--cicd \
	"

run_spytest:
	echo "run spytest sanity..."
	bash -c " \
		${PYTHON} update_topo.py -t ${TOPOLOGY} -p ${PLATFORM} --dut-username=${DUT_USERNAME} --goldencode=$(GOLDENCODE) --dut-password=${DUT_PASSWORD} ${DISABLE_ZTP_COMMAND}; \
		cd infra; \
		source pyats/bin/activate; \
		${PYTHON} -u run_spytest.py  \
		--topology '${TOPOLOGY}' \
		--platform '${PLATFORM}' \
		--script_file '${TESTFILE}' \
		--tar_ball '$(GOLDENCODE)' \
	"

# Files Needed:
# generate_spytest_html_report - infra/generate_spytest_html_report.py
# run parallel script - infra/run_spytest_parallel.py
# topology suite file - sonic-mgmt/spytest/reporting/suites/tortuga_parallel

run_spytest_parallel:
	echo "run spytest parallel sanity..."
	bash -c " \
		${PYTHON} update_topo.py -t ${TOPOLOGY} -p ${PLATFORM} \
		--onie-install ../../../sonic-cisco-8000.bin; \
		cd infra; \
		source pyats/bin/activate; \
		${PYTHON} -u run_spytest_parallel.py  \
		--topology '${TOPOLOGY}' \
		--platform '${PLATFORM}' \
		--script_file '${TESTFILE}' \
		--tar_ball '$(GOLDENCODE)' \
		--num_of_threads ${NUM_SIMS} \
	"
t0_run:
	echo "run T0 testing..."
	bash -c "${PYTHON} update_topo.py T0"
	bash -c "cd infra; source pyats/bin/activate; ${PYTHON} -u ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml -u cisco -p cisco123 -t t0-64 -c -s $(TESTFILE) -b $(GOLDENCODE) --cicd --cicd_clean --create_allure_report --additional_tests $(ADDITIONAL_TESTS)"

t1_run:
	echo "run T1 testing..."
	bash -c "${PYTHON} update_topo.py T1"
	bash -c "cd infra; source pyats/bin/activate; ${PYTHON} -u ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml -u cisco -p cisco123 -t t1-64-lag -c -s $(TESTFILE) -b $(GOLDENCODE) --cicd --cicd_clean --create_allure_report --additional_tests --add_sim_patches $(ADDITIONAL_TESTS)"

run_hw:
	echo "run sanity on HW..."
	bash -c "cd infra; ${PYTHON} -u run_scripts_remote.py  \
	--host_address=${HOST_ADDRESS} \
	--username=${USERNAME} \
	--password=${PASSWORD} \
	--topo_name=${TOPO_NAME} \
	--script_file=${TESTFILE} \
	--device_type=${DEVICE_TYPE} \
	--docker_mgmt_container=${DOCKER_MGMT_CONTAINER} \
	--sonic_test_dir=${SONIC_TEST_DIR} \
	--create_allure_report \
	--additional_tests="${ADDITIONAL_TESTS}"

collect_controller_logs:
	echo "collect controller test result..."
	pwd
	cd infra; mkdir $(BUILD_ID)
	cd infra; cp sanity_logs.tar.gz $(BUILD_ID)/
	cd infra; cp -r $(BUILD_ID) $(REPORT_REPO) | true
