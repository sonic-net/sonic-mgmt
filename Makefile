PYTHON := python3.8
BIN := pyats/bin
TESTFILE ?= sanity-scripts/sanity_scripts.txt
GOLDENBRANCH ?= 202012
GOLDENCODE ?= http://172.29.93.10/sonic-images/golden-code/golden_code_$(GOLDENBRANCH).tar.gz
TEMP_TESTFILE := $(shell mktemp)
REPORT_REPO ?= /home/report_server_pv/
DUT_USERNAME ?= "cisco"
DUT_PASSWORD ?= "cisco123"

.PHONY: init t0_run t1_run collect

init:
ifeq (, $(shell which $(PYTHON)))
	$(error $(PYTHON) is not present in $$PATH)
endif
	cd infra && \
	$(PYTHON) -m venv pyats && \
	$(BIN)/pip install --upgrade pip && \
	$(BIN)/pip install -r requirements.txt

create_sonic_topo:
	echo "creating SIM sonic topology..."
	bash -c "python3.8 update_topo.py -t ${TOPOLOGY} -p ${PLATFORM} --dut-username=${DUT_USERNAME} --dut-password=${DUT_PASSWORD}"
	bash -c " \
	 cd infra; \
	 source pyats/bin/activate; \
	 python3.8 -u ./create_sonic_topo.py \
		--dut_uname ${DUT_USERNAME} \
		--dut_passwd ${DUT_PASSWORD} \
		--topo_type ${TOPOLOGY} \
		--device_type ${PLATFORM} \
		--script_file $(TESTFILE) \
		--tar_ball $(GOLDENCODE) \
		--clean_sim \
		--cicd \
	"

clear_sim:
	echo "clearing SIM sonic topology..."
	bash -c " \
	 cd infra; \
	 source pyats/bin/activate; \
	 python3.8 /auto/vxr/pyvxr/pyvxr-latest/vxr.py clean"

run_sanity_using_cfg_file:
	echo "run sanity on HW..."
	bash -c "cd infra; python3.8 -u run_scripts_remote.py  \
	--sim_config_file=${SIM_CONFIG_FILE} \
	--script_file=${TESTFILE} \
	--create_allure_report \
	--additional_tests="${ADDITIONAL_TESTS}"

run_sanity:
	echo "run sanity..."
	bash -c " \
		cd infra; \
		python3.8 -u run_scripts_remote.py  \
		--host_address=${HOST_ADDRESS} \
		--username=${USERNAME} \
		--password=${PASSWORD} \
		--ssh_port=${SSH_PORT} \
		--topo_name=${TOPO_NAME} \
		--script_file=${TESTFILE} \
		--device_type=${DEVICE_TYPE} \
		--docker_mgmt_container='${DOCKER_MGMT_CONTAINER}' \
		--sonic_test_dir='${SONIC_TEST_DIR}' \
		--create_allure_report \
		--additional_tests='${ADDITIONAL_TESTS}'"

t0_run:
	echo "run T0 testing..."
	bash -c "python3.8 update_topo.py T0"
	bash -c "cd infra; source pyats/bin/activate; python3.8 -u ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml -u cisco -p cisco123 -t t0-64 -c -s $(TESTFILE) -b $(GOLDENCODE) --cicd --cicd_clean --create_allure_report --additional_tests $(ADDITIONAL_TESTS)"

t1_run:
	echo "run T1 testing..."
	bash -c "python3.8 update_topo.py T1"
	bash -c "cd infra; source pyats/bin/activate; python3.8 -u ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml -u cisco -p cisco123 -t t1-64-lag -c -s $(TESTFILE) -b $(GOLDENCODE) --cicd --cicd_clean --create_allure_report --additional_tests $(ADDITIONAL_TESTS)"

run_hw:
	echo "run sanity on HW..."
	bash -c "cd infra; python3.8 -u run_scripts_remote.py  \
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

collect:
	echo "collect test result..."
	cd infra; python3 ./pipeline_collect_result.py
	pwd
	cd infra; mkdir $(BUILD_ID)
	cd infra; cp report.html $(BUILD_ID)/; cp test-results.xml.html $(BUILD_ID)/; cp sanity_logs.tar.gz $(BUILD_ID)/
	cd infra; scp -r $(BUILD_ID) sonic-ci-1-lnx:$(REPORT_REPO)
	cd infra; scp -r $(BUILD_ID) sonic-ci-2-lnx:$(REPORT_REPO)
	cd infra; scp -r $(BUILD_ID) sonic-ci-3-lnx:$(REPORT_REPO)
	