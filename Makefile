PYTHON := python3.8
BIN := pyats/bin
TESTFILE ?= sanity_scripts.txt
GOLDENBRANCH ?= 202012
GOLDENCODE ?= http://172.29.93.10/sonic-images/golden-code/golden_code_$(GOLDENBRANCH).tar.gz
TEMP_TESTFILE := $(shell mktemp)
REPORT_REPO ?= /home/report_server_pv/

.PHONY: init t0_run t1_run collect

init:
ifeq (, $(shell which $(PYTHON)))
	$(error $(PYTHON) is not present in $$PATH)
endif
	cd infra && \
	$(PYTHON) -m venv pyats && \
	$(BIN)/pip install --upgrade pip && \
	$(BIN)/pip install -r requirements.txt

t0_run:
	echo "run T0 testing..."
	bash -c "python3.8 update_topo.py T0"
	bash -c "cd infra; source pyats/bin/activate; python3.8 ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml -u cisco -p cisco123 -t t0-64 -c -r -s $(TESTFILE) -b $(GOLDENCODE) --cicd --cicd_clean --create_allure_report"

t1_run:
	echo "run T1 testing..."
	bash -c "python3.8 update_topo.py T1"
	bash -c "cd infra; source pyats/bin/activate; python3.8 ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml -u cisco -p cisco123 -t t1-64-lag -c -r -s $(TESTFILE) -b $(GOLDENCODE) --cicd --cicd_clean --create_allure_report"

collect:
	echo "collect test result..."
	cd infra; python3 ./pipeline_collect_result.py
	pwd
	cd infra; mkdir $(BUILD_ID)
	cd infra; cp report.html $(BUILD_ID)/; cp test-results.xml.html $(BUILD_ID)/; cp sanity_logs.tar.gz $(BUILD_ID)/
	cd infra; scp -r $(BUILD_ID) sonic-ci-1-lnx:$(REPORT_REPO)
	cd infra; scp -r $(BUILD_ID) sonic-ci-2-lnx:$(REPORT_REPO)
	cd infra; scp -r $(BUILD_ID) sonic-ci-3-lnx:$(REPORT_REPO)

ut_t0:
	# create_sonic_topo only accepts a file for list of tests. Create temp file
	echo $(TEST_LIST) | sed 's/,/\n/g' > $(TEMP_TESTFILE)
	cat $(TESTFILE) >> $(TEMP_TESTFILE)
	echo "Running UT on T0 with ${TEMP_TESTFILE}"
	$(MAKE) TESTFILE=$(TEMP_TESTFILE) t0_run
	rm $(TEMP_TESTFILE)
