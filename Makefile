PYTHON := python3.8
BIN := pyats/bin

.PHONY: init t0_run t1_run collect

init: pyats

pyats:
ifeq (, $(shell which $(PYTHON)))
	$(error $(PYTHON) is not present in $$PATH)
endif
	$(PYTHON) -m venv pyats
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	$(BIN)/pre-commit install

t0_run:
	echo "run T0 testing..."
	cd infra; python3 ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml -u cisco -p cisco123 -t t0-64 -c -r

collect:
	echo "collecting testing result..."
	cd infra; python3 ./pipeline_collect_result.py
