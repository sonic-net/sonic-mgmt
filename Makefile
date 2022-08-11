PYTHON := python3.8
BIN := pyats/bin

.PHONY: init t0_run t1_run collect

init:
ifeq (, $(shell which $(PYTHON)))
	$(error $(PYTHON) is not present in $$PATH)
endif
	cd infra && \
	$(PYTHON) -m venv pyats && \
	$(BIN)/pip install --upgrade pip && \
	$(BIN)/pip install -r requirements.txt && \
	$(BIN)/pre-commit install

t0_run:
	echo "run T0 testing..."
	bash -c "cd infra; source pyats/bin/activate; python3.8 ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml -u cisco -p cisco123 -t t0-64 -c -r"

t1_run:
	echo "run T1 testing..."
	bash -c "cd infra; source pyats/bin/activate; python3.8 ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml -u cisco -p cisco123 -t t1-64-lag -c -r"

collect:
	echo "run T0 testing..."
	cd infra; python3 ./pipeline_collect_result.py
