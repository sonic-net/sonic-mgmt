.PHONY: t0_run t1_run collect

t0_run:
	echo "run T0 testing..."
	cd infra; python3 ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t0-64_topo.yaml -u cisco -p cisco123 -t t0-64 -c -r

collect:
	echo "collecting testing result..."
	cd infra; python3 ./pipeline_collect_result.py
