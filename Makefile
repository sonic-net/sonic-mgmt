# Container
CONTAINER   ?= sonic-mgmt
ANSIBLE_DIR := /data/sonic-mgmt/ansible
TESTS_DIR   := /data/sonic-mgmt/tests

# Testbed config
TOPO        ?= vms-kvm-t0
TESTBED     ?= vtestbed.yaml
INVENTORY   ?= veos_vtb
PASSFILE    ?= password.txt
DUT         ?= vlab-01

# Test config
T           ?=
EXTRA       ?=

# Base exec
EXEC_ANSIBLE := docker exec -t -w $(ANSIBLE_DIR) $(CONTAINER)
EXEC_TESTS   := docker exec -t -w $(TESTS_DIR) $(CONTAINER)

.PHONY: check-container shell add-topo remove-topo deploy-mg test

check-container:
	@docker ps --format '{{.Names}}' | grep -q '^$(CONTAINER)$$' || \
		(echo "Error: Container '$(CONTAINER)' is not running." && \
		 echo "Run: ./setup-container.sh -n $(CONTAINER) -d /data" && exit 1)

shell: check-container
	docker exec -it $(CONTAINER) bash

add-topo: check-container
	$(EXEC_ANSIBLE) ./testbed-cli.sh -t $(TESTBED) -m $(INVENTORY) add-topo $(TOPO) $(PASSFILE)

remove-topo: check-container
	$(EXEC_ANSIBLE) ./testbed-cli.sh -t $(TESTBED) -m $(INVENTORY) -k ceos remove-topo $(TOPO) $(PASSFILE)

deploy-mg: check-container
	$(EXEC_ANSIBLE) ./testbed-cli.sh -t $(TESTBED) -m $(INVENTORY) deploy-mg $(TOPO) $(INVENTORY) $(PASSFILE)

test: check-container
ifndef T
	$(error T is required. Usage: make test T=bgp/test_bgp_fact.py)
endif
	$(EXEC_TESTS) ./run_tests.sh -n $(TOPO) -d $(DUT) -f $(TESTBED) -i ../ansible/$(INVENTORY) -c $(T) $(EXTRA)
