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

# Neighbor VM type (veos|ceos|vsonic) - simulated neighboring devices
NEIGHBOR    ?= ceos

# Test config
T           ?=
EXTRA       ?=

# TTY handling: use -t only if terminal is available (for CI compatibility)
TTY         := $(shell test -t 0 && echo "-t")

# Base exec
EXEC_ANSIBLE := docker exec $(TTY) -w $(ANSIBLE_DIR) $(CONTAINER)
EXEC_TESTS   := docker exec $(TTY) -w $(TESTS_DIR) $(CONTAINER)

.PHONY: help check-container shell add-topo remove-topo deploy-mg test

help:
	@echo "Usage: make <target> [VARIABLE=value ...]"
	@echo ""
	@echo "Targets:"
	@echo "  shell       - Enter sonic-mgmt container"
	@echo "  add-topo    - Deploy topology"
	@echo "  remove-topo - Remove topology"
	@echo "  deploy-mg   - Deploy minigraph to DUT"
	@echo "  test        - Run tests (requires T=<test_path>)"
	@echo ""
	@echo "Variables:"
	@echo "  TOPO        - Topology name (default: vms-kvm-t0)"
	@echo "  TESTBED     - Testbed file (default: vtestbed.yaml)"
	@echo "  INVENTORY   - Inventory file (default: veos_vtb)"
	@echo "  DUT         - DUT name (default: vlab-01)"
	@echo "  NEIGHBOR    - Neighbor VM type: ceos|veos|vsonic (default: ceos)"
	@echo "  T           - Test path for 'test' target"
	@echo "  EXTRA       - Extra arguments for test"
	@echo ""
	@echo "Examples:"
	@echo "  make add-topo"
	@echo "  make add-topo TOPO=vms-kvm-t1"
	@echo "  make test T=bgp/test_bgp_fact.py"
	@echo "  make test T=bgp/test_bgp_fact.py EXTRA='-e \"--neighbor_type=sonic\"'"

check-container:
	@docker ps --format '{{.Names}}' | grep -q '^$(CONTAINER)$$' || \
		(echo "Error: Container '$(CONTAINER)' is not running." && \
		 echo "Run: ./setup-container.sh -n $(CONTAINER) -d /data" && exit 1)

shell: check-container
	docker exec -it $(CONTAINER) bash

add-topo: check-container
	$(EXEC_ANSIBLE) ./testbed-cli.sh -t $(TESTBED) -m $(INVENTORY) -k $(NEIGHBOR) add-topo $(TOPO) $(PASSFILE)

remove-topo: check-container
	$(EXEC_ANSIBLE) ./testbed-cli.sh -t $(TESTBED) -m $(INVENTORY) -k $(NEIGHBOR) remove-topo $(TOPO) $(PASSFILE)

deploy-mg: check-container
	$(EXEC_ANSIBLE) ./testbed-cli.sh -t $(TESTBED) -m $(INVENTORY) deploy-mg $(TOPO) $(INVENTORY) $(PASSFILE)

test: check-container
ifndef T
	$(error T is required. Usage: make test T=bgp/test_bgp_fact.py)
endif
	$(EXEC_TESTS) ./run_tests.sh -n $(TOPO) -d $(DUT) -f $(TESTBED) -i ../ansible/$(INVENTORY) -c $(T) $(EXTRA)
