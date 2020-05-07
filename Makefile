BUILDDIR=$(PWD)/build
DOCKER_IMG=$(BUILDDIR)/iidfile
RUNOPTS=-v $(PWD):/godiva-test -v $(HOME):/opt/home
BUILD_ARGS=--build-arg http_proxy --build-arg https_proxy \
	--build-arg no_proxy=.cisco.com

.PHONY: all clean runtest

all: $(DOCKER_IMG)
	docker run $(RUNOPTS) -it $(shell cat $(DOCKER_IMG)) bash

runtest : $(DOCKER_IMG)
	@if [ -s $(BASH_CMD) ]; then \
		docker run $(RUNOPTS) -w /godiva-test $(shell cat $(DOCKER_IMG)) /godiva-test/$(BASH_CMD); \
	fi;

$(DOCKER_IMG): docker/Dockerfile docker/current-req.txt docker/docker_startup_env
	@git submodule update --init --recursive
	@mkdir -p $(BUILDDIR)
	@docker build $(BUILD_ARGS) --iidfile $(DOCKER_IMG) -t ubuntu-cafy docker

distclean: clean
	@rm -fr $(BUILDDIR)

clean:
	@if [ -e $(DOCKER_IMG) ]; then \
		docker image remove --force $(shell cat $(DOCKER_IMG)); \
		rm -fr $(DOCKER_IMG); \
	fi;
