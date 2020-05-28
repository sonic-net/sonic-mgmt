DOCKER_IMG=iidfile
RUNOPTS=-v $(PWD):/gnmitest -v $(HOME):/opt/home
.PHONY: all clean runtest

all: $(DOCKER_IMG)
	docker run $(RUNOPTS) -it $(shell cat $(DOCKER_IMG)) bash

runtest : $(DOCKER_IMG)
	@if [ -f $(BASH_CMD) ]; then \
		docker run $(RUNOPTS) -w /gnmitest $(shell cat $(DOCKER_IMG)) /gnmitest/$(BASH_CMD); \
	fi

$(DOCKER_IMG): #Dockerfile current-req.txt docker_startup_env
	docker build --iidfile $(DOCKER_IMG) -t godiva-perf .

clean:
	@if [ -f $(DOCKER_IMG) ]; then \
		docker image remove --force $(shell cat $(DOCKER_IMG)); \
		rm -fr $(DOCKER_IMG); \
	fi
