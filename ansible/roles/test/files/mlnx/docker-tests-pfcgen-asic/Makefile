all: save

build: Dockerfile
	cp ../../helpers/pfc_gen.py ./pfc_gen_cpu.py
	docker build -t pfc_storm .
	rm ./pfc_gen_cpu.py

save: build
        docker save pfc_storm:latest | gzip >pfc_storm.tgz
