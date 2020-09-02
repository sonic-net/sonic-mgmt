all: save

build: Dockerfile
	cp ../../helpers/pfc_gen.py .
	docker build -t pfc_storm .
	rm ./pfc_gen.py

save: build
	docker save pfc_storm:latest | gzip >pfc_storm.tgz
