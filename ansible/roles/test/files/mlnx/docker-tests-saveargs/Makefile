all: save

build: Dockerfile
	docker build -t storm_args .

save: build
	docker save storm_args:latest | gzip >storm_args.tgz
