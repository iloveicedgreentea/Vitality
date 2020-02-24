.PHONY: all

APP_NAME := "vitality"
TAG		 ?= "latest"
ARGS	 := ""

all: test

build_system:
	go build -o $(PWD)/bin/vt

test: build
	@echo
	@# TODO: make and run actual tests later
	@./bin/vt -pr personal -p /app/test/123 -i ./tests/files/virus.exe -i https://www.nsa.gov/aboutus/equationgroup/ 

build:
	docker build -t $(APP_NAME)-build:$(TAG) -f Dockerfile.build .
	docker run -v $(PWD):/go/src/app:delegated -it $(APP_NAME)-build:$(TAG)

push: build_docker
	docker tag $(APP_NAME):$(TAG)  account_name/$(APP_NAME):$(TAG) 
	docker push account_name/$(APP_NAME):$(TAG) 

run: 
	docker run -it $(APP_NAME):$(TAG) vt $(ARGS)
