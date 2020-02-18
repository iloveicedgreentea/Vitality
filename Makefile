.PHONY: all

APP_NAME := "vitality"
TAG		 ?= "latest"

all: build

build:
	go build -o $(PWD)/bin/vt

run:
	./bin/vt -pr personal -p /app/test/123 -f ./virus.exe ./virus2.exe badsite.com/virus.php www.nsa.gov/aboutus/equationgroup/ 

build_docker:
	docker build -t $(APP_NAME):$(TAG) .

push: build_docker
	docker tag $(APP_NAME):$(TAG)  account_name/$(APP_NAME):$(TAG) 
	docker push account_name/$(APP_NAME):$(TAG) 

docker_run:
	docker run -it $(APP_NAME):$(TAG) vt
