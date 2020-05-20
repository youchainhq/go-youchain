SHELL := /bin/bash
GROUP_NAME = maisi
RELEASE_DIR = ${GOPATH}/src/youchain/you-release
REGISTRY_URL = registry.cn-hangzhou.aliyuncs.com
SRC_DIR = ../../cmd/you
PKG_DIR = github.com/youchainhq/go-youchain/cmd/you
ROOT_DIR = ../../
BIN_REVISION_STRING := $(shell git show -s --pretty=format:%h)
BIN_BUILD_TIME := $(shell date +"%Y-%m-%d %H:%M:%S")
BIN_BUILD_TIME_SHORT := $(shell date +"%Y%m%d-%H%M")
BIN_BUILD_BRANCH := $(shell git symbolic-ref --short -q HEAD)
BIN_PATH_PREFIX := ${RELEASE_DIR}/you-$(BIN_REVISION_STRING)-$(BIN_BUILD_TIME_SHORT)
SERVICE_NAME := feature-ci

all: push

project_testcase:
	cd ${ROOT_DIR} && go test -v -short ./...

update_version:
	echo -e "package node\n\nconst revision = \"$(BIN_REVISION_STRING)\"\n\nconst buildTime = \"$(BIN_BUILD_TIME)\"\n\nconst buildBranch = \"$(BIN_BUILD_BRANCH)\"" > $(SRC_DIR)/node/version.go

clear_version:
	echo -e "package node\n\nconst revision = \"\"\n\nconst buildTime = \"\"\n\nconst buildBranch = \"\"" > $(SRC_DIR)/node/version.go

docker:
	go mod tidy
	xgo2 --targets=linux/amd64 -ldflags "-s -w" -out you --pkg=${PKG_DIR} ${ROOT_DIR}
	docker build -t ${GROUP_NAME}/${SERVICE_NAME}:$(BIN_REVISION_STRING) .
	rm -rf you-linux-amd64

push: project_testcase update_version docker clear_version
	docker tag ${GROUP_NAME}/${SERVICE_NAME}:$(BIN_REVISION_STRING) ${REGISTRY_URL}/${GROUP_NAME}/${SERVICE_NAME}:$(BIN_REVISION_STRING)
	docker push ${REGISTRY_URL}/${GROUP_NAME}/${SERVICE_NAME}:$(BIN_REVISION_STRING)