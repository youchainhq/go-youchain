SHELL := /bin/bash
GROUP_NAME = maisi
SERVICE_NAME = net-server
VERSION_STRING = v0610
RELEASE_DIR = $(GOPATH)/src/youchain/you-release
REGISTRY_URL = registry.cn-hangzhou.aliyuncs.com

PKG_DIR = github.com/youchainhq/go-youchain/p2p/nat/check/server
ROOT_DIR = ../../../../

all: push

build_linux:
	xgo2 --targets=linux/amd64 -dest $(RELEASE_DIR)/ -out natserver --goproxy=https://mirrors.aliyun.com/goproxy/ --pkg=${PKG_DIR} ${ROOT_DIR}

build_macos:
    xgo2 --targets=darwin/amd64 -ldflags "-s -w" -dest $(RELEASE_DIR)/ -out natserver --goproxy=https://mirrors.aliyun.com/goproxy/ --pkg=${PKG_DIR} ${ROOT_DIR}

docker:
	xgo2 --targets=linux/amd64 -out you --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}
	docker build -t ${GROUP_NAME}/${SERVICE_NAME}:latest -t ${GROUP_NAME}/${SERVICE_NAME}:${VERSION_STRING} .
	rm you-linux-amd64

push: docker
	docker tag ${GROUP_NAME}/${SERVICE_NAME}:latest ${REGISTRY_URL}/${GROUP_NAME}/${SERVICE_NAME}:latest
	docker push ${REGISTRY_URL}/${GROUP_NAME}/${SERVICE_NAME}:latest