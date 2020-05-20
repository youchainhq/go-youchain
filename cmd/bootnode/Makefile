GROUP_NAME = maisi
SERVICE_NAME = youchain-bootnode-ci
REGISTRY_URL = registry.cn-hangzhou.aliyuncs.com
PKG_DIR = github.com/youchainhq/go-youchain/cmd/bootnode
ROOT_DIR = ../../
BIN_VERSION_STRING = $(shell git show -s --pretty=format:%h)
BIN_BUILD_TIME = $(shell date +"%Y-%m-%d %H:%M:%S")
VERSION_STRING = latest

all: push

docker:
	xgo2 --targets=linux/amd64 -out bootnode --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}
	docker build -t ${GROUP_NAME}/${SERVICE_NAME}:${VERSION_STRING} .
	rm bootnode-linux-amd64

push: docker
	docker push ${REGISTRY_URL}/${GROUP_NAME}/${SERVICE_NAME}:${VERSION_STRING}