SRC_DIR := ./cmd/you
OUTPUT_DIR := ./output
PKG_DIR = github.com/youchainhq/go-youchain/cmd/you
ROOT_DIR = ./
GIT_COMMIT := $(shell git show -s --pretty=format:%h)
GIT_TIME := $(shell git show -s --pretty=format:%ci)
BIN_BUILD_TIME := $(shell date +"%Y-%m-%d %H:%M:%S")
BIN_BUILD_TIME_SHORT := $(shell date +"%Y%m%d-%H%M")
BIN_BUILD_BRANCH := $(shell git symbolic-ref --short -q HEAD)
GROUP_NAME := youchain
SERVICE_NAME := you

.PHONY: build install clean all

# local build. let target build on the top as the default make target.
build:
	CGO_ENABLED=1 go build -o $(OUTPUT_DIR)/$(SERVICE_NAME) -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" $(SRC_DIR)

install:
	CGO_ENABLED=1 go install -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" $(SRC_DIR)

clean:
	go clean -cache
	rm -rf $(OUTPUT_DIR)

# Cross Compilation Targets (using xgo2 to support gomod)

build_linux:
	xgo2 --targets=linux/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

build_arm64:
	xgo2 --targets=linux/arm64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

build_win64:
	xgo2 --targets=windows/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

build_win32:
	xgo2 --targets=windows/386 --dest $(OUTPUT_DIR)/ -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

build_darwin:
	xgo2 --targets=darwin/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

all:build
	xgo2 --targets=linux/amd64,linux/arm64,windows/amd64,windows/386,darwin/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w -X '$(PKG_DIR)/node.revision=$(GIT_COMMIT)' -X '$(PKG_DIR)/node.buildTime=$(BIN_BUILD_TIME)' -X '$(PKG_DIR)/node.buildBranch=$(BIN_BUILD_BRANCH)'" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

docker:
	docker build -t ${GROUP_NAME}/${SERVICE_NAME}:latest-build .

# develop tools for go-youchain developer or smart contract developer
devtools:
	@echo "installing tools required for 'go generate'..."
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/youchainhq/xgo2
	@echo "installing abigen ..."
	go install -ldflags "-X main.gitCommit=${GIT_COMMIT} -X 'main.gitTime=${GIT_TIME}'" ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc from github.com/youchainhq'