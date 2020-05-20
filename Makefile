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

# local build. let target build on the top as the default make target.

build: update_build_info direct_build clear_build_info

install: update_build_info direct_install clear_build_info

clean: clear_build_info
	go clean -cache
	rm -rf $(OUTPUT_DIR)

update_build_info:
	echo "package node\n\nconst revision = \"$(GIT_COMMIT)\"\n\nconst buildTime = \"$(BIN_BUILD_TIME)\"\n\nconst buildBranch = \"$(BIN_BUILD_BRANCH)\"" > $(SRC_DIR)/node/version.go

clear_build_info:
	echo "package node\n\nconst revision = \"\"\n\nconst buildTime = \"\"\n\nconst buildBranch = \"\"" > $(SRC_DIR)/node/version.go

direct_build:
	CGO_ENABLED=1 go build -o $(OUTPUT_DIR)/$(SERVICE_NAME) -ldflags "-s -w" $(SRC_DIR)

direct_install:
	CGO_ENABLED=1 go install -ldflags "-s -w" $(SRC_DIR)

# Cross Compilation Targets (using xgo2 to support gomod)

direct_build_linux:
	xgo2 --targets=linux/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

direct_build_arm64:
	xgo2 --targets=linux/arm64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

direct_build_win64:
	xgo2 --targets=windows/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

direct_build_win: direct_build_win64

direct_build_darwin:
	xgo2 --targets=darwin/amd64 --dest $(OUTPUT_DIR)/ -ldflags "-s -w" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

direct_all:
	xgo2 --targets=*/* --dest $(OUTPUT_DIR)/ -ldflags "-s -w" --out "you" --pkg=${PKG_DIR} --goproxy=https://mirrors.aliyun.com/goproxy/ ${ROOT_DIR}

all: update_build_info direct_all clear_build_info

build_linux: update_build_info direct_build_linux clear_build_info

build_arm64: update_build_info direct_build_arm64 clear_build_info

build_win: update_build_info direct_build_win clear_build_info

build_darwin: update_build_info direct_build_darwin clear_build_info

docker: build_linux
	docker build -t ${GROUP_NAME}/${SERVICE_NAME}:build .

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