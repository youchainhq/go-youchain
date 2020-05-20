SDK_VERSION = 190416
SDK_ARCH_ANDROID = android/arm,android/386
SDK_ARCH_IOS = ios
SDK_NAME = YouMobile
SDK_BUILD_DIR = $(GOPATH)/src/youchain/you-release
BIN_BUILD_TIME = $(shell date +"%Y%m%d-%H%M")
SDK_BUILD_DIST_DIR=$(SDK_BUILD_DIR)/mobile-sdk

all: clean generate android ios
generate:
	go generate
	mkdir -p $(SDK_BUILD_DIST_DIR)

android:
	gomobile bind -target=$(SDK_ARCH_ANDROID) -ldflags "-s -w" -v -o=$(SDK_BUILD_DIST_DIR)/$(SDK_NAME).aar
	@open $(SDK_BUILD_DIR)

ios:
	gomobile bind -target=$(SDK_ARCH_IOS) -ldflags "-s -w" -v -o=$(SDK_BUILD_DIST_DIR)/$(SDK_NAME).framework
	@open $(SDK_BUILD_DIR)

clean:
	rm -f $(SDK_BUILD_DIR)/$(SDK_NAME).aar
	rm -f $(SDK_BUILD_DIR)/$(SDK_NAME)-sources.jar
	rm -rf $(SDK_BUILD_DIR)/$(SDK_NAME).framework
