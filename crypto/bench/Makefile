PKG_DIR = github.com/youchainhq/go-youchain/crypto/bench
ROOT_DIR = ../../

all: build_linux build_win64 build_win32 build_darwin build_arm64

build_linux:
	xgo2 --targets=linux/amd64 -out bench -ldflags "-s -w"  --pkg=${PKG_DIR} ${ROOT_DIR}

build_win64:
	xgo2 --targets=windows/amd64 -out bench  -ldflags "-s -w"  --pkg=${PKG_DIR} ${ROOT_DIR}

build_win32:
	xgo2 --targets=windows/386 -out bench  -ldflags "-s -w"  --pkg=${PKG_DIR} ${ROOT_DIR}

build_darwin:
	CGO_ENABLED=1 go build -o "bench-darwin" -ldflags '-s -w' .

build_arm64:
	xgo2 --targets=linux/arm64 -out bench  -ldflags "-s -w"  --pkg=${PKG_DIR} ${ROOT_DIR}
