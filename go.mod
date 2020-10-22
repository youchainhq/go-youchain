module github.com/youchainhq/go-youchain

go 1.12

require (
	github.com/ALTree/bigfloat v0.0.0-20180506151649-b176f1e721fc
	github.com/aristanetworks/goarista v0.0.0-20180907105523-ff33da284e76
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ccding/go-stun v0.1.2
	github.com/davecgh/go-spew v1.1.1
	github.com/deckarep/golang-set v1.7.1
	github.com/fatih/color v1.7.0
	github.com/go-stack/stack v1.8.0
	github.com/golang/snappy v0.0.1 // indirect
	github.com/hashicorp/golang-lru v0.5.0
	github.com/huin/goupnp v0.0.0-20180415215157-1395d1447324
	github.com/influxdata/influxdb1-client v0.0.0-20190402204710-8ff2fc3824fc
	github.com/jackpal/go-nat-pmp v0.0.0-20170405195558-28a68d0c24ad
	github.com/kr/pretty v0.2.0 // indirect
	github.com/lucas-clemente/quic-go v0.14.5
	github.com/mattn/go-colorable v0.0.9
	github.com/mattn/go-isatty v0.0.9
	github.com/multiformats/go-multiaddr v0.0.0-20180721003118-d6ad8896def6
	github.com/multiformats/go-multihash v0.0.13 // indirect
	github.com/nanyan/golz4 v1.0.0
	github.com/pborman/uuid v0.0.0-20180827223501-4c1ecd6722e8
	github.com/peterh/liner v1.1.0
	github.com/rcrowley/go-metrics v0.0.0-20190826022208-cac0b30c2563
	github.com/robertkrimen/otto v0.0.0-20180617131154-15f95af6e78d
	github.com/rs/cors v0.0.0-20180826180256-dc7332ab32be
	github.com/stretchr/testify v1.4.0
	github.com/syndtr/goleveldb v1.0.0
	github.com/urfave/cli v1.21.0
	github.com/youchainhq/bls v0.9.0
	golang.org/x/crypto v0.0.0-20200423211502-4bdfaf469ed5
	golang.org/x/net v0.0.0-20200226121028-0de0cce0169b
	golang.org/x/sys v0.0.0-20190904154756-749cb33beabd
	gonum.org/v1/gonum v0.0.0-20190628223043-536a303fd62f
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/karalabe/cookiejar.v2 v2.0.0-20150724131613-8dcd6a7f4951
	gopkg.in/natefinch/lumberjack.v2 v2.0.0-20170531160350-a96e63847dc3
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v2 v2.2.4
)

replace github.com/lucas-clemente/quic-go v0.14.5 => github.com/youchainhq/quic-go v0.14.5
