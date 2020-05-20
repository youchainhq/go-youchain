package params

var MainnetBootnodes = []string{
	"enode://9af98f9bb26530b7cd7449a580c7f0b10457b9404810ad93651edd9061245e981dde2244acaf122843bce3e513756c2455c8cadc420305515be7ee942e549b6d@47.114.151.44:9283?discport=9284&nat=2&nodetype=2",
	"enode://9ca4777fc642ccbb5e2cf120dae8c05b4dc827390daa82442a5cbbcf4944e995089b96d2f6a479847376d5ecc0f6fa25e42309975e6d50952a61231a3b0df517@47.111.249.64:9283?discport=9284&nat=2&nodetype=2",
	"enode://7eb533b94f5e28cfd2bdb198a494f2ce50464ee4246f0fcf05839fcb55631e9331170b6513ff98930d210a2a017d34f953d3637df0b8b798f7bc42dbccad9355@47.93.225.217:9283?discport=9284&nat=2&nodetype=2",
}

// TODO Bootstrap node information needs to be added when the main chain is launched
var TestnetBootnodes = []string{
	// ex. "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.68:9283?discport=9284&nat=1&nodetype=1"
}

func LoadBootstrapNodes() []string {
	id := NetworkId()
	if id == uint64(MainNetId) {
		return MainnetBootnodes
	} else if id == uint64(TestNetId) {
		return TestnetBootnodes
	}

	return nil
}
