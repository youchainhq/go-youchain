// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus/solo"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"testing"
)

var (
	acc1Key, _ = crypto.HexToECDSA("372f86826d3a107bd342aa8713081514e97d7dcc8c6f4168a4f8bc6a6c6fa358")
	acc2Key, _ = crypto.HexToECDSA("e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109")
	acc1Addr   = crypto.PubkeyToAddress(acc1Key.PublicKey) //0x59677fD68ec54e43aD4319D915f81748B5a6Ff8B
	acc2Addr   = crypto.PubkeyToAddress(acc2Key.PublicKey) //0xbe862AD9AbFe6f22BCb087716c7D89a26051f74C
	codes      = map[string][]byte{
		"empty.sol": common.FromHex(`6080604052348015600f57600080fd5b50603e80601d6000396000f3fe6080604052600080fdfea265627a7a72305820b71462d9dc5e24650216fec41572af20d4a64227b0d3f372875954c08c3fd29a64736f6c634300050a0032`),
		"erc20.sol": common.FromHex(`608060405234801561001057600080fd5b50610394806100206000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806318160ddd1461004657806370a0823114610064578063a9059cbb146100bc575b600080fd5b61004e610122565b6040518082815260200191505060405180910390f35b6100a66004803603602081101561007a57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610128565b6040518082815260200191505060405180910390f35b610108600480360360408110156100d257600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610171565b604051808215151515815260200191505060405180910390f35b60005481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60008073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614156101ac57600080fd5b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020548211156101f857600080fd5b61024a82600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461032c90919063ffffffff16565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506102df82600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461034390919063ffffffff16565b600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506001905092915050565b60008282111561033857fe5b818303905092915050565b60008082840190508381101561035557fe5b809150509291505056fea265627a7a72305820bca9fee6c7584a8a19c5e8d9852c09e47b5a57c898a2b0da0654c186f5a6c18564736f6c634300050a0032`),
		"cat.sol":   common.FromHex(`608060405234801561001057600080fd5b50600a60ff16600a0a63bebc20000260008190555061024b806100346000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806306fdde031461005157806318160ddd146100d4578063313ce567146100f257806395d89b4114610116575b600080fd5b610059610199565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561009957808201518184015260208101905061007e565b50505050905090810190601f1680156100c65780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6100dc6101d2565b6040518082815260200191505060405180910390f35b6100fa6101d8565b604051808260ff1660ff16815260200191505060405180910390f35b61011e6101dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561015e578082015181840152602081019050610143565b50505050905090810190601f16801561018b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6040518060400160405280600381526020017f594f32000000000000000000000000000000000000000000000000000000000081525081565b60005481565b600a81565b6040518060400160405280600381526020017f594f3200000000000000000000000000000000000000000000000000000000008152508156fea265627a7a7230582008ec7efb32a01653e7e4dda9f701bf80ac52651f5b20983f85e8c313cc767cb964736f6c634300050a0032`),
	}
	db    = youdb.NewMemDatabase()
	gspec = Genesis{
		NetworkId:   params.NetworkIdForTestCase,
		CurrVersion: params.YouCurrentVersion,
		Alloc:       GenesisAlloc{acc1Addr: {Balance: big.NewInt(1000000000000000000)}, acc2Addr: {Balance: big.NewInt(1000000000000000000)}},
	}
)

//=====NOTICE======
// A unit-test for `insertSidechain`, `verifyAllSideChainBlocks` and `consensus.Ucon.VerifySideChainHeader`
// see the test case `TestUconFork` in cmd/you/ucon_integrate_test.go
//=================

func TestHex(t *testing.T) {
	v := common.Hex2Bytes(`608060405260008055348015601357600080fd5b50607b60005560a8806100276000396000f300608060405260043610603e5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631003e2d281146043575b600080fd5b348015604e57600080fd5b506058600435606a565b60408051918252519081900360200190f35b6000805491909102606f0190819055905600a165627a7a72305820b327b01f1e97c628fa439f6aeffea68c31be1b75a5b93eb2429ee5706a8596a00029`)
	fmt.Println(len(v))
}

func TestEvm(t *testing.T) {
	genesisHash, _ := SetupGenesisBlock(db, params.NetworkIdForTestCase, &gspec)
	logging.Info(genesisHash.String())
	// Time the insertion of the new chain.
	// State and blocks are stored in the same DB.
	bc, _ := NewBlockChain(db, solo.NewSolo(), nil)
	st, _ := bc.State()
	vmCfg, err := PrepareVMConfig(bc, 0, vm.LocalConfig{})
	require.NoError(t, err)

	signer := types.MakeSigner(big.NewInt(0))
	for _, code := range codes {
		//log.Info("code", i+1)
		//log.Info("code", string(code))

		gp := new(GasPool).AddGas(100000000000)
		unsignedTx := types.NewContractCreation(st.GetNonce(acc1Addr), big.NewInt(0), uint64(1000000), big.NewInt(2), code)
		tx, err := types.SignTx(unsignedTx, signer, acc1Key)
		assert.Nil(t, err)
		msg, _ := tx.AsMessage(signer)
		ret, usedGas, _, err := bc.Processor().ApplyMessageEntry(msg, st, bc, bc.CurrentHeader(), &acc1Addr, gp, vmCfg)
		assert.Nil(t, err)
		logging.Info("codes", "ret", common.Bytes2Hex(ret), "usedGas", usedGas)
		logging.Info("codes", "acc1Addr", acc1Addr.String(), "balance", st.GetBalance(acc1Addr).String())
	}

	ss := st.GetOrNewStateObject(common.HexToAddress("0x179be2eA3e8d96C4Cf4361279522217668679E64"))
	logging.Info("GetOrNewStateObject", "ss", ss.Balance())
	logging.Info("GetOrNewStateObject", "ss.CodeHash", common.Bytes2Hex(ss.CodeHash()))
	logging.Info("GetOrNewStateObject", "ss.Code", len(ss.Code(st.Database())))
}

func TestEmptyCode(t *testing.T) {
	emptyState := crypto.Keccak256Hash(nil)
	fmt.Println(emptyState.String())
	emptyRoot := common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	fmt.Println(emptyRoot.String())

}

func TestInitSealForLeapfrogVerify(t *testing.T) {
	type item struct {
		StartNum uint64
		Ln       int
		Want     []bool
	}
	dt := []item{
		{StartNum: 16, Ln: 3, Want: []bool{true, true, true}},
		{StartNum: 10, Ln: 6, Want: []bool{true, true, true, true, true, true}},
		{StartNum: 10, Ln: 7, Want: []bool{false, false, false, false, false, false, true}},
		{StartNum: 16, Ln: 9, Want: []bool{true, false, false, false, false, false, false, false, true}},
		{StartNum: 16, Ln: 10, Want: []bool{true, false, false, false, false, false, false, false, true, true}},
		{StartNum: 16, Ln: 11, Want: []bool{true, false, false, false, false, false, false, false, true, true, true}},
	}
	for _, d := range dt {
		got := initSealForLeapfrogVerify(d.StartNum, 8, d.Ln)
		if len(got) != len(d.Want) {
			t.Errorf("got: %v want: %v", got, d.Want)
		} else {
			for i := 0; i < len(got); i++ {
				if got[i] != d.Want[i] {
					t.Errorf("got[%d]: %v want[%d]: %v", i, got[i], i, d.Want[i])
				}
			}
		}
	}
}
