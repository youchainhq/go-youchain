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
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus/solo"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"testing"
)

func TestContractCallLib(t *testing.T) {
	acc1Key, _ := crypto.HexToECDSA("372f86826d3a107bd342aa8713081514e97d7dcc8c6f4168a4f8bc6a6c6fa358")
	//contract built-in owner
	acc1Addr := crypto.PubkeyToAddress(acc1Key.PublicKey) //0x59677fD68ec54e43aD4319D915f81748B5a6Ff8B
	genesis := DefaultGenesisBlock()
	balance, ok := new(big.Int).SetString("100000000000000000000000", 10)
	require.True(t, ok)
	genesis.Alloc[acc1Addr] = GenesisAccount{Balance: balance}

	db := youdb.NewMemDatabase()
	_, err := SetupGenesisBlock(db, 1, genesis)
	require.NoError(t, err, "SetupGenesisBlock")
	// Time the insertion of the new chain.
	// State and blocks are stored in the same DB.
	bc, _ := NewBlockChain(db, solo.NewSolo(), nil)
	st, _ := bc.State()
	vmCfg, err := PrepareVMConfig(bc, 0, vm.LocalConfig{})
	require.NoError(t, err)

	// lib
	code := libCode()
	deploy(t, bc, st, vmCfg, acc1Addr, code)

	//contract
	code = contCode()
	caddr := deploy(t, bc, st, vmCfg, acc1Addr, code)
	//	Function signatures:
	//	f8b2cb4f: getBalance(address)
	//	7bd703e8: getBalanceInEth(address)
	//	90b98a11: sendCoin(address,uint256)
	input := common.Hex2Bytes("7bd703e8")
	input = append(input, caddr.Hash().Bytes()...)

	call(t, bc, st, vmCfg, acc1Addr, caddr, input)
}

func deploy(t *testing.T, bc *BlockChain, st *state.StateDB, vmCfg *vm.Config, from common.Address, code []byte) common.Address {
	gp := new(GasPool).AddGas(100000000000)
	callerNonce := st.GetNonce(from)
	gasPrice := big.NewInt(1000000000)
	msg := types.NewMessage(from, nil, callerNonce, big.NewInt(0), uint64(50000000), gasPrice, code, true)
	_, usedGas, failed, err := bc.Processor().ApplyMessageEntry(msg, st, bc, bc.CurrentHeader(), nil, gp, vmCfg)
	fmt.Println("usedGas", usedGas, "token", new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(usedGas)))
	require.NoError(t, err)
	require.False(t, failed)

	contractAddr := crypto.CreateAddress(acc1Addr, callerNonce)

	fmt.Println("contractAddr", contractAddr.String())
	return contractAddr
}

func call(t *testing.T, bc *BlockChain, st *state.StateDB, vmCfg *vm.Config, from, to common.Address, data []byte) {
	gp := new(GasPool).AddGas(100000000000)
	gasPrice := big.NewInt(1000000000)
	msg := types.NewMessage(from, &to, 0, big.NewInt(0), uint64(50000000), big.NewInt(1000000000), data, false)
	ret, usedGas, failed, err := bc.Processor().ApplyMessageEntry(msg, st, bc, bc.CurrentHeader(), nil, gp, vmCfg)
	fmt.Println("usedGas", usedGas, "token", new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(usedGas)))
	require.NoError(t, err)
	require.False(t, failed)
	fmt.Printf("call result: %v\n", ret)
}

func libCode() []byte {
	/*
		library ConvertLib{
			function convert(uint amount,uint conversionRate) public pure returns (uint convertedAmount)
			{
				return amount * conversionRate;
			}
		}
	*/
	return common.Hex2Bytes("60b361002f600b82828239805160001a6073146000811461001f57610021565bfe5b5030600052607381538281f300730000000000000000000000000000000000000000301460806040526004361060395760003560e01c63ffffffff16806396e4ee3d14603e575b600080fd5b60646004803603810190808035906020019092919080359060200190929190505050607a565b6040518082815260200191505060405180910390f35b60008183029050929150505600a165627a7a723058201edc74391fe4eeac517bc167157c4c9c0a20bd426fc94e6604a7d33cf9e3f1650029")
}

func contCode() []byte {
	/*
		contract MetaCoin {
			mapping (address => uint) balances;

			event Transfer(address indexed _from, address indexed _to, uint256 _value);

			constructor() public {
				balances[tx.origin] = 10000;
			}

			function sendCoin(address receiver, uint amount) public returns(bool sufficient) {
				if (balances[msg.sender] < amount) return false;
				balances[msg.sender] -= amount;
				balances[receiver] += amount;
				emit Transfer(msg.sender, receiver, amount);
				return true;
			}

			function getBalanceInEth(address addr) public view returns(uint,uint,uint){
				uint a = getBalance(addr);
				uint b = ConvertLib.convert(a,2);
				uint c = ConvertLib.convert(3,7);
				return (a,b,c);
			}

			function getBalance(address addr) public view returns(uint) {
				return balances[addr];
			}
		}
	*/

	// for --libraries ConvertLib:0x9e7361EB4749D45EDf4a048b3E87595F97054A77
	return common.Hex2Bytes("608060405234801561001057600080fd5b506127106000803273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555061047f806100656000396000f30060806040526004361061003a5760003560e01c63ffffffff1680637bd703e81461003f57806390b98a11146100a4578063f8b2cb4f14610109575b600080fd5b34801561004b57600080fd5b50610080600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610160565b60405180848152602001838152602001828152602001935050505060405180910390f35b3480156100b057600080fd5b506100ef600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506102b2565b604051808215151515815260200191505060405180910390f35b34801561011557600080fd5b5061014a600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061040b565b6040518082815260200191505060405180910390f35b6000806000806000806101728761040b565b9250739e7361eb4749d45edf4a048b3e87595f97054a776396e4ee3d8460026040518363ffffffff1660e01b8152600401808381526020018281526020019250505060206040518083038186803b1580156101cc57600080fd5b505af41580156101e0573d6000803e3d6000fd5b505050506040513d60208110156101f657600080fd5b81019080805190602001909291905050509150739e7361eb4749d45edf4a048b3e87595f97054a776396e4ee3d600360076040518363ffffffff1660e01b8152600401808381526020018281526020019250505060206040518083038186803b15801561026257600080fd5b505af4158015610276573d6000803e3d6000fd5b505050506040513d602081101561028c57600080fd5b810190808051906020019092919050505090508282829550955095505050509193909250565b6000816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156103035760009050610405565b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282540392505081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190505b92915050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490509190505600a165627a7a72305820fd4e2d9a9165bb628168b6f86d1d30c9a13fd0ff297c6cda65b7c9be53d7cb8c0029")
}
