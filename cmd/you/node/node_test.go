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

package node

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus/solo"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/miner"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/you"
	"github.com/youchainhq/go-youchain/youdb"
	"gopkg.in/yaml.v2"
)

func TestCreateAddressFromPrivateKey(t *testing.T) {
	a := `e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109`
	b, err := crypto.HexToECDSA(a)
	if err != nil {
		fmt.Println(err)
	}
	c := crypto.PubkeyToAddress(b.PublicKey)
	assert.Equal(t, c.String(), "0xbe862AD9AbFe6f22BCb087716c7D89a26051f74C")
}

type Yc struct {
	b *core.BlockChain
	t *core.TxPool
}

type ukey struct {
	Uconkey       string `json:"uconkey"`
	Uconvalidator int    `json:"uconvalidator"`
	Stake         uint64 `json:"stake"`
	Coinbase      string `json:"coinbase"`
	BLSSignkey    string `json:"blssignkey"`
}

func (y *Yc) BlockChain() *core.BlockChain {
	return y.b
}
func (y *Yc) TxPool() *core.TxPool {
	return y.t
}

func TestGenkeys(t *testing.T) {
	t.SkipNow() // run on need
	type Balance struct {
		Balance string `json:"balance"`
	}

	balanceMap := make(map[string]Balance)

	blsmgr := bls.NewBlsManager()
	var arr []ukey
	for i := 0; i < 10000; i++ {
		key, _ := crypto.GenerateKey()
		blskey, _ := blsmgr.GenerateKey()
		addr := crypto.PubkeyToAddress(key.PublicKey).String()
		stake := uint64(rand.Intn(1000))
		u := ukey{
			fmt.Sprintf("%x", crypto.FromECDSA(key)),
			1,
			stake,
			addr,
			fmt.Sprintf("%x", blskey.Compress()),
		}
		arr = append(arr, u)
		balanceMap[addr] = Balance{common.Big0().Mul(new(big.Int).SetUint64(stake), new(big.Int).SetUint64(params.YOU)).String()}
	}

	j, err := json.Marshal(arr)
	if err != nil {
		t.Fatal(err)
	}

	_ = ioutil.WriteFile("ucon.json", j, 0664)
	_ = ioutil.WriteFile("alloc.json", []byte(common.AsJson(balanceMap)), 0664)

	type Pos struct {
		Address string `json:"address"`
		Stake   uint64 `json:"stake"`
	}

	var posTable = make(map[string]*Pos)
	for _, a := range arr {
		p := Pos{a.Coinbase, a.Stake}
		posTable[a.Coinbase] = &p
	}

	_, err = json.Marshal(posTable)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSortHistoryKeys(t *testing.T) {
	t.SkipNow() //comment this line to run this test case
	filePath := "../../../deployment/ci/ucon.json"
	bs, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var ucons []ukey
	err = json.Unmarshal(bs, &ucons)
	if err != nil {
		t.Fatal(err)
	}
	//sort by coin base
	sort.Slice(ucons, func(i, j int) bool {
		return ucons[i].Coinbase < ucons[j].Coinbase
	})
	j, err := json.Marshal(ucons)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(filePath, j, 0664)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenContractCreation(t *testing.T) {
	var (
		acc1Key, _ = crypto.HexToECDSA("372f86826d3a107bd342aa8713081514e97d7dcc8c6f4168a4f8bc6a6c6fa358")
		acc2Key, _ = crypto.HexToECDSA("e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109")
		acc1Addr   = crypto.PubkeyToAddress(acc1Key.PublicKey) //0x59677fD68ec54e43aD4319D915f81748B5a6Ff8B
		acc2Addr   = crypto.PubkeyToAddress(acc2Key.PublicKey) //0xbe862AD9AbFe6f22BCb087716c7D89a26051f74C
	)
	// Remove the journal created in NewTxPool with core.DefaultTxPoolConfig
	defer os.Remove(core.DefaultTxPoolConfig.Journal)

	code := common.Hex2Bytes(`608060405260008055348015601357600080fd5b50607b60005560a8806100276000396000f300608060405260043610603e5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631003e2d281146043575b600080fd5b348015604e57600080fd5b506058600435606a565b60408051918252519081900360200190f35b6000805491909102606f0190819055905600a165627a7a72305820b327b01f1e97c628fa439f6aeffea68c31be1b75a5b93eb2429ee5706a8596a00029`)

	db := youdb.NewMemDatabase()
	gspec := &core.Genesis{
		NetworkId:   params.NetworkIdForTestCase,
		CurrVersion: params.YouCurrentVersion,
		GasLimit:    10000000000000,
		Alloc: core.GenesisAlloc{
			acc1Addr: {Balance: big.NewInt(10000000000000), Nonce: 0},
			acc2Addr: {Balance: big.NewInt(10000000000000), Nonce: 0},
		},
	}
	engine := solo.NewSolo()

	_, err := core.SetupGenesisBlock(db, gspec.NetworkId, gspec)
	assert.NoError(t, err)

	eventMux := new(event.TypeMux)
	blockchain, _ := core.NewBlockChain(db, engine, eventMux)
	defer blockchain.Stop()
	txPool := core.NewTxPool(core.DefaultTxPoolConfig, blockchain)

	minerInstance := miner.NewMiner(&Yc{b: blockchain, t: txPool}, eventMux, engine, nil)
	minerInstance.Start()
	signer := types.NewYouSigner(gspec.NetworkId)

	num := 10
	for i := 0; i < num; i++ {
		nonce := txPool.Nonce(acc1Addr)
		contractTx := types.NewContractCreation(nonce, big.NewInt(100), uint64(700000), big.NewInt(1000), code) //10000000000000 700000000
		signedContractTx, _ := types.SignTx(contractTx, signer, acc1Key)
		err := txPool.AddLocal(signedContractTx)
		assert.NoError(t, err)
	}

	v, err := txPool.Pending()
	assert.NoError(t, err)
	assert.Equal(t, num, len(v[acc1Addr]))
}

func TestMinerInstance(t *testing.T) {
	chainDb := youdb.NewMemDatabase()
	config := &you.DefaultConfig
	_, genesisErr := core.SetupGenesisBlock(chainDb, 1, config.Genesis)
	if genesisErr != nil {
		t.Fatal(genesisErr)
	}
	eventMux := new(event.TypeMux)
	blockChain, _ := core.NewBlockChain(chainDb, solo.NewSolo(), eventMux)

	priv1, _ := crypto.GenerateKey()
	addr1 := crypto.PubkeyToAddress(priv1.PublicKey)
	txPool := core.NewTxPool(core.DefaultTxPoolConfig, blockChain)
	// Remove the journal created in NewTxPool with core.DefaultTxPoolConfig
	defer os.Remove(core.DefaultTxPoolConfig.Journal)
	for i := 0; i < 3; i++ {
		tx := types.NewTransaction(uint64(i), addr1, big.NewInt(1), uint64(0), big.NewInt(0), nil)
		signedTx, _ := types.SignTx(tx, types.NewYouSigner(config.NetworkId), priv1)
		err := txPool.AddLocal(signedTx)
		if err != nil {
			fmt.Println("nonce", i, "err", err.Error())
		}
	}

	nonce := txPool.Nonce(addr1)
	fmt.Println("nonce", nonce)
}

func TestGenConfigYaml(t *testing.T) {
	c := node.Config{}
	bs, _ := yaml.Marshal(c)
	fmt.Println(string(bs))
}
