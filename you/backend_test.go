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

package you

import (
	"crypto/ecdsa"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/node"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

var (
	genesisJsonString = `{
  "config": {
        "networkId": 111
    },
  "consensus"  : "0xf8ea80a0a903f2c9575a4b01e70e0e589494bdb6850a18299f433f0b2eaf9a60469d2f4bb8811817c610db2610f59d5067df6c50f1b19cf1f24cdd31a1e84310ef6fa8b5d2a93e489bef1c60d67ee7145d975ebd366a73f9602ae4ab8a3c7f0948d54263939904d81c215d8a0de0587c39fb20225699ec257062c870a48fcdd5ba5e5c0351134248b4a34a09c8eb779737b36cf6e4a4371c03e162cb5af45ca5e2682ac9787be0a000000000000000000000000000000000000000000000000000000000000000008080a0000000000000000000000000000000000000000000000000000000000000000080",
  "gasLimit"   : "0xffffffff",
  "mixhash"    : "0x87c71741b903194ab0eb0bd581d5c522f0328e979f3c1bf29f6068bd2797fdf8",
  "parentHash" : "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp"  : "0x00",
  "alloc": {
        "0x59677fD68ec54e43aD4319D915f81748B5a6Ff8B": {
            "balance": "3100000000000000000000000000"
        }
    }
}
`
)

func DefaultTestKey() (*ecdsa.PrivateKey, common.Address) {
	key, _ := crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

func TestNew(t *testing.T) {
	t.SkipNow() //fix it or run on need
	stopSignal := make(chan os.Signal, 1)
	signal.Notify(stopSignal, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL, syscall.SIGHUP, syscall.SIGQUIT)

	config := &Config{}
	genesis := &core.Genesis{}
	err := genesis.UnmarshalJSON([]byte(genesisJsonString))
	if err != nil {
		logging.Crit("decode err", "err", err.Error())
	}
	config.Genesis = genesis

	port := 0
	//sk, _ := crypto.GenerateKey()
	//uconKey:= common.Bytes2Hex(crypto.FromECDSA(sk))
	//fmt.Println(uconKey)
	uconKeyList := [10]string{
		"979143aacdfde59bfb947f62532f39cbdae68ea6c2014004afefb4302b2d6f09",
		"fc0f1d6d5bb78908e9288bd556700a3504ecf25408776916a85ca2754049562b",
		"7fa38b35f7b6d753e4e95813c3bf0b8ebe29c6ba1e729e2b7f8818f157dd75ed",
		"9782599167f4664ba99c6bf3ec1e3ca748bdd33314753788ae8a212ca0a44f51",
		"ad2762d0493431b301d63b865c6b9e9cb20b33899cf5dc22ab7f397714258964",
		"9bf3516b359b103ea85eb37bf32366ab1fc156464f899ea7fb1ebd99d4ee100c",
		"eacf31bbd2ea414299cb73b6c2d2c89069d1745058212553626b1ed4a702410c",
		"dc03598b8429e0af61cceec2a113896192b59d5e0ca2429385bd8dd7aac7c89a",
		"47a8428a25ba6f1011f55f70b6d0c0df5080233e58fdb653a3488f84b72a584a",
		"e989636333c8dc8efdb7e5831d6d0c606900794dcdeecb1892c4103e23a646ce",
	}

	nodeConfig := node.Config{
		//HTTPPort: 8001,
		//HTTPHost: "0.0.0.0",
		P2pPort: 6890 + port,
		//P2pSeed: "/ip4/0.0.0.0/tcp/6890/ipfs/12D3KooWHwgje7Uq4WrNf2H23vobVHzHAa7959A2FuRGGeypDrtb", //
		DataDir: "p2p",
		//UConValidator: 1,
		UConKey: uconKeyList[port], //"7d60cfed353fa2248abc1c2ca2346ad90b405da8285feea474f459a5ed4f323c",
	}
	if port > 0 {
		nodeConfig.P2PBootNode = "/ip4/0.0.0.0/tcp/6890/ipfs/12D3KooWB8vVJsuYHB7seWb9voD2Y2zvTuGHi3KaSSLEwUfWLiuY"
		//nodeConfig.P2pSeed = "/ip4/123.113.35.164/tcp/63708/ipfs/12D3KooWB6Zn4rcG1mfDwf2d9s8acQZY3rsW7mANAFwzaE3Mz4Dm"
	}
	//nodeConfig.P2pSeed = "/ip4/106.121.19.240/tcp/6890/ipfs/12D3KooWSGAyQc8wkXieEh8E1LFyppiZ9DDGzt4NLcCjBLsRtBmg"

	yc, err := New(config, &nodeConfig)
	if err != nil {
		logging.Crit("new failed", "err", err.Error())
	}
	block := yc.blockChain.GetBlockByNumber(0)
	logging.Info("zeroBlock hash", block.Hash().String())
	//hs, err := block.Header().MarshalJSON()
	//log.Info(string(hs))
	//block1 := you.blockChain.GetBlockByNumber(1)
	//log.Info("Block 1 hash", block1.Hash().String())
	//hs1, err := block1.Header().MarshalJSON()
	//log.Info(string(hs1))

	yc.Start(nil)

	key, addr := DefaultTestKey()
	logging.Info("addr", addr.String())
	logging.Info("private", hexutil.Encode(crypto.FromECDSA(key)))

	ticker := time.NewTicker(30 * time.Second)
	nonce := 100
	for {
		select {
		case <-ticker.C:
			if port == 10 {
				signer := types.MakeSigner(big.NewInt(0))
				for i := nonce; i < nonce+2; i++ {
					tx := types.NewTransaction(uint64(i), addr, new(big.Int), 0, new(big.Int), nil)
					tx, _ = types.SignTx(tx, signer, key)
					e := yc.txPool.AddLocal(tx)
					if e != nil {
						logging.Info("err", i, e)
					}
				}
				nonce += 2
			}
		}
	}
}
