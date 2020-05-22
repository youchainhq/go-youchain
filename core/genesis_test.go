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
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"testing"
)

var genesisDemo = `
{
	"networkId":99,
	"consensus":"0xf8f28001a0388582ae9408aea9a2789980a52c9a7f3953ac287777f7503ac189afe434dae8b881c24b3ea8d229d64c57c4237f8b6e161f197d2355ec68f10dc97f2ef97a36fe8df33fc7b074186b6bb6919efbb7ea7f97432dd6b41cb178c2791f0f2d03409aba04947dfa8c20629f8b14df0413164add799068024fca3172c2a8e83f41cf2b3fb6a89bc4b63d3147fa9d74db3d98d180b25fc38776c27740e2493f3d0f485b0b87a0010000000000000000000000000000000000000000000000000000000000000001a00100000000000000000000000000000000000000000000000000000000000000018502540be400801a",
    "gasLimit": "0xffffffff",
    "mixhash":"0x87c71741b903194ab0eb0bd581d5c522f0328e979f3c1bf29f6068bd2797fdf8",
    "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp":"0x00",
	"version":1,
    "alloc":{
        "0x59677fD68ec54e43aD4319D915f81748B5a6Ff8B":{
            "balance":"3100000000000000000000000000"
        },
        "0x5e0d404c85A88FA97F1E33087547EA1B18bb03d4": {
            "balance": "1000000000000000000000"
        },
        "0xfEA007b01Df96a2e54C04D0F20a66818Fd5A9016": {
            "balance": "1000000000000000000000"
        },
        "0x96E79c805AC0EF282e97894C635d20dC36Bc1133": {
            "balance": "1000000000000000000000"
        },
        "0xedB430903e6cf8ACf8dFe50C448A090F375d50D7": {
            "balance": "1000000000000000000000"
        },
        "0xeFE0a5d9b083e3225d595C11A936EB85881781ac": {
            "balance": "1000000000000000000000"
        },
        "0xc5F0D7dEEE8fab98F88de0Fb75fC28E3B54146BA": {
            "balance": "1000000000000000000000"
        }
    },
	"validators": {
	    "0xa716bbbde530e58c4b400ce63320970714aaa89a": {
    		"name": "",
      		"operatorAddress": "0xa716bBBDE530E58C4b400cE63320970714aaa89a",
      		"coinbase": "0xa716bBBDE530E58C4b400cE63320970714aaa89a",
      		"mainPubKey": "0x0394831c73142b89c6dd7b3eb43649994742bef08145f27d520e92354a3990920e",
      		"blsPubKey": "0xa079279906f09d9deedfaaa5ccef4a5de2ab2e04b073d1b7a51cdcbd5cc28a2dc5a63acdae0a0771eeba59b5e2c483fa031688f3f85e9669f0a9355f33fd797b2814fcf937a304ba06b05eb2226fda87207282ac83103c0571f45974b9b905b1",
      		"token": "0x1fc3842bd1f071c00000",
      		"role": 3,
      		"status": 1
    	},
    	"0xbe635e5a8d2552160c26221adc1c8a58730e388b": {
      		"name": "",
      		"operatorAddress": "0xbe635E5a8D2552160c26221ADC1c8A58730E388B",
      		"coinbase": "0xbe635E5a8D2552160c26221ADC1c8A58730E388B",
      		"mainPubKey": "0x024646f2ec9575438d961e945aaab6af5fd284b60d004671e9ccc434cbfa94b5b6",
      		"blsPubKey": "0x882027d7f466cd0ce33c67d569ae9cb3258fdb8ab6db2ca0c52732d47123ecda641b36473c04e4214966b21d2ca28ff6071544ee32b7ec3e38c9e8505791d950397ad336c045593b4cc88c8ba0e051804c8eb1b06c0e94469945ff517c0860e2",
      		"token": "0xc7e657b0c9a4ee00000",
      		"role": 2,
      		"status": 1
    	},
    	"0xccc6936e6fcbedf2db1becf46399e0e153dd189c": {
      		"name": "",
      		"operatorAddress": "0xCCc6936E6FcbEdF2Db1bECf46399E0E153dd189c",
      		"coinbase": "0xCCc6936E6FcbEdF2Db1bECf46399E0E153dd189c",
      		"mainPubKey": "0x02277c7a972777a090970cd7637989ae7c158fe371d98119114b705c04c6429172",
      		"blsPubKey": "0xa31bdad808cec395781db027af17dc853184dd35c53cd18aaef3911b023b4946ba5a928a81c257f06b5f8e132aafa9570bceeba4af1ee0510bc71d5058b02d87430a6dbaa72838f5c72fd16aa9d9262f7860272b62d32db00dc9174d4a422e04",
      		"token": "0x59ff4bd17d7e97a00000",
      		"role": 3,
      		"status": 1
    	},
    	"0xe4926b924960eeef6801c3c9de7470e7de7ab49f": {
      		"name": "",
      		"operatorAddress": "0xE4926b924960eEEF6801C3C9dE7470e7dE7ab49F",
      		"coinbase": "0xE4926b924960eEEF6801C3C9dE7470e7dE7ab49F",
      		"mainPubKey": "0x03827a57e8afe1215464730e74d5ae2c2305f773dde5e412ede46761b562aebb66",
      		"blsPubKey": "0x98cd979838545cc061dcbcde123ccda824473429830113a5452dabf04db7c4966c03c805ae0b966b31a584b12efe02741937799c740058b22eacf7a52b724164d1ab25875934b636e54440e123ef59128a4ee2bb55900ebcaec45a44570eee12",
      		"token": "0x112704cffb9b70a00000",
      		"role": 2,
      		"status": 1
    	},
    	"0xfc417779c6805a80fe8e788335ffd9f326aa5893": {
      		"name": "",
      		"operatorAddress": "0xFc417779C6805A80Fe8e788335ffD9F326AA5893",
      		"coinbase": "0xFc417779C6805A80Fe8e788335ffD9F326AA5893",
      		"mainPubKey": "0x02caaee86e678fe50e4dcbfb5c44c34068c98d4beb5e48ec48873b66735d963686",
      		"blsPubKey": "0xaf1f6e9853a8b5ed698d0b4769b023f5a6e417809c9ca981f063d94ab81d1b9028ad675fd6a0e2614cd62b719861ff09127500f97b7277dfc83a5f4b3711736c9a188631f2f1e8216be744c6af64aaa3751dc3c24728dd595ef9605b466e065d",
      		"token": "0xb35bf645f1ab93600000",
      		"role": 2,
      		"status": 1
    	}
	}
}
`

var validatorDemo = `
{
  "name": "",
  "operatorAddress": "0xbe635E5a8D2552160c26221ADC1c8A58730E388B",
  "coinbase": "0xbe635E5a8D2552160c26221ADC1c8A58730E388B",
  "mainPubKey": "0x024646f2ec9575438d961e945aaab6af5fd284b60d004671e9ccc434cbfa94b5b6",
  "blsPubKey": "0x882027d7f466cd0ce33c67d569ae9cb3258fdb8ab6db2ca0c52732d47123ecda641b36473c04e4214966b21d2ca28ff6071544ee32b7ec3e38c9e8505791d950397ad336c045593b4cc88c8ba0e051804c8eb1b06c0e94469945ff517c0860e2",
  "token": "0xc7e657b0c9a4ee00000",
  "role": 2,
  "status": 1
}
`

var validatorsDemo = `
{
    "0xa716bbbde530e58c4b400ce63320970714aaa89a": {
      "name": "",
      "operatorAddress": "0xa716bBBDE530E58C4b400cE63320970714aaa89a",
      "coinbase": "0xa716bBBDE530E58C4b400cE63320970714aaa89a",
      "mainPubKey": "0x0394831c73142b89c6dd7b3eb43649994742bef08145f27d520e92354a3990920e",
      "blsPubKey": "0xa079279906f09d9deedfaaa5ccef4a5de2ab2e04b073d1b7a51cdcbd5cc28a2dc5a63acdae0a0771eeba59b5e2c483fa031688f3f85e9669f0a9355f33fd797b2814fcf937a304ba06b05eb2226fda87207282ac83103c0571f45974b9b905b1",
      "token": "0x1fc3842bd1f071c00000",
      "role": 3,
      "status": 1
    },
    "0xbe635e5a8d2552160c26221adc1c8a58730e388b": {
      "name": "",
      "operatorAddress": "0xbe635E5a8D2552160c26221ADC1c8A58730E388B",
      "coinbase": "0xbe635E5a8D2552160c26221ADC1c8A58730E388B",
      "mainPubKey": "0x024646f2ec9575438d961e945aaab6af5fd284b60d004671e9ccc434cbfa94b5b6",
      "blsPubKey": "0x882027d7f466cd0ce33c67d569ae9cb3258fdb8ab6db2ca0c52732d47123ecda641b36473c04e4214966b21d2ca28ff6071544ee32b7ec3e38c9e8505791d950397ad336c045593b4cc88c8ba0e051804c8eb1b06c0e94469945ff517c0860e2",
      "token": "0xc7e657b0c9a4ee00000",
      "role": 2,
      "status": 1
    },
    "0xccc6936e6fcbedf2db1becf46399e0e153dd189c": {
      "name": "",
      "operatorAddress": "0xCCc6936E6FcbEdF2Db1bECf46399E0E153dd189c",
      "coinbase": "0xCCc6936E6FcbEdF2Db1bECf46399E0E153dd189c",
      "mainPubKey": "0x02277c7a972777a090970cd7637989ae7c158fe371d98119114b705c04c6429172",
      "blsPubKey": "0xa31bdad808cec395781db027af17dc853184dd35c53cd18aaef3911b023b4946ba5a928a81c257f06b5f8e132aafa9570bceeba4af1ee0510bc71d5058b02d87430a6dbaa72838f5c72fd16aa9d9262f7860272b62d32db00dc9174d4a422e04",
      "token": "0x59ff4bd17d7e97a00000",
      "role": 3,
      "status": 1
    },
    "0xe4926b924960eeef6801c3c9de7470e7de7ab49f": {
      "name": "",
      "operatorAddress": "0xE4926b924960eEEF6801C3C9dE7470e7dE7ab49F",
      "coinbase": "0xE4926b924960eEEF6801C3C9dE7470e7dE7ab49F",
      "mainPubKey": "0x03827a57e8afe1215464730e74d5ae2c2305f773dde5e412ede46761b562aebb66",
      "blsPubKey": "0x98cd979838545cc061dcbcde123ccda824473429830113a5452dabf04db7c4966c03c805ae0b966b31a584b12efe02741937799c740058b22eacf7a52b724164d1ab25875934b636e54440e123ef59128a4ee2bb55900ebcaec45a44570eee12",
      "token": "0x112704cffb9b70a00000",
      "role": 2,
      "status": 1
    },
    "0xfc417779c6805a80fe8e788335ffd9f326aa5893": {
      "name": "",
      "operatorAddress": "0xFc417779C6805A80Fe8e788335ffD9F326AA5893",
      "coinbase": "0xFc417779C6805A80Fe8e788335ffD9F326AA5893",
      "mainPubKey": "0x02caaee86e678fe50e4dcbfb5c44c34068c98d4beb5e48ec48873b66735d963686",
      "blsPubKey": "0xaf1f6e9853a8b5ed698d0b4769b023f5a6e417809c9ca981f063d94ab81d1b9028ad675fd6a0e2614cd62b719861ff09127500f97b7277dfc83a5f4b3711736c9a188631f2f1e8216be744c6af64aaa3751dc3c24728dd595ef9605b466e065d",
      "token": "0xb35bf645f1ab93600000",
      "role": 2,
      "status": 1
    }
}
`

func TestValidator_UnmarshalJSON(t *testing.T) {
	var val GenesisValidator
	err := val.UnmarshalJSON([]byte(validatorDemo))
	assert.Nil(t, err)
}

func TestValidators_UnmarshalJSON(t *testing.T) {
	var valSet GenesisValidators
	err := valSet.UnmarshalJSON([]byte(validatorsDemo))
	assert.Nil(t, err)
	if err != nil {
		return
	}
	addr := common.HexToAddress(`0xe4926b924960eeef6801c3c9de7470e7de7ab49f`)
	gv := valSet[addr]
	assert.NotNil(t, gv)

	coinbase := common.BigToAddress(big.NewInt(111111))

	vals := []*state.Validator{}
	for operatorAddress, v := range valSet {
		stake := params.YOUToStake(v.Token)
		val := state.NewValidator(operatorAddress.String(), operatorAddress, coinbase, v.Role, v.MainPubKey, v.BlsPubKey, v.Token, stake, 0, 0, 0, params.ValidatorOnline)
		vals = append(vals, val)
	}
	valset := state.NewValidators(vals)
	idx, _ := valset.GetIndex(state.PubToAddress(gv.MainPubKey))
	assert.Equal(t, 3, idx)
}

func TestValidators_Marshal(t *testing.T) {
	valset := GenesisValidators{}
	for i := 0; i < 10; i++ {
		k, _ := crypto.GenerateKey()
		bs := crypto.CompressPubkey(&k.PublicKey)
		addr := crypto.PubkeyToAddress(k.PublicKey)
		val := GenesisValidator{
			Token:      big.NewInt(10000000000000000),
			BlsPubKey:  hexutil.Bytes(bs),
			MainPubKey: hexutil.Bytes(bs),
		}
		valset[addr] = val
	}
	_, err := json.Marshal(&valset)
	assert.Nil(t, err)
}

func TestExtra(t *testing.T) {
	original := []byte("From the 15th to the 17th century, new routes were opened and economic activities entered the most active period.")

	enc := hexutil.Encode(original)

	t.Logf("%s", enc)

	dec, err := hexutil.Decode(enc)
	assert.Nil(t, err)

	assert.Equal(t, dec, original)
}

func TestGenesis_UnmarshalJSON(t *testing.T) {
	var genesis Genesis
	err := genesis.UnmarshalJSON([]byte(genesisDemo))
	assert.Nil(t, err)
	assert.Equal(t, len(genesis.Alloc), 7)
	assert.Equal(t, len(genesis.Validators), 5)
}

func TestGenesis_ToBlock(t *testing.T) {
	db := youdb.NewMemDatabase()
	var genesis Genesis
	err := genesis.UnmarshalJSON([]byte(genesisDemo))
	assert.Nil(t, err)
	err = genesis.PreCheck()
	assert.NoError(t, err)
	blk := genesis.ToBlock(db)
	assert.NotNil(t, blk)
	bs, _ := json.MarshalIndent(blk.Header(), "", "    ")
	fmt.Println(string(bs))
}

func TestHash(t *testing.T) {
	onehash := common.BigToHash(big.NewInt(1))
	onebytes32 := onehash.Bytes()
	h1 := crypto.Keccak256(onebytes32)
	//b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6  ?
	fmt.Printf("%0x\n", h1)
	//a616d7aef03e4b282939c2ad9067aff27a705571d1cb3544b9012c224103275c ?
	mapone := append(common.HexToHash("0x59677fD68ec54e43aD4319D915f81748B5a6Ff8B").Bytes(), common.BigToHash(big.NewInt(2)).Bytes()...)
	h2 := crypto.Keccak256(mapone)
	fmt.Printf("%0x\n", h2)

}

func TestDecodePrealloc(t *testing.T) {
	data := "\xf9\b\xfd\xf9\b\u05543\u007f\xe3\x1d\x8f\x1b\x12\xf5>\x9e\x9eS\xda\xc2\nu\n\xbde\x94\x80\xf9\x01\x10\xf8B\xa0\xb1\x0e-Rv\x12\a;&\xee\xcd\xfdq~j2\f\xf4KJ\xfa\u00b0s-\x9f\xcb\xe2\xb7\xfa\f\xf6\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x94Yg\u007f\u058e\xc5NC\xadC\x19\xd9\x15\xf8\x17H\xb5\xa6\xff\x8b\xf8B\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xf8B\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xf8B\xa0\xa6\x16\u05ee\xf0>K()9\u00ad\x90g\xaf\xf2zpUq\xd1\xcb5D\xb9\x01,\"A\x03'\\\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xb9\a\xa9`\x80`@R`\x046\x10a\x00PW`\x005`\xe0\x1cc\xff\xff\xff\xff\x16\x80c\x10-QC\x14a\x00UW\x80c/\xc8r\xcd\x14a\x00\xbaW\x80c`\u053c\x81\x14a\x00\xddW\x80cd\xe9\xee\t\x14a\x00\xfeW\x80c\xd0d\xd3\xf4\x14a\x01%W[`\x00\x80\xfd[4\x80\x15a\x00aW`\x00\x80\xfd[Pa\x00ja\x01=V[`@\x80Q` \x80\x82R\x83Q\x81\x83\x01R\x83Q\x91\x92\x83\x92\x90\x83\x01\x91\x85\x81\x01\x91\x02\x80\x83\x83`\x00[\x83\x81\x10\x15a\x00\xa6W\x81\x81\x01Q\x83\x82\x01R` \x01a\x00\x8eV[PPPP\x90P\x01\x92PPP`@Q\x80\x91\x03\x90\xf3[4\x80\x15a\x00\xc6W`\x00\x80\xfd[Pa\x00\xdb`\x01`\xa0`\x02\n\x03`\x045\x16a\x02uV[\x00[4\x80\x15a\x00\xe9W`\x00\x80\xfd[Pa\x00\xdb`\x01`\xa0`\x02\n\x03`\x045\x16a\x03vV[4\x80\x15a\x01\nW`\x00\x80\xfd[Pa\x01\x13a\x04wV[`@\x80Q\x91\x82RQ\x90\x81\x90\x03` \x01\x90\xf3[4\x80\x15a\x011W`\x00\x80\xfd[Pa\x00\xdb`\x045a\x04}V[3`\x00\x90\x81R`\x02` R`@\x81 T``\x91\x90\x82\x90\x82\x90\x81\x90\x81\x10a\x01\x9bW`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\f`$\x82\x01R`\x00\x80Q` a\a^\x839\x81Q\x91R`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[`\x03T`\x01T`@\x80Q\x92\x90\x91\x03\x80\x83R` \x80\x82\x02\x84\x01\x01\x90\x91R\x94P\x84\x80\x15a\x01\xd0W\x81` \x01` \x82\x02\x808\x839\x01\x90P[P\x92P`\x00\x91P`\x00\x90P[`\x01T\x81\x10\x15a\x02lW`\x01\x80T`\x00\x91\x90\x83\x90\x81\x10a\x01\xf8W\xfe[`\x00\x91\x82R` \x90\x91 \x01T`\x01`\xa0`\x02\n\x03\x16\x14a\x02dW`\x01\x80T\x82\x90\x81\x10a\x02 W\xfe[`\x00\x91\x82R` \x90\x91 \x01T\x83Q`\x01`\xa0`\x02\n\x03\x90\x91\x16\x90\x84\x90\x84\x90\x81\x10a\x02FW\xfe[`\x01`\xa0`\x02\n\x03\x90\x92\x16` \x92\x83\x02\x90\x91\x01\x90\x91\x01R`\x01\x90\x91\x01\x90[`\x01\x01a\x01\xdcV[P\x90\x93\x92PPPV[3`\x00\x90\x81R`\x02` R`@\x81 T\x11a\x02\xc8W`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\f`$\x82\x01R`\x00\x80Q` a\a^\x839\x81Q\x91R`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[`\x01`\xa0`\x02\n\x03\x81\x16`\x00\x90\x81R`\x02` R`@\x90 T\x15a\x036W`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\x17`$\x82\x01R\u007fIt is already a manager\x00\x00\x00\x00\x00\x00\x00\x00\x00`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[a\x03?\x81a\x05hV[`@Q`\x01`\xa0`\x02\n\x03\x82\x16\x90\u007f\a\x1c\x1dl4\xc35y\xb7\xc6\x02\xd1B\a\\\xbf\xcdx\xa1\xf1zf\xd7\x04\xfa\x95(D\xa3\xc5\xe0\x8e\x90`\x00\x90\xa2PV[3`\x00\x90\x81R`\x02` R`@\x81 T\x11a\x03\xc9W`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\f`$\x82\x01R`\x00\x80Q` a\a^\x839\x81Q\x91R`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[`\x01`\xa0`\x02\n\x03\x81\x16`\x00\x90\x81R`\x02` R`@\x81 T\x11a\x047W`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\x13`$\x82\x01R\u007fIt is not a manager\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[a\x04@\x81a\x06wV[`@Q`\x01`\xa0`\x02\n\x03\x82\x16\x90\u007f\xb6\bl\xa7d\xb0)l\x94!\ud34e?06\xc6\xd5\xe2\xcb\u007f\x94\xc1X\u00cd\v\xe2\xa1l\x8bN\x90`\x00\x90\xa2PV[`\x00T\x81V[`\x00\x81\x81\x81\x11a\x04\xd7W`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\x16`$\x82\x01R\u007fmust be greater then 0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[3`\x00\x90\x81R`\x02` R`@\x81 T\x11a\x05*W`@\x80Q`\xe5`\x02\nbF\x1b\xcd\x02\x81R` `\x04\x82\x01R`\f`$\x82\x01R`\x00\x80Q` a\a^\x839\x81Q\x91R`D\x82\x01R\x90Q\x90\x81\x90\x03`d\x01\x90\xfd[`\x00\x80T\x84\x82U`@Q`\x80\x91\x90\x91\x1b\x93P\x84\x84\x01\x91\u007f<j$\xb9H A\xa6\x05\x17h\xaa\xb5T\x80\x01\xa1\xdbdIyT.\xbc\x8e\t\xaa\x044\xb3\xc3\x10\x91\xa2PPPV[`\x03T`\x00\x80\x82\x15\x15a\x05\xe3W`\x01\x80T\x80\x82\x01\x91\x82\x90U\u007f\xb1\x0e-Rv\x12\a;&\xee\xcd\xfdq~j2\f\xf4KJ\xfa\u00b0s-\x9f\xcb\xe2\xb7\xfa\f\xf6\x01\x80Ts\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x19\x16`\x01`\xa0`\x02\n\x03\x87\x16\x90\x81\x17\x90\x91U`\x00\x90\x81R`\x02` R`@\x90 \x81\x90U\x91Pa\x06qV[`\x03\x80T`\x00\x19\x85\x01\x90\x81\x10a\x05\xf5W\xfe[`\x00\x91\x82R` \x90\x91 \x01T`\x03\x80T\x91\x92Pa\x06\x16\x90`\x00\x19\x83\x01a\a\x13V[P\x83`\x01\x82\x81T\x81\x10\x15\x15a\x06'W\xfe[`\x00\x91\x82R` \x80\x83 \x91\x90\x91\x01\x80Ts\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x19\x16`\x01`\xa0`\x02\n\x03\x94\x85\x16\x17\x90U\x91\x86\x16\x81R`\x02\x90\x91R`@\x90 `\x01\x82\x01\x90U[PPPPV[`\x01`\xa0`\x02\n\x03\x81\x16`\x00\x90\x81R`\x02` R`@\x81 \x80T\x90\x82\x90U`\x01\x80T`\x00\x19\x90\x92\x01\x92\x91\x83\x90\x81\x10a\x06\xabW\xfe[`\x00\x91\x82R` \x82 \x01\x80Ts\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x19\x16`\x01`\xa0`\x02\n\x03\x93\x90\x93\x16\x92\x90\x92\x17\x90\x91U`\x03\x80T`\x01\x81\x01\x82U\x91R\u007f\xc2WZ\x0e\x9eY<\x00\xf9Y\xf8\xc9/\x12\xdb(i\xc39Z;\x05\x02\xd0^%\x16Doq\xf8[\x01UPV[\x81T\x81\x83U\x81\x81\x11\x15a\a7W`\x00\x83\x81R` \x90 a\a7\x91\x81\x01\x90\x83\x01a\a<V[PPPV[a\aZ\x91\x90[\x80\x82\x11\x15a\aVW`\x00\x81U`\x01\x01a\aBV[P\x90V[\x90V\x00manager only\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1ebzzr0X n\xf4\x05\xe1\x18\xee\x16\xb6g\xde\xc1\xa0\xb3S>\xa3\v\x06\xa6\xa5\x96aT\u0612mC\xc39\xec\xe0\u007f\x00)\xe4\x94Yg\u007f\u058e\xc5NC\xadC\x19\xd9\x15\xf8\x17H\xb5\xa6\xff\x8b\x8c\n\x04B\x88\xbc9\x8d\x89\x9c\x00\x00\x00\xc0\x80"

	ga := decodePrealloc(data)
	require.Equal(t, 2, len(ga))
	contractAddr := common.HexToAddress("337fe31d8f1b12f53e9e9e53dac20a750abd6594")
	c := ga[contractAddr]
	require.NotNil(t, c)
	first := c.Storage[common.Hash{}]
	require.EqualValues(t, common.BytesToHash([]byte{0x1}), first)
}

func TestDefaultGenesisBlock(t *testing.T) {
	g := DefaultGenesisBlock()
	require.NotNil(t, g)
	require.Greater(t, len(g.Validators), 0)
	db := youdb.NewMemDatabase()
	b := g.ToBlock(db)
	gh := common.HexToHash("0xce0efc6c8bd2195b53bf9cce7e7fff3bfc8aeba19b1f314ab029da68a521acf6")
	if b.Hash() != gh {
		t.Fatal("DefaultGenesisBlock hash mismatch")
	}
}
