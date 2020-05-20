// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// This file is part of the go-youchain library.
//
// The go-youchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-youchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.

package staking

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/rlp"
)

func int32ToBytes(i uint32) []byte {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return buf
}

func Sign(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hashData := crypto.Keccak256([]byte(data))
	return crypto.Sign(hashData, key)
}

func TestEvidencesPubSub(t *testing.T) {
	mux := new(event.TypeMux)
	sub := mux.Subscribe(Evidence{})
	log.Info("mux subscribe", "sub", sub)

	quit := make(chan struct{}, 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-quit:
				return
			case ev := <-sub.Chan():
				log.Info("receive evidenct", ev.Data)
				evidence := ev.Data.(Evidence)
				switch evidence.Type {
				default:
					log.Warn("ignored unknown evidence type", "type", evidence.Type)

				case EvidenceTypeDoubleSign:
					var doubleSign EvidenceDoubleSign
					if err := rlp.DecodeBytes(evidence.Data, &doubleSign); err != nil {
						continue
					}
					log.Info("double sign", "round", doubleSign.Round, "roundIndex", doubleSign.RoundIndex)
					quit <- struct{}{}
				}
			}
		}
	}()

	rawSk, _ := crypto.GenerateKey()
	round := big.NewInt(100)
	roundIndex := uint32(1000)
	hash0 := common.BigToHash(big.NewInt(1))
	hash1 := common.BigToHash(big.NewInt(2))
	payload0 := append(hash0.Bytes(), append(round.Bytes(), int32ToBytes(roundIndex)...)...) ////append(blockHash.Bytes(), int32ToBytes(vote.Votes)...)
	payload1 := append(hash1.Bytes(), append(round.Bytes(), int32ToBytes(roundIndex)...)...) ////append(blockHash.Bytes(), int32ToBytes(vote.Votes)...)

	signature0, err := Sign(rawSk, payload0)
	assert.NoError(t, err)
	signature1, err := Sign(rawSk, payload1)
	assert.NoError(t, err)

	log.Info("start post")
	err = mux.Post(NewEvidence(EvidenceDoubleSign{
		Round:      round,
		RoundIndex: roundIndex,
		Signs: map[common.Hash][]byte{
			common.BigToHash(big.NewInt(1)): signature0,
			common.BigToHash(big.NewInt(2)): signature1,
		},
	}))
	assert.NoError(t, err)

	wg.Wait()
	sub.Unsubscribe()
}

func TestEventDoubleSign(t *testing.T) {
	e := EvidenceDoubleSign{
		Round:      big.NewInt(1024),
		RoundIndex: 128,
		Signs:      map[common.Hash][]byte{},
	}
	hash1 := common.BigToHash(big.NewInt(100))
	hash2 := common.BigToHash(big.NewInt(101))
	e.Signs[hash1] = hash1.Bytes()
	e.Signs[hash2] = hash2.Bytes()

	ebs, err := rlp.EncodeToBytes(e)
	assert.NoError(t, err)

	fmt.Println(hexutil.Encode(ebs))

	e2 := EvidenceDoubleSign{}
	err = rlp.DecodeBytes(ebs, &e2)
	assert.NoError(t, err)

	assert.Equal(t, e.Round.Uint64(), e2.Round.Uint64())
	assert.Equal(t, e.RoundIndex, e2.RoundIndex)
	assert.Equal(t, 2, len(e2.Signs))
	for e := range e2.Signs {
		fmt.Println("hash", e.String(), "sign", hexutil.Bytes(e2.Signs[e]).String())
	}
}

func TestEvidenceEncode(t *testing.T) {
	e := EvidenceDoubleSign{
		Round:      big.NewInt(1024),
		RoundIndex: 128,
		Signs:      map[common.Hash][]byte{},
	}
	hash1 := common.BigToHash(big.NewInt(100))
	hash2 := common.BigToHash(big.NewInt(101))
	e.Signs[hash1] = hash1.Bytes()
	e.Signs[hash2] = hash2.Bytes()

	var applyEvidences []Evidence
	applyEvidences = append(applyEvidences, NewEvidence(e))
	applyEvidences = append(applyEvidences, NewEvidence(e))
	applyEvidences = append(applyEvidences, NewEvidence(e))

	bs, err := rlp.EncodeToBytes(applyEvidences)
	assert.NoError(t, err)
	fmt.Println("bs", hexutil.Encode(bs))

	var ls []Evidence
	err = rlp.DecodeBytes(bs, &ls)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(ls))
	fmt.Println(ls[0].Type)
	var ls0 EvidenceDoubleSign
	err = rlp.DecodeBytes(ls[0].Data, &ls0)
	assert.NoError(t, err)
	fmt.Println(ls0.Round)
}

func TestEvidenceInactive(t *testing.T) {
	e := EvidenceInactive{
		Round: 100,
	}
	e.Validators = []common.Address{
		common.BigToAddress(big.NewInt(1)),
		common.BigToAddress(big.NewInt(2)),
		common.BigToAddress(big.NewInt(3)),
	}

	bs, err := rlp.EncodeToBytes(e)
	assert.NoError(t, err)

	var x EvidenceInactive
	err = rlp.DecodeBytes(bs, &x)
	assert.NoError(t, err)
	assert.Equal(t, x.Round, e.Round)
	assert.Equal(t, 3, len(x.Validators))
	for k, v := range x.Validators {
		fmt.Println("k", k, "v", v.String())
	}
}

func TestEvidencesDecode(t *testing.T) {
	input := `0xf891f88f88696e616374697665b884f8828181f87e940f63534d9816f7324267fc853b3b0ac7a70221969447fcf5c421ef8e5d14b43b6a127c82f285292c83945a2e9c176f57c5d37bb1d6864f3662dca6e699d394843a9b823cdfb2b6d82cf59b90a7c13885c2ff9794a716bbbde530e58c4b400ce63320970714aaa89a94ccc6936e6fcbedf2db1becf46399e0e153dd189c`
	var evidences []Evidence
	data, err := hexutil.Decode(input)
	assert.NoError(t, err)
	fmt.Println("input", input)
	fmt.Println("data", data)
	assert.Equal(t, input, hexutil.Encode(data))

	err = rlp.DecodeBytes(data, &evidences)
	assert.NoError(t, err)
	t.Log("evidences", "count", len(evidences))
	for _, v := range evidences {
		if v.Type == EvidenceTypeInactive {
			var ina EvidenceInactive
			err := rlp.DecodeBytes(v.Data, &ina)
			assert.NoError(t, err)
			t.Log("evidence", "round", ina.Round, "count", len(ina.Validators))
			for _, vv := range ina.Validators {
				t.Log("inactive validator", "addr", vv.String())
			}

		}
	}

}
