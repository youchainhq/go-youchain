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

package keystore

import (
	"crypto/ecdsa"
	"github.com/pborman/uuid"
	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"math/big"
)

const (
	version = 3
)

type Key struct {
	Id      uuid.UUID // Version 4 "random" for unique id not derived from key data
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
	// for validator, also store the bls key in case of enable bls signature
	BlsKey []byte
}

func (k *Key) Clone() *Key {
	nid := uuid.UUID{}
	copy(nid[:], k.Id[:])
	addr := common.Address{}
	copy(addr[:], k.Address[:])
	sk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: crypto.S256(),
			X:     new(big.Int).Set(k.PrivateKey.PublicKey.X),
			Y:     new(big.Int).Set(k.PrivateKey.PublicKey.Y),
		},
		D: new(big.Int).Set(k.PrivateKey.D),
	}
	blsSk := bls.CompressedSecret{}
	copy(blsSk[:], k.BlsKey)
	return &Key{
		Id:         nid,
		Address:    addr,
		PrivateKey: sk,
		BlsKey:     blsSk.Bytes(),
	}
}

func (k *Key) IsValKey() bool {
	if k != nil && len(k.BlsKey) == bls.SecretKeyBytes {
		return true
	}
	return false
}
