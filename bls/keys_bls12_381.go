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

package bls

import (
	"errors"
	"github.com/youchainhq/bls/g2pubs"
)

var ErrSigMismatch = errors.New("signature mismatch")
var ErrInvalidSig = errors.New("invalid signature")

type secret struct {
	sk *g2pubs.SecretKey
}

type public struct {
	pk *g2pubs.PublicKey
}

type signature struct {
	sig *g2pubs.Signature
	cb  *CompressedSignature //for optimization reason
}

func (s *secret) Sign(m Message) Signature {
	sig := g2pubs.Sign(m, s.sk)
	return &signature{sig: sig}
}

// PubKey returns the corresponding public key.
func (s *secret) PubKey() (PublicKey, error) {
	pk := g2pubs.PrivToPub(s.sk)
	return &public{pk: pk}, nil
}

// Compress compresses the secret key to a byte slice.
func (s *secret) Compress() CompressedSecret {
	return s.sk.Serialize()
}

// Verify verifies a signature against a message and the public key.
func (p *public) Verify(m Message, sig Signature) error {
	osig, ok := sig.(*signature)
	if !ok {
		return ErrInvalidSig
	}
	if ok := g2pubs.Verify(m, p.pk, osig.sig); ok {
		return nil
	}
	return ErrSigMismatch
}

// Aggregate adds an other public key to the current.
func (p *public) Aggregate(other PublicKey) error {
	op, ok := other.(*public)
	if ok {
		p.pk.Aggregate(op.pk)
		return nil
	} else {
		return errors.New("invalid public key")
	}
}

// Compress compresses the public key to a byte slice.
func (p *public) Compress() CompressedPublic {
	return p.pk.Serialize()
}

// Aggregate adds an other signature to the current.
//func (s *signature) Aggregate(other Signature) error {
//	osig, ok := other.(*signature)
//	if ok {
//		s.sig.Aggregate(osig.sig)
//		s.cb = nil
//		return nil
//	}
//	return ErrInvalidSig
//}

// Compress compresses the signature to a byte slice.
func (s *signature) Compress() CompressedSignature {
	if s.cb == nil {
		cb := CompressedSignature(s.sig.Serialize())
		s.cb = &cb
	}
	var copyBytes CompressedSignature
	copy(copyBytes[:], s.cb[:])
	return copyBytes
}

// serialize just for compare with Compress
func (s *signature) serialize() CompressedSignature {
	return s.sig.Serialize()
}
