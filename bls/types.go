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
	"fmt"
)

const (
	// SignatureBytes is the length of a BLS signature
	SignatureBytes = 48
	// SecretKeyBytes is the length of a BLS private key
	SecretKeyBytes = 32
	// PublicKeyBytes is the length of a BLS public key
	PublicKeyBytes = 96
)

var ErrBytesLen = errors.New("invalid length of the compressed byte slice")

// CompressedSignature is a compressed affine
type CompressedSignature [SignatureBytes]byte

// CompressedSecret is a compressed affine representing a SecretKey
type CompressedSecret [SecretKeyBytes]byte

// CompressedPublic is a compressed affine representing a PublicKey
type CompressedPublic [PublicKeyBytes]byte

// Message is a byte slice
type Message []byte

type SecretKey interface {
	// Sign returns the BLS signature of the giving message.
	Sign(m Message) Signature
	// PubKey returns the corresponding public key.
	PubKey() (PublicKey, error)
	// Compress compresses the secret key to a byte slice.
	Compress() CompressedSecret
}

type PublicKey interface {
	// Verify verifies a signature against a message and the public key.
	Verify(m Message, sig Signature) error
	// Aggregate adds an other public key to the current.
	Aggregate(other PublicKey) error
	// Compress compresses the public key to a byte slice.
	Compress() CompressedPublic
}

type Signature interface {
	// Compress compresses the signature to a byte slice.
	Compress() CompressedSignature
}

type BlsManager interface {
	// GenerateKey generates a fresh key-pair for BLS signatures.
	GenerateKey() (SecretKey, PublicKey)
	//Aggregate aggregates signatures together into a new signature.
	Aggregate([]Signature) (Signature, error)
	//AggregatePublic aggregates public keys together into a new PublicKey.
	AggregatePublic([]PublicKey) (PublicKey, error)
	// VerifyAggregatedOne verifies each public key against a message.
	VerifyAggregatedOne([]PublicKey, Message, Signature) error
	// VerifyAggregatedN verifies each public key against each message.
	VerifyAggregatedN([]PublicKey, []Message, Signature) error
	//DecPublicKey decompress a public key
	DecPublicKey([]byte) (PublicKey, error)
	//DecPublicKeyHex decompress a public key from a hex string
	DecPublicKeyHex(string) (PublicKey, error)
	//DecSecretKey decompress a secret key
	DecSecretKey([]byte) (SecretKey, error)
	//DecSecretKeyHex decompress a secret key from a hex string
	DecSecretKeyHex(string) (SecretKey, error)
	//DecSignature decompress a signature
	DecSignature([]byte) (Signature, error)
	//DecSignatureHex decompress a signature from a hex string
	DecSignatureHex(string) (Signature, error)
}

func (b CompressedPublic) String() string {
	return fmt.Sprintf("%0x", b[:])
}

func (b CompressedSecret) String() string {
	return fmt.Sprintf("%0x", b[:])
}

func (b CompressedSignature) String() string {
	return fmt.Sprintf("%0x", b[:])
}

func (b CompressedPublic) Bytes() []byte {
	return b[:]
}

func (b CompressedSecret) Bytes() []byte {
	return b[:]
}

func (b CompressedSignature) Bytes() []byte {
	return b[:]
}
