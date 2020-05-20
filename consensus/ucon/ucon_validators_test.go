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

package ucon

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	secp256k1VRF "github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"

	"github.com/stretchr/testify/assert"
)

func TestNewUconValidators(t *testing.T) {
	votesInfo := VotesInfoForBlockHash{}
	print := true
	for i := 1; i < 101; i++ {
		sk, _ := crypto.GenerateKey()
		vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
		payload := []byte{00001}
		signature, _ := Sign(sk, payload)
		addr, _ := GetSignatureAddress(payload, signature)
		_, proof, _ := VrfSortition(vrfSk, seed, index, role, threshold, stake, totalStake)

		vote := &SingleVote{
			Votes:     uint32(i),
			Signature: signature,
			Proof:     proof,
		}
		votesInfo[addr] = vote
		if print {
			t.Logf("proof len %d signature len %d", len(proof), len(signature))
			print = false
		}
	}
	uc := NewUconValidators(CommitEvent{
		RoundIndex:        uint32(2),
		ChamberPrecommits: votesInfo,
		HousePrecommits:   votesInfo,
		ChamberCerts:      votesInfo,
	}, params.LookBackStake)
	//logging.Info("uc", "len", len(uc.ChamberValidators))

	data, err := uc.ValidatorsToByte()
	if err != nil {
		logging.Error("ValidatorsToByte", "err", err)
		return
	}

	h := &types.Header{
		Validator: data,
	}
	uc2, err := ExtractUconValidators(h, params.LookBackStake)
	if err != nil {
		logging.Error("ExtractUconValidators", "err", err)
		return
	}

	if uc2.RoundIndex != uc.RoundIndex {
		logging.Error("not the same 1")
		return
	}

	//if len(uc2.ChamberValidators) != len(uc.ChamberValidators) {
	//	logging.Error("not the same 2")
	//	return
	//}

	if len(uc2.ChamberCommitters) != len(uc.ChamberCommitters) {
		logging.Error("not the same 3")
		return
	}

	//h2 := UconFilteredHeader(h)
	//log.Info("header 2", len(h2.Validator))
}

func TestVoteBLSMgr_PackVotes(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	voterMgr := NewVoteBLSMgr(sk, nil)
	votesInfo := VotesInfoForBlockHash{}
	payload := []byte{00001}
	print := true
	for i := 1; i < 101; i++ {
		sk, _ := crypto.GenerateKey()
		vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
		_, proof, _ := VrfSortition(vrfSk, seed, index, role, threshold, stake, totalStake)

		blssk, _ := voterMgr.blsMgr.GenerateKey()
		signature := blssk.Sign(payload)
		vote := &SingleVote{
			Votes:     uint32(i),
			Signature: signature.Compress().Bytes(),
			Proof:     proof,
		}
		addr := crypto.PubkeyToAddress(sk.PublicKey)
		votesInfo[addr] = vote
		if print {
			t.Logf("proof len: %d ", len(proof))
		}
	}

	uc, err := voterMgr.Verifier.PackVotes(CommitEvent{
		RoundIndex:        uint32(2),
		ChamberPrecommits: votesInfo,
		HousePrecommits:   votesInfo,
	}, params.LookBackPos)
	if err != nil {
		t.Error(err)
	}
	data, err := uc.ValidatorsToByte()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("bls packed header len: %d", len(data))
}

func BenchmarkNewUconValidators(b *testing.B) {
	votesInfo := VotesInfoForBlockHash{}
	for i := 1; i < 101; i++ {
		sk, _ := crypto.GenerateKey()
		vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
		payload := []byte{00001}
		signature, _ := Sign(sk, payload)
		addr, _ := GetSignatureAddress(payload, signature)
		_, proof, _ := VrfSortition(vrfSk, seed, index, role, threshold, stake, totalStake)

		vote := &SingleVote{
			Votes:     uint32(i),
			Signature: signature,
			Proof:     proof,
		}
		votesInfo[addr] = vote
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewUconValidators(CommitEvent{
			RoundIndex:        uint32(2),
			ChamberPrecommits: votesInfo,
			HousePrecommits:   votesInfo,
			ChamberCerts:      votesInfo,
		}, params.LookBackStake)
	}
}

func TestExtractUconValidators(t *testing.T) {
	type a struct {
		data string
		hash string
	}
	list := []a{
		{
			data: `0xf9033701f90330f8ca8082018ab841881ddf1c75d36908a8de6fdf1a3e335cb8e12faf22c6fadccc41b175dd123caa69e21cdd1ebff1ec0393fef48eea90629c02e1857115e938abdcfa03c469cd7901b881ca9b421e200b306858ffc7d63464180e938893f6b21f1c3fd7141cf38420ba3b5b8cd40b9ad0594b45f021b429c1ecb7ed68e709224fa12c9dec1389da5d0bb004857a53c07ca6e4dd816b8c0d0af7c42e76d0c68c1c4318a309b5ec4fed336b7c509c690948f5c9cde9ca52d2d0506563468158e668736118cd71746b362e0a08f8ca80820192b8418f6a04fd5f0fe3697dc9d671fe9248f801d146bb498c1c3d24bc74a7101b05c2769702b72387be8ad5e556cf8535ccd2a1460113cc6f2efa2b5746ac24d00eb800b881767c4bbb4e73349cab5a450445a6631ad4aa92a0c7dedc9ff6bf8e1f09e2f626c1c2aa9769c3d77db38fcb24eb3d7c7073c9d70813c16a52ba93183afe619304049251265d34fbe11717eca8f9b06c14118ba5483fbd90c51095d5ef146b6e74368d4afd3c7bdf1783468ce67b3dda2f8721cb6cc8362416faa920e143e3f5f6dff8ca808201abb8416befe2cc88f63cce1f0d9540c8faf3b388eeaa40e1dd2faea58be8c6a0e772884b235466417931d40d9232fe900419de0ab60f5693031f02f8215194ca816bcf01b88130741577f03f8e349c8ab8320a433d3341160f7b5bf25a649c3cff49209af1107bae952b81471ca7442ce509ec7df3ee01057fdcc8381393d2e94373bd287199045c4abbacc8caaec1b99c660d1f2b5d2d3a510016c16c6f73058373a7d11f32672939656e9684dc67e8ea0e436a15b5fbc6ac01ae82311fd30804f9828e52616df8ca80820198b841c1e8a821e64f7c073ec8aaa3c504c77206fbb5a2c0354322bb2cb1cd9a452a636b0234e738f57d4cccb388e40447e5574a9afdb0479af0b1605739e05d50d63401b881cfc9164ff7686ecb7c5fdaae81a52f3e5e578331bf6ca84478ebe98640da70ba54b94ca4c17d0db3199d64ada86c82b16d4f18dd0285783b93572b2188380fab048d2a0ed916c43fcd875f720b3575cc05c3e519e85201862044cb20d0c6823a4722ffcb2e4ea074dbe74062f74b8477c1e924545f9fe021f5fd1efc3e1231fb07c08080`,
			hash: `0xd2ce921172b535b8f46b7c9cfa03b039c3f438eca66b6a7465a36b8acc596952`,
		},
		{
			data: `0xf9033701f90330f8ca80820198b841c1e8a821e64f7c073ec8aaa3c504c77206fbb5a2c0354322bb2cb1cd9a452a636b0234e738f57d4cccb388e40447e5574a9afdb0479af0b1605739e05d50d63401b881cfc9164ff7686ecb7c5fdaae81a52f3e5e578331bf6ca84478ebe98640da70ba54b94ca4c17d0db3199d64ada86c82b16d4f18dd0285783b93572b2188380fab048d2a0ed916c43fcd875f720b3575cc05c3e519e85201862044cb20d0c6823a4722ffcb2e4ea074dbe74062f74b8477c1e924545f9fe021f5fd1efc3e1231fb07f8ca80820192b8418f6a04fd5f0fe3697dc9d671fe9248f801d146bb498c1c3d24bc74a7101b05c2769702b72387be8ad5e556cf8535ccd2a1460113cc6f2efa2b5746ac24d00eb800b881767c4bbb4e73349cab5a450445a6631ad4aa92a0c7dedc9ff6bf8e1f09e2f626c1c2aa9769c3d77db38fcb24eb3d7c7073c9d70813c16a52ba93183afe619304049251265d34fbe11717eca8f9b06c14118ba5483fbd90c51095d5ef146b6e74368d4afd3c7bdf1783468ce67b3dda2f8721cb6cc8362416faa920e143e3f5f6dff8ca8082018ab841881ddf1c75d36908a8de6fdf1a3e335cb8e12faf22c6fadccc41b175dd123caa69e21cdd1ebff1ec0393fef48eea90629c02e1857115e938abdcfa03c469cd7901b881ca9b421e200b306858ffc7d63464180e938893f6b21f1c3fd7141cf38420ba3b5b8cd40b9ad0594b45f021b429c1ecb7ed68e709224fa12c9dec1389da5d0bb004857a53c07ca6e4dd816b8c0d0af7c42e76d0c68c1c4318a309b5ec4fed336b7c509c690948f5c9cde9ca52d2d0506563468158e668736118cd71746b362e0a08f8ca808201abb8416befe2cc88f63cce1f0d9540c8faf3b388eeaa40e1dd2faea58be8c6a0e772884b235466417931d40d9232fe900419de0ab60f5693031f02f8215194ca816bcf01b88130741577f03f8e349c8ab8320a433d3341160f7b5bf25a649c3cff49209af1107bae952b81471ca7442ce509ec7df3ee01057fdcc8381393d2e94373bd287199045c4abbacc8caaec1b99c660d1f2b5d2d3a510016c16c6f73058373a7d11f32672939656e9684dc67e8ea0e436a15b5fbc6ac01ae82311fd30804f9828e52616dc08080`,
			hash: `0xd2ce921172b535b8f46b7c9cfa03b039c3f438eca66b6a7465a36b8acc596952`,
		},
		{
			data: `0xf9033701f90330f8ca80820192b8418f6a04fd5f0fe3697dc9d671fe9248f801d146bb498c1c3d24bc74a7101b05c2769702b72387be8ad5e556cf8535ccd2a1460113cc6f2efa2b5746ac24d00eb800b881767c4bbb4e73349cab5a450445a6631ad4aa92a0c7dedc9ff6bf8e1f09e2f626c1c2aa9769c3d77db38fcb24eb3d7c7073c9d70813c16a52ba93183afe619304049251265d34fbe11717eca8f9b06c14118ba5483fbd90c51095d5ef146b6e74368d4afd3c7bdf1783468ce67b3dda2f8721cb6cc8362416faa920e143e3f5f6dff8ca8082018fb84129c510417a9087a637f56d4e659f18f9f2838d257ca159b95812c25579ff5a004b2ae0fab5cd2f096e123afe9f3b239313fe44222cc3d0c2231df03442f2b67e01b8819456eac1ee6853e4bd61ecbaf6cf4908b0c77081de4fd6a1a4ab58d17259e22ec458b494e906ba2026cc7de2d7b9f0e40cc67575a957f4ca02752f63c9343ea104067432706f0ba1ca59bce018c4f8e5a6f64770c2d9c25df8cbad4ee2c8a28d6311d8c6e2b121ac35915cad35c78e356c07c53c75ba56c3ec8d6539453f03855df8ca808201abb8416befe2cc88f63cce1f0d9540c8faf3b388eeaa40e1dd2faea58be8c6a0e772884b235466417931d40d9232fe900419de0ab60f5693031f02f8215194ca816bcf01b88130741577f03f8e349c8ab8320a433d3341160f7b5bf25a649c3cff49209af1107bae952b81471ca7442ce509ec7df3ee01057fdcc8381393d2e94373bd287199045c4abbacc8caaec1b99c660d1f2b5d2d3a510016c16c6f73058373a7d11f32672939656e9684dc67e8ea0e436a15b5fbc6ac01ae82311fd30804f9828e52616df8ca8082018ab841881ddf1c75d36908a8de6fdf1a3e335cb8e12faf22c6fadccc41b175dd123caa69e21cdd1ebff1ec0393fef48eea90629c02e1857115e938abdcfa03c469cd7901b881ca9b421e200b306858ffc7d63464180e938893f6b21f1c3fd7141cf38420ba3b5b8cd40b9ad0594b45f021b429c1ecb7ed68e709224fa12c9dec1389da5d0bb004857a53c07ca6e4dd816b8c0d0af7c42e76d0c68c1c4318a309b5ec4fed336b7c509c690948f5c9cde9ca52d2d0506563468158e668736118cd71746b362e0a08c08080`,
			hash: `0xd2ce921172b535b8f46b7c9cfa03b039c3f438eca66b6a7465a36b8acc596952`,
		},
		{
			data: `0xf9033701f90330f8ca8082018ab841881ddf1c75d36908a8de6fdf1a3e335cb8e12faf22c6fadccc41b175dd123caa69e21cdd1ebff1ec0393fef48eea90629c02e1857115e938abdcfa03c469cd7901b881ca9b421e200b306858ffc7d63464180e938893f6b21f1c3fd7141cf38420ba3b5b8cd40b9ad0594b45f021b429c1ecb7ed68e709224fa12c9dec1389da5d0bb004857a53c07ca6e4dd816b8c0d0af7c42e76d0c68c1c4318a309b5ec4fed336b7c509c690948f5c9cde9ca52d2d0506563468158e668736118cd71746b362e0a08f8ca80820192b8418f6a04fd5f0fe3697dc9d671fe9248f801d146bb498c1c3d24bc74a7101b05c2769702b72387be8ad5e556cf8535ccd2a1460113cc6f2efa2b5746ac24d00eb800b881767c4bbb4e73349cab5a450445a6631ad4aa92a0c7dedc9ff6bf8e1f09e2f626c1c2aa9769c3d77db38fcb24eb3d7c7073c9d70813c16a52ba93183afe619304049251265d34fbe11717eca8f9b06c14118ba5483fbd90c51095d5ef146b6e74368d4afd3c7bdf1783468ce67b3dda2f8721cb6cc8362416faa920e143e3f5f6dff8ca808201abb8416befe2cc88f63cce1f0d9540c8faf3b388eeaa40e1dd2faea58be8c6a0e772884b235466417931d40d9232fe900419de0ab60f5693031f02f8215194ca816bcf01b88130741577f03f8e349c8ab8320a433d3341160f7b5bf25a649c3cff49209af1107bae952b81471ca7442ce509ec7df3ee01057fdcc8381393d2e94373bd287199045c4abbacc8caaec1b99c660d1f2b5d2d3a510016c16c6f73058373a7d11f32672939656e9684dc67e8ea0e436a15b5fbc6ac01ae82311fd30804f9828e52616df8ca80820198b841c1e8a821e64f7c073ec8aaa3c504c77206fbb5a2c0354322bb2cb1cd9a452a636b0234e738f57d4cccb388e40447e5574a9afdb0479af0b1605739e05d50d63401b881cfc9164ff7686ecb7c5fdaae81a52f3e5e578331bf6ca84478ebe98640da70ba54b94ca4c17d0db3199d64ada86c82b16d4f18dd0285783b93572b2188380fab048d2a0ed916c43fcd875f720b3575cc05c3e519e85201862044cb20d0c6823a4722ffcb2e4ea074dbe74062f74b8477c1e924545f9fe021f5fd1efc3e1231fb07c08080`,
			hash: `0xd2ce921172b535b8f46b7c9cfa03b039c3f438eca66b6a7465a36b8acc596952`,
		},
		{
			data: `0xf9033701f90330f8ca8082018ab841881ddf1c75d36908a8de6fdf1a3e335cb8e12faf22c6fadccc41b175dd123caa69e21cdd1ebff1ec0393fef48eea90629c02e1857115e938abdcfa03c469cd7901b881ca9b421e200b306858ffc7d63464180e938893f6b21f1c3fd7141cf38420ba3b5b8cd40b9ad0594b45f021b429c1ecb7ed68e709224fa12c9dec1389da5d0bb004857a53c07ca6e4dd816b8c0d0af7c42e76d0c68c1c4318a309b5ec4fed336b7c509c690948f5c9cde9ca52d2d0506563468158e668736118cd71746b362e0a08f8ca80820192b8418f6a04fd5f0fe3697dc9d671fe9248f801d146bb498c1c3d24bc74a7101b05c2769702b72387be8ad5e556cf8535ccd2a1460113cc6f2efa2b5746ac24d00eb800b881767c4bbb4e73349cab5a450445a6631ad4aa92a0c7dedc9ff6bf8e1f09e2f626c1c2aa9769c3d77db38fcb24eb3d7c7073c9d70813c16a52ba93183afe619304049251265d34fbe11717eca8f9b06c14118ba5483fbd90c51095d5ef146b6e74368d4afd3c7bdf1783468ce67b3dda2f8721cb6cc8362416faa920e143e3f5f6dff8ca8082018fb84129c510417a9087a637f56d4e659f18f9f2838d257ca159b95812c25579ff5a004b2ae0fab5cd2f096e123afe9f3b239313fe44222cc3d0c2231df03442f2b67e01b8819456eac1ee6853e4bd61ecbaf6cf4908b0c77081de4fd6a1a4ab58d17259e22ec458b494e906ba2026cc7de2d7b9f0e40cc67575a957f4ca02752f63c9343ea104067432706f0ba1ca59bce018c4f8e5a6f64770c2d9c25df8cbad4ee2c8a28d6311d8c6e2b121ac35915cad35c78e356c07c53c75ba56c3ec8d6539453f03855df8ca808201abb8416befe2cc88f63cce1f0d9540c8faf3b388eeaa40e1dd2faea58be8c6a0e772884b235466417931d40d9232fe900419de0ab60f5693031f02f8215194ca816bcf01b88130741577f03f8e349c8ab8320a433d3341160f7b5bf25a649c3cff49209af1107bae952b81471ca7442ce509ec7df3ee01057fdcc8381393d2e94373bd287199045c4abbacc8caaec1b99c660d1f2b5d2d3a510016c16c6f73058373a7d11f32672939656e9684dc67e8ea0e436a15b5fbc6ac01ae82311fd30804f9828e52616dc08080`,
			hash: `0xd2ce921172b535b8f46b7c9cfa03b039c3f438eca66b6a7465a36b8acc596952`,
		},
	}
	number := big.NewInt(676159)
	for ni, node := range list {
		headerHash := common.BytesToHash(common.FromHex(node.hash))
		fmt.Println("ehaderHash", headerHash.String())
		bs, _ := hexutil.Decode(node.data)

		h := &types.Header{
			Number:    number,
			Validator: bs,
		}
		uc2, err := ExtractUconValidators(h, params.LookBackStake)
		if err != nil {
			logging.Error("ExtractUconValidators", "err", err)
			return
		}

		fmt.Println("------------------------------------------------")
		fmt.Println("nodeIndex", ni, "RoundIndex", uc2.RoundIndex)
		for i, v := range uc2.ChamberCommitters {
			payload := append(headerHash.Bytes(), append(number.Bytes(), uint32ToBytes(uc2.RoundIndex)...)...)
			pubKey, err := GetSignaturePublicKey(payload, v.Signature)
			assert.NoError(t, err)
			addr := crypto.PubkeyToAddress(*pubKey)
			fmt.Println("i", i, "addr", addr.String(), "idx", v.VoterIdx, "votes", v.Votes)
		}
	}
}

func TestExtract(t *testing.T) {
	data := `0xf905b901f902a8f886070380b8819c5dce4c87957eda815076e0f3f88c15d1926d198e26cc38025ab1fac60ed96478ab8af5a536c9abaf6d589e502c3b775809c744e29354d28b935d4d2fbe07a504c64d0715beab79a57eabb292e49d3d22d00ac65a4e389d9a578b26b34f15f30756144d5810c3f447275dd932998f0bccbf182006a6966c9aa6a6dadf39b60883f886012e80b88190ea067530e643df9a1a7f0ad948e1d8b546af4832ca073f7650a6c82ee8a4087835a051d0e181d424a810b365fedb1c75ab7bc07b7f4c534fa31b44e745797f04ffcf4052af542852a4b014f32862f5bb6a4ab488cc49056de8516d9c27925caa854c3610d48473e96102c42e2465d1a4549847a41f554c319d39a2d3771c8381f886090480b881f9fe1d7e3fdb0e9504216c910f9e78fd8ca91859540ac66d7b789825198a4a5e9ac5402aec76fe5e0485c2f5aec971cef2bbd1ee28a74edcd8a26cff630464a3042af86a496282bc85438e472dd498246acded9f5c38271eedd4ce4e9e68252cc547475269564505badca867b8efa8c5ff2eeea5e1ea139389673e0872552941dff886080880b881bd3f4e73da033fb6afdb3c796defc870d2a5aeb2ce4f4bf8c32c721965b9d68dd8ac3066417521534910f17434cfaaad9b9dd634fa916e96163c3c2f12604ee104f270490a031a025d026b0d22c4ae82bc0a7cd4a138577543777554e0ba3407abb65b4702e2f301a6d5ac7ea4da127fec68530b2c684a46964d51785171f20322f886802b80b881fab1c7615bc0d255b94f8bb8c3ecf8c0bc9fe37db8ad78d08fe77c29a2313f1c44753b364fc5141cc222296fad9f283ad6f6b1c0445320802163c8eac54d0b81049d3b2308be4573315de91cd7efb0fb71b8a8d8bb4203dae38da615952607157c3537973db5efd0e2e44d276d66c1263b5e8ee9b03ef435fa03aba95741cbde6ff902a8f886060b80b88140a6a255215c1f5f3871095b68f7cd8bf47ebd759d2f4099928db1fc78ab5991730d3375afe6cb7e1ca8831775bede046631b2f0aca48df82100e035f309a18704e1e52632be4a9a9204edc9e67e4a5c1b52e4b9a0acd5baf97ae26db13f95e8884cd67bd39103211694bcd79f7e13ac28b6075019e190149235fa378dea9bb5ecf886041280b8812d7abbd8a799f44ae54a3a59504a9425d77e282672f40d1f62f1a34f08e01ba4d7e262e5fe2bc7e38c8814ce6a3f113c1e6b0db365b90fbf3440a3434dc8d289041013027a1b2e4a438e333151f732b77d135ab2fd4469b4b47b28c5a60e6a4a7fe6e827ec8fd52148b646eaf6ecedc867263d9d523c96fb0195020ab5c9fae87cf886022580b881cbb11d7265e62bdad057a1d9fe202b35b8d427783b4bcdd925db7ad1af8aa544d8d5075ad4c68731aa1053f539162269aaebfb490a2871b07874349fe80cc24704fa02e9c270bd65aaa8cd1993ae7bd9c3214e479ec10bcbf927b97a14ac1759a669f0e4511094409b10d52d3983bd51d4c0359cc9463dffb67549f987bfa4e09bf886031380b881c3a49aa4ddf9736fc5b5e9edfc7dfc81ca98ed884431b1d934ce9f91589762f8a9332707cafc1616e2d50eba565a51927229c92389dde7448ff58efe0e2faeae04485da9319a9d6c6fa4d9eb2796c1f22c1e8c0fe8a375d52a73d44b86a4759a7a40265cce56f8332db5fc4b5d75231ae0cba19da38ecae2e42b988d2abc0f3a4cf886050d80b88189ae20e51c50714fbff78d29220dbb27d95ae123b3ffacaa0e87b9ed7d32f591e85892f962a167b14270840dd454f3950e918a198f42254ed68b38d7169ccd76041cef15d3abbcd41837a38b6448ec52ca0d038c38adf762bc521bb03c2da61b5dc35de1b4a79204128017bc3bd9dd5dc66642867da30ff1d1c65216d830108f2eb0805572cded818fb1c529d8df55ffd02cebdfeb0b1737773e85fe6c29667e7b7114b171c6775c8d7f36cf27ddac773435b0a96a452b9412c6ccf24abb1de0cc5bbf51896ccc32fd84bd76619830a1fa5112020d6c5b0e4741d2ba4e77d1c14082f0`
	h := types.Header{
		Validator: common.FromHex(data),
	}
	vs, _ := ExtractUconValidators(&h, params.LookBackStake)

	if vs != nil {
		fmt.Println("RoundIndex", vs.RoundIndex)
		fmt.Println("ChamberCommitters", len(vs.ChamberCommitters))
		fmt.Println("HouseCommitters", len(vs.HouseCommitters))
	}
	//380s 7m
}

func TestA(t *testing.T) {
	sk, err := crypto.GenerateKey()
	assert.NoError(t, err)
	vrfSk, err := secp256k1VRF.NewVRFSigner(sk)
	assert.NoError(t, err)

	threshold := uint64(600)
	stake := big.NewInt(10000)
	totalStake := big.NewInt(40000)
	_, _, vs := VrfSortition(vrfSk, seed, index, role, threshold, stake, totalStake)
	fmt.Println("vs", vs)
}
