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
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	secp256k1VRF "github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/params"
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
		t.Error("ValidatorsToByte", "err", err)
		return
	}

	h := &types.Header{
		Validator: data,
	}
	uc2, err := ExtractUconValidators(h, params.LookBackStake)
	if err != nil {
		t.Error("ExtractUconValidators", "err", err)
		return
	}

	if uc2.RoundIndex != uc.RoundIndex {
		t.Error("not the same 1")
		return
	}

	//if len(uc2.ChamberValidators) != len(uc.ChamberValidators) {
	//	logging.Error("not the same 2")
	//	return
	//}

	if len(uc2.ChamberCommitters) != len(uc.ChamberCommitters) {
		t.Error("not the same 3")
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

func TestExtract(t *testing.T) {
	data := `0xf9102c01f90ff3f88702818080b881c6a432eeb0a67d34de267cc8e6172468aada30da598b765244e0ed46595e5a828722aae2e8b450ec6940426fec76289e76b719b1019f57ba1922fe911785892704bb1ae55e971543b6df463e97f10820244566a6ba84ae2065dcf61e44109605b98cb0915edfe68c73311f24823870d8a40e4fde313b008d9f7d6c7f9e189319a1f8861e1380b881f7bc93f4781c73bd7d51c1a08021eb893ba7b45b3d8c059eab2da173f96f06020c51d07e4e714208a35e7a225ca4b1c1364eff2a02e6ff7a5e31bf385164d6e0046d1401a9b293eddf62401a619ba2ab659f68c9c61f7da284ffedb073ab234642c285d3045e77a5bb51c2dbe7cf413d615dcea56892a1abd5e52c2f360b36bb0ff88704818f80b881eaca477146753ebba61da458ad9d25311b0f957078552c42079715316a55acbd8951c0f8ff9dddaa2307230bb39d65523de33980fd09da165d82f0c1249ead0304b7725ae878aee6276a0d4ea65530aecaef5654edc312e16ba32bd15cdbe0420351d609e124adf7208c2f68488e0e2a8bb10d0dc5da81481bed971c93b99fb9adf8860b7880b8814f427bb3fc16f4751c991cec55e1338ed7775aed6e07003b2db26ce30ec1998dbc2e646d16a15b414021af4b9be8e6e9fd619a310dcbb9c1aff90bfa93a53de8042de18e21e9b5d1da760d56120e8a9d740811a57c9db1a93742184929942670b3b70ad5693dccf2f01f0317d04d152558d26fc8e3df73746edb05ceac9f135634f886211480b881718b83a3e9d9728e445a1c5126f9bf4b8449446e8e72b4da5a6bf3a63570d9a989c3da771d3eab7e39631d5624f429ae597d48e95355d99702ccfd57378300b304df9e9a1bad3fa81a49510b760077a0f47e3807b7ea844b7d953e60c5c01c103b31cf8b2160e38638026e32df9590b83214c4f3e03fa078031a532651f47dd5aef88707818780b8812333e436580e60b7b2ffb4c3469e5d11fba72b876dee2fcced39d8a372cf6445ebf7f890d30436e6e8f06a2489d54c0efd04ed6f2b9c12c5a23751183a0683c1044def9b62c114f70bdec8ae356b63d8c6c8d1b64cd3332c77c63d932fae49a0937c075624cd1cfd1ec41c4988181901cd6a3a0407ed9f491c193eeaaf722ea43df886391b80b881310b428190828da6740b93945eafaa5e61b3dfbff2df0faaaaaf1294db736b21b9009de31c303b614bcb160b3b436fab353b696604664c51608d447b9b55c75504939b4f6881105a95009619e03accdc670cd675f01c3075b426b9ee977371cf198301d4b8b2d8d8bf9224defde28ca6ed13e795b821ceff1465b6bacf0e67ec41f8862c1a80b8812be48dd293bab0e9437c566b2d4b18bcc827fae70a73f95921ee46c93e02dce8cfa82feea5130e58b640b5a23f4344c1246f6530b386ea819d9ee3725198c0f5043256f5181618a84a1b71d170d5180f943250924de40afddccdec95e6ea41c7643bf7dc73824a9b47d4bcb207e52568235c6c49ff3904cc04de3bae605271e78bf886261480b8817631eda22326fe26aded99ef505b59749e4ad0c91d47f4b6ab5e6d7dff85434895aaab23d917ec83bb4a2d5c2bd878e47d745b49424e80d6b8bf79b7fbd2c0190468a266c77ccb0a6a4d008e58dcadabd54b241119b7dfa19603895724d5281ac7c547b086d636363a87fd95ca510e964c5b63472dcd3498cb8b56d98ba4285ea5f8862a1780b881548037f1427ad45fad679b2024187021dd58dd3e19392188d8bb7da6a954c19f40e6931a52dfe2a1cd41403f56b75921c52c5b68cf10150814eb2e450c0d2962041e7187492b53f8c3ae3095afee02734da01ce9da63631ae3f07d941e57b4563f71b3a10346ebf2e444d01866ff273e59baad4afb2de2f5d5bd6583c5f480c06bf886101280b881026aeb26d2415e65275ccc34593b872690efe48c80305aa242ba89b3931071a3e2312f200729506393fe63cb706d5f615e887d014ded504c4beef4f0e3ef503104f358962730732c70b5e7ad5a5ecf9f926c5c1d315ce5e32ddfece96cc1d1f84ab79db7251bd4e08d7b0f20f633d6594f386ae8acdb0853143534c710f11ff6aaf8862b1480b88165646da84b7fb103822712031ef3a03faa1eb8df12133182a95efb841d1beb9c12c760f1b78e296745db0765e45c948c310b84994bf3ae5eab3e55b47563c55704b957a50cb1c4be8a1a009ff18a1d0373c917598680d48f93134fdc7faf0ff01a7b9d6a33cfc802c36ccb6647c21b30a6a4d171484cbeca03cf69aced1ce4b4b8f886130f80b8818feaa915af52c68c2c9a0cba21de094953303bef527c0939064c301b0a8ccf880f89f1daaf60e8d85e75a83d757c0dda544984d96e177051140e2f5972396e41047f4e6c06fbb80dcf9a59dfac027e6eb9fa942dca1c159c384cc988d89a99f21827f400094a6a553ec4ab8d2693bf2bee56c205309af7117563e9812366dfff55f8860c7380b8817c31347cfd3121bb0f566b698b7c7200a59595402dda33bdfd6f1280bf936b19541448b63389a2fbff952bbe123dff12746ef36302175c051d9a54eaa1598f9e0424d42ca1acfde5b003088c6e8bbfef8ded03936230a0f42ea7d00e964fe2f8b8a95be6f3ddb9cedb20f334db1b9e7bd81b02b2486246138ca4c083335b10cec4f886371880b881c3d9f1d5d1bf1b6b6609af46e0465ea904a040260cd8076db0b3f1b0ff7c5869a827f3d136ce502073421f7a50495bffb2bcaf5704b867ba94c77671ae93211a04e350b01e0108494ace24f0d5a1e35b1b40afad39bddec2f2968244b38e5775caee4beb0661269c5e3a4fd70fa17856bfd14ed40e91c50012cdb7f979dcead685f886191d80b88172c1cfa986e67041f49a9bff4ce222acea2c022b1fa51e75f6c9a8a76c43829ccba268e2fd835cc37d637b7af8d530ddb7e32d74fa44bb0a55b1c115b491446004e750469cf3a2b58e6fa433c0b263ea0c4662584b5a754ee2cff5ef3b9297d013e11d23417bfc4facd51639d22a11e34329fc580a39fb97a2749f6935475b4370f8860a6180b881d08fb9cd2dbf38778934abd3a45a40db732fbe02165ab8077079a977d123d1c21e685d02c17d3a35c3cc841fd7a0c7712e0f6c9e583b6d41d112060c25ceeace04dd929163539c9dd52a59ade3cd8ed9824151d01083d5762e139a371297805a0460f9f7a558ef8c0d64c078f38278919e533a1a85b1cfef3ef623532b26bb8d9af886160d80b8815cddb7ebb957208a19736d141a43c1c32df612af12eeff33502f2fccbaf0907fe1be658731a1bacfe23f73a2ec0b14c13c231578ed719e7c6b08d8a95a83e42d0404e05cf69c381aa8fb305e6a327e1a48ee786b3108732e916946e5e9332701fc93a1d5e88f5351644538e94cace4c3deb3fd220de91cd9a047a830550e94505df886271380b881bfe225b2afe3487bc6a79fdb2fb4e762fd008eb46cb61fd2dd8b6e593ff931ce3d2eb70e1bda368021b9681e8c008cb3de1cbe9eaee96dce1690e23170fa6335043cba4be8c630b5a65dda6ee700997992ad440040879e1e72d24dd386c683eb8cabd867f4a1ccba177669154ece35ec48b0760cde263455b1d17d8c6db70d3eccf886017f80b881bba576a42c098a43a2989e77c2079b98c3ce933aa6acadd8dda320cf78a02723672ac20839ecc1e10896ebb1a911b2c904e5375b1bfc9d51ce9228daa6e32ef0040cdc760f4612e931144ff7b53c70b4112c8fd9d2cf2ebcaf057cf438206e2321b10b5d36d54cf03ca35af628f55e24249cf740a1043d2f05cc3a45bad083dd26f886240f80b8811199c607c8bccb2f814b4d6ba0b0efa06ca2eeb5b2c16b2186c22e343860c859b7e6565264cc2f8cbff7855e35de58a4daed93b2a464cfaf9c32981eec055176044790f980d4021ce327d36814edeea1961c6b6ba1660ae096dcdae304e3aaba2014b52b1c171eefc67bc5f3d357efd4a02e5a33997889d2ba94a3e129882f44d8f886281580b8817f06236cb5f557e2e64b003974985245caeb38ca0c691f7399bcb2684c1054658f6f20fb242bb67cbe64f725dd85db90cde7c209f4a51ac3b6314f86e5f34e13048407dff9dcb82e2c711397e3f9e9316afcae66d6eda439f2a101d590a26d980ba45c9c73e849ee3cec6911ea8b30638def0153c26554d544cbd1c515f469eaa0f8861d1180b88123cabef8a1fd1efe3a0b514d29c77ffc4ed574eef9c402bbd0052fb891e7f7058704fb089a105aec10e3fdb9b49294063f19759b7132fdb51381af33abc5ee2b04a06786715b936da2cf054fef15d1dc660ed6f6658b2c5916c7098dd1fc3d2a7c50cea49410dc60790fff491577ddfde856bfbe9f325b7e487b9982f9a8a1a4d6f886361880b881e02159b7ec37b6671e78beb00c8605e3e0be5ab9bad2c0f380cee0fb6a16cb283ac111ef65762705777b0c901202185e16c8e42efa5b58708f7517e0841c8ea2048c0350c94261c265533017c9bfc6ea56fbe1a730c2dc68f7b3c30a3d3136471ac7aa207031a02d2ada11c831cca604edc226e446bc44c1471a121ab0322f9c85f886056980b8811d677afe2c8e4c112007ad59f5a75ac0d24d12ed2763e7da3cef81415b24e0d4826e5c407f160a73ab6634610abded9aa9282a8432ab5786c676fa9eaf25dccb047de76efcf13cbecdaec2dbfafa20a2753f5bfa223b2f60508daa27651438fc58670c386cbc603c89cb39f7cf1c0bf0fb3703354ddbc1170a5a1649d0f0905560f886311280b8810dc2e96c9ad6aaa37dae556712c2203c455dce647bce6e7daa919eac8a2063d37fb5fd8a33c4c43081314bcd85e30cec8ee0d90d3756e135dfe8b3f02641e478048b97a74149f30bbeec92fe0f4dea4d425ced649930892c87134bf16abb7a3ed46ede1549e7a76a0cd140389c6088507144e30b551eda9cca8047bfde23cd0189f886291280b88124f4e4dfebcb3726ac72244971182195386c126dbb50a3ad4dedbe0a9d0a4458c82d1c393a727f3eff87695e048928c2c7bbb823b4032de2a98996a63e48d1eb047d19dd912bee7a58c689f339d876fb0fadb52b658e9df22e1f0ad54bc328fee50f89db73d1ec2c52baaccb2ac34d2818fbdeb6a9ba18d791b3f2d5ddb5f9459ef886201180b88181c0ddaade7d102af93dfcf9166e8b95540ee5cb7f48ed930b48519971b1d226b44aadf995bd33e69e303ce43ad2c690808d52bce9da2d5c1f110b26d675b07d04f1e8efaa73c2c0e39abfb2bf64a5b2628043730321f7f97e97f55c5b8cf162316537e55b3b2084004ac123ef3828a68bd343c79c45fc1bfba842f16521ca96aaf886181780b881423ea240cd3e2e808b085ba48641543ce42abcde4d8e51b79e1a7013cd4a5eb102d9c83733954cfc6ae1a3cc7d8a408c2d3b59c13f3ce2b1bb263c226e11142e045c281a0a5675ebfbd330964d94ff9fde50d60e4b55bf52ae2c5a961bb9ecdbecfbc2d43094a9b7ee8ffeaef5909e6a075bd11e8a837b907bf0739daca70d3a33f886171180b88186ab96fda769a696a58b38ec9d503611a13ff7a7221e5c44281c37010f06ce880d61d4a90b45ccceb2fb97d405f91dc30689d8dd872f3777ec5ac98fded1ea5304522f18b1e48421658ba2e73ea653e0fbbca869a099eb6090f4d202af7631f657aa9655709a295caaa535677abf9cf83fb894d930bddda39caf92867f84821dfac0c0b08b268472d2cb6c8efd0827357c9f2928ce74dc1a37c164bd558e2736cc95ebe704a781746d3975e0531b74c0f9f06d588080`
	h := types.Header{
		Validator: common.FromHex(data),
	}
	vs, err := ExtractUconValidators(&h, params.LookBackStake)
	require.NoError(t, err)

	if vs != nil {
		fmt.Println("RoundIndex", vs.RoundIndex)
		fmt.Println("ChamberCommitters", len(vs.ChamberCommitters))
		fmt.Println("HouseCommitters", len(vs.HouseCommitters))
	}
	//380s 7m
}
