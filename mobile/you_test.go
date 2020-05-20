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

package mobile

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"math/big"
	"os"
	"testing"
)

func init() {
	params.InitNetworkId(params.NetworkIdForTestCase)
}

func TestNewYouMobile(t *testing.T) {
	config := NewConfig()
	config.Endpoint = "http://localhost:3009"
	_, err := NewYouMobile(config)
	defer os.RemoveAll("keystore/")
	assert.NoError(t, err)
}

func testGetClient() *YouMobile {
	config := NewConfig()
	config.Endpoint = "http://localhost:3009"
	cli, _ := NewYouMobile(config)
	defer os.RemoveAll("keystore/")
	return cli
}

func TestMobile_CreateAccount(t *testing.T) {
	cli := testGetClient()
	acc, _ := cli.CreateAccount("111111")
	fmt.Println(acc.account.Address.String())
	assert.Len(t, acc.account.Address.String(), len("0x328b862bB7DB4814c7170d6c6192F62107075B0a"))
}

func TestYouMobile_Find(t *testing.T) {
	cli := testGetClient()
	acc, _ := cli.CreateAccount("111111")
	f, _ := cli.Find(acc.GetAddress().String())

	assert.Len(t, f.GetAddress().String(), len("0x328b862bB7DB4814c7170d6c6192F62107075B0a"))
}

func TestYouMobile_Call(t *testing.T) {
	cli := testGetClient()

	fmt.Println("------------------------------------------------------------------")
	balance, err := cli.Call("you_getBalance", []byte(`["0xF247f8ccFf43161ca3c6331538a6C4b2923fA1B2"]`))
	if err != nil {
		logging.Error("call failed", "err", err.Error())
	} else {
		logging.Info("call succeed", "balance", string(balance))
	}
	assert.Equal(t, "", balance)
}

func TestGetAddressFromPrivate(t *testing.T) {
	privateKeyStr := `0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109`
	bs, _ := hexutil.Decode(privateKeyStr)
	privateKey, _ := crypto.ToECDSA(bs)
	addr := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Println(addr.String())
}

func TestYouMobile_SendTransactions(t *testing.T) {
	t.SkipNow() // run on need

	config := NewConfig()
	api := "http://27.159.122.28:34283"
	config.Endpoint = api
	cli, _ := NewYouMobile(config)
	defer os.RemoveAll("keystore/")
	//privateKeyStr := `0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8`
	privateKeyStr := `0x372f86826d3a107bd342aa8713081514e97d7dcc8c6f4168a4f8bc6a6c6fa358`
	bs, err := hexutil.Decode(privateKeyStr)
	if err != nil {
		logging.Crit("Decode failed", err.Error())
	}
	privateKey, err := crypto.ToECDSA(bs)
	if err != nil {
		logging.Crit("ToECDSA failed", "err", err.Error())
	}
	accRaw, err := cli.accountManager.ImportECDSA(privateKey, "")
	if err != nil {
		logging.Crit("ImportECDSA failed", "err", err.Error())
	}
	acc1 := &Account{accRaw}
	cli.Unlock(acc1, "")

	addr2, _ := NewAddress(`0x328b862bB7DB4814c7170d6c6192F62107075B0a`)

	amount, _ := big.NewInt(0).SetString("1000000000000001", 10)
	hexAmount := hexutil.EncodeBig(amount)
	tx, err := NewTransaction(hexutil.EncodeUint64(uint64(20002)), addr2, hexAmount, "0x1000000", "0x100", nil)
	bs1, err := cli.SignTransaction(acc1, tx)
	if err != nil {
		logging.Info("SignTransaction failed", "err", err.Error())
	} else {
		logging.Info("SignTransaction")
	}

	x := fmt.Sprintf(`["%s"]`, bs1)
	//["0xf86c824e22820100840100000094328b862bb7db4814c7170d6c6192f62107075b0a87038d7ea4c68001801ba0c9b7b4db9b791e5b64c15c81dbab75b314f05f8bfba8913f35785307b1c65de1a031e414c7c384624774714bb5e33eb0d2458a5367ba0c537fa78348f502b372fc"]
	fmt.Println(x)
	vv, err := cli.Call("you_sendRawTransaction", []byte(x))
	fmt.Println("err", err)
	fmt.Println("value", vv)

	txs := []hexutil.Bytes{}
	{
		amount, _ := big.NewInt(0).SetString("1000000000000001", 10)
		hexAmount := hexutil.EncodeBig(amount)
		tx, _ := NewTransaction(hexutil.EncodeUint64(uint64(20003)), addr2, hexAmount, "0x1000000", "0x100", nil)
		bs1, _ := cli.SignTransaction(acc1, tx)
		bs11, _ := hexutil.Decode(bs1)
		txs = append(txs, bs11)
	}
	{
		amount, _ := big.NewInt(0).SetString("1000000000000001", 10)
		hexAmount := hexutil.EncodeBig(amount)
		tx, _ := NewTransaction(hexutil.EncodeUint64(uint64(20004)), addr2, hexAmount, "0x1000000", "0x100", nil)
		bs1, _ := cli.SignTransaction(acc1, tx)
		bs11, _ := hexutil.Decode(bs1)
		txs = append(txs, bs11)
	}
	fmt.Println("txs", len(txs))
	fmt.Println("txs", txs)
	//var Data []interface{}
	//Data = append(Data, txs)
	bsss, _ := json.Marshal(txs)
	vv, err = cli.Call("you_sendRawTransactions", bsss)
	fmt.Println("err", err)
	fmt.Println("vv", vv)

}

func TestHexBytesInt(t *testing.T) {
	//i := "0x222221"
	//v, err := hexutil.DecodeUint64(i)
	//if err != nil {
	//	fmt.Println(err.Error())
	//} else {
	//	fmt.Println(v)
	//}

	a := "0x7e37be2022c0914b2680000000"
	bg, _ := hexutil.DecodeBig(a)
	fmt.Println(a)
	bg.Add(bg, big.NewInt(1))
	fmt.Println(bg)
	fmt.Println(hexutil.EncodeBig(bg))

	a = "0x7e37be2022c0914b2680000000" //10000000000000000000000000000000
	b1 := NewBigInt(0)
	err := b1.SetHexString(a)
	if err != nil {
		fmt.Println(err.Error())
	}
	b1.Add(10000)
	fmt.Println(b1.Hex())    //0x7e37be2022c0914b2680002710
	fmt.Println(b1.String()) // 10000000000000000000000000010000

}

func TestYouMobile_ImportECDSAKey(t *testing.T) {
	privateKey := `0xe236aad01473381b506542fbe5de0826d41991c21defd6b6be99a264aa1125ae`
	address := `0x43728Ef88f0235400B674b339201FbeF811FE513`
	config := NewConfig()
	cli, _ := NewYouMobile(config)
	defer os.RemoveAll("keystore/")
	acc, err := cli.ImportECDSAKey(privateKey, "")
	assert.Nil(t, err)
	assert.Equal(t, address, acc.GetAddress().String())
	assert.NotNil(t, acc.GetPath())
}
