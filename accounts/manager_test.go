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

package accounts

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/params"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var (
	ks     *keystore.PassphraseKeyStore
	mgr    AccountManager
	keydir = "./testkey"
)

func init() {
	os.RemoveAll(keydir)
	var err error
	ks, err = keystore.NewPassphraseKeyStore(keydir, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		panic(err)
	}
	params.InitNetworkId(params.NetworkIdForTestCase)
	mgr, err = NewManager(ks, nil)
	if err != nil {
		panic(err)
	}
}

func TestManager_ValKey_All(t *testing.T) {
	blsmgr := bls.NewBlsManager()
	n := 2
	pwdBase := "pass"
	accounts := make([]*Account, n, 2*n)
	//test NewAccount
	for i := 0; i < n; i++ {
		a, err := mgr.NewAccount([]byte(pwdBase))
		require.NoError(t, err)
		accounts[i] = a
	}
	//test NewValKey
	va, err := mgr.NewValKey(pwdBase)
	require.NoError(t, err)
	require.Equal(t, 33, len(va.MainPubKey))
	require.Equal(t, bls.PublicKeyBytes, len(va.BlsPubKey))
	fmt.Println("validator account: ", va.Address.String(), "mianPubKey:", common.Bytes2Hex(va.MainPubKey), "blsPubKey:", common.Bytes2Hex(va.BlsPubKey))
	//check Accounts
	require.Equal(t, n+1, len(mgr.Accounts()))

	//test UseValKey with wrong password
	k, err := mgr.UseValKey(va.Address, "wrongpass", true)
	require.Nil(t, k)
	require.Error(t, err)
	k = mgr.GetUnlockedValKey()
	require.Nil(t, k)
	//test UseValKey with keep=false
	k, err = mgr.UseValKey(va.Address, pwdBase, false)
	require.NoError(t, err)
	require.NotNil(t, k)
	require.NotNil(t, k.PrivateKey)
	require.Equal(t, bls.SecretKeyBytes, len(k.BlsKey))
	blsSk, err := blsmgr.DecSecretKey(k.BlsKey)
	require.NoError(t, err)
	blspub, err := blsSk.PubKey()
	require.NoError(t, err)
	cpk := blspub.Compress()
	equal := bytes.Equal(cpk[:], va.BlsPubKey)
	require.True(t, equal)
	//no unlock
	k = mgr.GetUnlockedValKey()
	require.Nil(t, k)
	//test UseValKey with keep=true
	k, err = mgr.UseValKey(va.Address, pwdBase, true)
	require.NoError(t, err)
	require.NotNil(t, k)
	require.NotNil(t, k.PrivateKey)
	require.Equal(t, bls.SecretKeyBytes, len(k.BlsKey))
	k2 := mgr.GetUnlockedValKey()
	require.NotNil(t, k2)
	require.Equal(t, 0, k.PrivateKey.D.Cmp(k2.PrivateKey.D))

	//
	va2, err := mgr.NewValKey(pwdBase)
	require.NoError(t, err)
	k, err = mgr.UseValKey(va2.Address, pwdBase, true)
	require.NoError(t, err)
	require.NotNil(t, k)

	//Only one unlocked validator key
	files, err := ioutil.ReadDir(keydir)
	require.NoError(t, err)
	uvcnt := 0
	fmt.Println("key files after second call of UseValKey with keep=true:")
	for _, f := range files {
		fmt.Println(f.Name())
		if strings.HasPrefix(f.Name(), uvPrefix) {
			uvcnt++
		}
	}
	require.Equal(t, 1, uvcnt)

	//get cached
	k2 = mgr.GetUnlockedValKey()
	require.NotNil(t, k2)
	require.Equal(t, 0, k.PrivateKey.D.Cmp(k2.PrivateKey.D))

	//test get history cached
	ks2, err := keystore.NewPassphraseKeyStore(keydir, keystore.StandardScryptN, keystore.StandardScryptP)
	require.NoError(t, err)
	mgr2, err := NewManager(ks2, nil)
	require.NoError(t, err)
	k2 = mgr2.GetUnlockedValKey()
	require.NotNil(t, k2)
	require.Equal(t, 0, k.PrivateKey.D.Cmp(k2.PrivateKey.D))

	//test LockValKey
	err = mgr.LockValKey()
	require.NoError(t, err)
	//after lock, should have no cached and uvfile
	files, err = ioutil.ReadDir(keydir)
	require.NoError(t, err)
	uvcnt = 0
	fmt.Println("key files after LockValKey:")
	for _, f := range files {
		fmt.Println(f.Name())
		if strings.HasPrefix(f.Name(), uvPrefix) {
			uvcnt++
		}
	}
	require.Equal(t, 0, uvcnt)

	//test Contains
	ok := mgr.Contains(va.Address)
	require.True(t, ok)
	ok = mgr.Contains(common.Address{})
	require.False(t, ok)

	//test ExportValKey - DelValKey - ImportValKey
	keyJson, err := mgr.ExportValKey(va.Address, pwdBase, "newPwd")
	require.NoError(t, err)
	fmt.Println(string(keyJson))

	//test delvalkey
	//delete first val key
	err = mgr.DelValKey(va.Address, pwdBase)
	require.NoError(t, err)
	//delete second val key
	err = mgr.DelValKey(va2.Address, pwdBase)

	//test
	vai, err := mgr.ImportValKey(keyJson, "newPwd", pwdBase)
	require.NoError(t, err)
	require.NotNil(t, vai)
	require.Equal(t, va.Address, vai.Address)
}
