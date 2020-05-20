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
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"os"
	"testing"
)

func TestYouMobile_SignTransaction(t *testing.T) {
	fromKey, _ := crypto.GenerateKey()
	fromKeyBytes := crypto.FromECDSA(fromKey)
	privateKey := fmt.Sprintf("0x%x", fromKeyBytes)
	fmt.Println("from", privateKey)

	toAddr := common.StringToAddress("1")
	tx, err := NewTransaction("0x1", &Address{toAddr}, "0x1", "0x1", "0x1", nil)
	assert.Nil(t, err)

	config := NewConfig()
	y, _ := NewYouMobile(config)
	acc, _ := y.ImportECDSAKey(privateKey, "")
	err = y.Unlock(acc, "")
	assert.Nil(t, err)
	s, err := y.SignTransaction(acc, tx)
	assert.Nil(t, err)
	fmt.Println(s)
	//remove keystore after testing
	defer os.RemoveAll("keystore/")
}
