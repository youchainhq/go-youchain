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
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/rlp"
)

// Transaction represents a single transaction.
type Transaction struct {
	tx *types.Transaction
}

// NewTransaction creates a new transaction with the given properties.
func NewTransaction(nonce string, to *Address, amount string, gasLimit string, gasPrice string, data []byte) (*Transaction, error) {
	amountBig, err := hexutil.DecodeBig(amount)
	if err != nil {
		return nil, err
	}
	gasLimitBig, err := hexutil.DecodeBig(gasLimit)
	if err != nil {
		return nil, err
	}
	gasPriceBig, err := hexutil.DecodeBig(gasPrice)
	if err != nil {
		return nil, err
	}
	nonceBig, err := hexutil.DecodeBig(nonce)
	if err != nil {
		return nil, err
	}
	return &Transaction{types.NewTransaction(nonceBig.Uint64(), to.address, amountBig, gasLimitBig.Uint64(), gasPriceBig, common.CopyBytes(data))}, nil
}

type Transactions struct {
	txs []*Transaction
}

// Append Transaction to list
func (t *Transactions) Append(tx *Transaction) {
	t.txs = append(t.txs, tx)
}

// SignTransaction sign tx for SignRawTransaction
func (y *YouMobile) SignTransaction(account *Account, tx *Transaction) (string, error) {
	signedTx, err := y.accountManager.SignTx(*account.account, tx.tx)
	if err != nil {
		return "", err
	}
	if bs, err := rlp.EncodeToBytes(signedTx); err == nil {
		return fmt.Sprintf("0x%x", bs), nil
	} else {
		return "", err
	}
}
