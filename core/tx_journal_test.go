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

package core

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"os"
	"testing"
	"time"
)

func TestTxJournalDecode(t *testing.T) {
	journalFile := "transactions.rlp"
	journal := newTxJournal(journalFile)

	defer journal.close()
	defer os.Remove(journalFile)

	//signer := types.MakeSigner(params.TestnetChainConfig, big.NewInt(0))
	proc := time.Now()
	//prevNonce := uint64(0)
	total := 0
	err := journal.load(func(txs []*types.Transaction) []error {
		//for _, tx := range txs {
		//from, err := types.Sender(signer, tx)
		//distance := tx.Nonce() - prevNonce
		//log.Info("from", from.String(), "tx", tx.Nonce(), "from", "address", tx.To().String(), "distance", distance, "err", err)
		//prevNonce = tx.Nonce()
		//total++
		//}
		total += len(txs)
		return nil
	})
	fmt.Println("total", total)
	fmt.Println("using", time.Since(proc))
	if err := journal.rotate(nil); err != nil {
		logging.Warn("Failed to rotate transaction journal", "err", err)
	}
	fmt.Println("using", time.Since(proc))

	assert.NoError(t, err)
}
