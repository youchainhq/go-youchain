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

package trie

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/youdb"
	"testing"
)

func newEmpty() *Trie {
	trie, _ := New(common.Hash{}, NewDatabase(youdb.NewMemDatabase()))
	return trie
}

func TestEmptyTrie(t *testing.T) {
	var trie Trie
	res := trie.Hash()
	exp := emptyRoot
	if res != common.Hash(exp) {
		t.Errorf("expected %x got %x", exp, res)
	}
}

func TestInsert(t *testing.T) {
	trie := newEmpty()

	updateString(trie, "abc", "def")
	updateString(trie, "111", "222")

	exp := common.HexToHash("08f168795cf15b746e607120c01ed67cc3db05b61f0ccd243c58bde7acd9b2e2")
	root := trie.Hash()

	if root != exp {
		t.Errorf("exp %x got %x", exp, root)
	}

	trie = newEmpty()
	updateString(trie, "A", "BBB")

	exp = common.HexToHash("995be854bd598038e9298cf2b3dcf9665da154192f954387afa0849ed1c909f3")

	root, err := trie.Commit(nil)
	if err != nil {
		t.Fatalf("commit error: %v", err)
	}
	if root != exp {
		t.Errorf("exp %x got %x", exp, root)
	}
}

func TestGet(t *testing.T) {
	trie := newEmpty()
	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")

	for i := 0; i < 2; i++ {
		res := getString(trie, "dog")
		if !bytes.Equal(res, []byte("puppy")) {
			t.Errorf("expected puppy got %x", res)
		}

		unknown := getString(trie, "unknown")
		if unknown != nil {
			t.Errorf("expected nil got %x", unknown)
		}

		if i == 1 {
			return
		}
		trie.Commit(nil)
	}
}

func TestNew(t *testing.T) {
	mdb := youdb.NewMemDatabase()
	trie, _ := New(common.Hash{}, NewDatabase(mdb))
	updateString(trie, "doe", "reindeer")
	updateString(trie, "dog", "puppy")
	updateString(trie, "dogglesworth", "cat")
	root, err := trie.Commit(nil)
	require.NoError(t, err, "trie commit error")
	err = trie.db.Commit(root, false)
	require.NoError(t, err, "mdb commit error")

	_, err = New(root, trie.db)
	require.NoError(t, err, "error on New:")

	fmt.Printf("root: %x\n", root)
	//dump db
	for _, key := range mdb.Keys() {
		value, _ := mdb.Get(key)
		fmt.Printf("%x:%x\n", key, value)
	}

	mdb.Delete(root.Bytes())
	_, err = New(root, trie.db)
	require.Error(t, err)
	fmt.Println(err)

	//redo update
	trie, _ = New(common.Hash{}, NewDatabase(mdb))
	tryUpdateString(t, trie, "doe", "reindeer")
	tryUpdateString(t, trie, "dog", "puppy")
	tryUpdateString(t, trie, "dogglesworth", "cat")
	r2, err := trie.Commit(nil)
	require.NoError(t, err, "mdb commit error")
	err = trie.db.Commit(root, false)
	fmt.Println("after update")
	//dump db
	for _, key := range mdb.Keys() {
		value, _ := mdb.Get(key)
		fmt.Printf("%x:%x\n", key, value)
	}
	require.NoError(t, err)
	require.Equal(t, root, r2)
	_, err = New(r2, trie.db)
	require.NoError(t, err)
}

func getString(trie *Trie, k string) []byte {
	return trie.Get([]byte(k))
}

func updateString(trie *Trie, k, v string) {
	trie.Update([]byte(k), []byte(v))
}

func deleteString(trie *Trie, k string) {
	trie.Delete([]byte(k))
}

func tryUpdateString(t *testing.T, trie *Trie, k, v string) {
	err := trie.TryUpdate([]byte(k), []byte(v))
	require.NoError(t, err)
}
