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

package state

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"

	mapset "github.com/deckarep/golang-set"

	checker "gopkg.in/check.v1"
)

type stateTest struct {
	db    youdb.Database
	state *StateDB
}

func newStateTest() *stateTest {
	db := youdb.NewMemDatabase()
	sdb, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))
	return &stateTest{db: db, state: sdb}
}

type StateSuite struct {
	db    *youdb.MemDatabase
	state *StateDB
}

var _ = checker.Suite(&StateSuite{})

var toAddr = common.BytesToAddress

func (s *StateSuite) TestBasic(c *checker.C) {
	addr := common.BigToAddress(big.NewInt(1))
	obj1 := s.state.GetOrNewStateObject(addr)

	obj1.AddBalance(big.NewInt(1))
	obj1.SetNonce(1)

	pub := hexutil.Bytes(hexutil.MustDecode(`0x02008bd2ee1c634626e935503b0669fc459e19e19f0132b1bdd31994b97593ea8b`))

	addr1 := common.BigToAddress(big.NewInt(int64(1)))
	name := addr1.String()
	fmt.Println("name", name)
	val := s.state.CreateValidator(name, addr1, addr1, params.RoleChancellor, pub, pub, big.NewInt(15000), big.NewInt(15000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	s.state.updateStateObject(obj1)
	s.state.UpdateDelegation(addr, val, params.StakeUint)
	s.state.Commit(true)

	got := string(s.state.Dump())
	fmt.Println(got)
	//TODO: update testcase
	/*
			want := `{
			"root": "64e178806bec646a23c2222c1b0bf5164bdee72ec94d2fb3c89525e8adef9bed",
			"valRoot": "e49f5a120ee486910481812533b14ef454f76fdc21e04aa363484e71eaef2062",
			"accounts": {
				"0000000000000000000000000000000000000001": {
					"balance": "1",
					"nonce": 1,
					"root": "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
					"storage": {}
				}
			},
			"validators": {
				"0x9Eb0dE3E2F1bE8087343258e63fEf417e18d5d77": {
					"mainAddress": "0x9eb0de3e2f1be8087343258e63fef417e18d5d77",
		            "name": "0x0000000000000000000000000000000000000001",
					"operatorAddress": "0x0000000000000000000000000000000000000001",
					"coinbase": "0x0000000000000000000000000000000000000001",
					"mainPubKey": "0x02008bd2ee1c634626e935503b0669fc459e19e19f0132b1bdd31994b97593ea8b",
					"blsPubKey": "0x02008bd2ee1c634626e935503b0669fc459e19e19f0132b1bdd31994b97593ea8b",
					"token": "15000",
					"stake": "15000",
					"status": 1,
					"role": 1,
					"rewardsBase": "0",
					"rewardsTotal": "0",
					"expelled": false,
					"expelExpired": 0,
					"lastInactive": 0
				}
			},
			"validatorsStat": {
				"kinds": {
					"0": {
						"onlineStake": "15000",
						"onlineToken": "15000",
						"onlineCount": 1,
						"offlineStake": "0",
						"offlineToken": "0",
						"offlineCount": 0,
						"lastSettle": 0,
						"rewardsResidue": "0",
						"rewardsLevel": "0",
						"rewardsTotal": "0"
					},
					"1": {
						"onlineStake": "15000",
						"onlineToken": "15000",
						"onlineCount": 1,
						"offlineStake": "0",
						"offlineToken": "0",
						"offlineCount": 0,
						"lastSettle": 0,
						"rewardsResidue": "0",
						"rewardsLevel": "0",
						"rewardsTotal": "0"
					},
					"2": {
						"onlineStake": "0",
						"onlineToken": "0",
						"onlineCount": 0,
						"offlineStake": "0",
						"offlineToken": "0",
						"offlineCount": 0,
						"lastSettle": 0,
						"rewardsResidue": "0",
						"rewardsLevel": "0",
						"rewardsTotal": "0"
					}
				},
				"roles": {
					"1": {
						"onlineStake": "15000",
						"onlineToken": "15000",
						"onlineCount": 1,
						"offlineStake": "0",
						"offlineToken": "0",
						"offlineCount": 0,
						"lastSettle": 0,
						"rewardsResidue": "0",
						"rewardsLevel": "0",
						"rewardsTotal": "0"
					},
					"2": {
						"onlineStake": "0",
						"onlineToken": "0",
						"onlineCount": 0,
						"offlineStake": "0",
						"offlineToken": "0",
						"offlineCount": 0,
						"lastSettle": 0,
						"rewardsResidue": "0",
						"rewardsLevel": "0",
						"rewardsTotal": "0"
					},
					"3": {
						"onlineStake": "0",
						"onlineToken": "0",
						"onlineCount": 0,
						"offlineStake": "0",
						"offlineToken": "0",
						"offlineCount": 0,
						"lastSettle": 0,
						"rewardsResidue": "0",
						"rewardsLevel": "0",
						"rewardsTotal": "0"
					}
				}
			},
			"validatorsWithdraw": []
		}`
			want = strings.Replace(want, "	", "    ", -1)
			if got != want {
				c.Errorf("dump mismatch:\ngot: \n%s\nwant: \n%s\n", got, want)
			}
	*/
}

func (s *StateSuite) TestNull(c *checker.C) {
	address := common.HexToAddress("0x823140710bf13990e4500136726d8b55")
	s.state.CreateAccount(address)
	//value := common.FromHex("0x823140710bf13990e4500136726d8b55")
	var value common.Hash
	s.state.SetState(address, common.Hash{}, value)
	s.state.Commit(true)

	value = s.state.GetState(address, common.Hash{})
	if value != (common.Hash{}) {
		c.Errorf("expected empty hash. got %x", value)
	}
}

func (s *StateSuite) TestSnapshot(c *checker.C) {
	stateobjaddr := toAddr([]byte("aa"))
	var storageaddr common.Hash

	data1 := common.BytesToHash([]byte{42})
	data2 := common.BytesToHash([]byte{43})

	genesis := s.state.Snapshot()

	s.state.SetState(stateobjaddr, storageaddr, data1)
	snapshot := s.state.Snapshot()

	//revert prev state
	s.state.SetState(stateobjaddr, storageaddr, data2)
	s.state.RevertToSnapshot(snapshot)

	c.Assert(s.state.GetState(stateobjaddr, storageaddr), checker.DeepEquals, data1)

	//revert to genesis
	s.state.RevertToSnapshot(genesis)

	c.Assert(s.state.GetState(stateobjaddr, storageaddr), checker.DeepEquals, common.Hash{})
}

func (s *StateSuite) SetUpTest(c *checker.C) {
	s.db = youdb.NewMemDatabase()
	s.state, _ = New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(s.db))
}

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { checker.TestingT(t) }

func TestSnapshot(t *testing.T) {
	stateobjaddr := toAddr([]byte("aa"))
	var storageaddr common.Hash
	data1 := common.BytesToHash([]byte{42})
	data2 := common.BytesToHash([]byte{43})
	s := newStateTest()

	// snapshot the genesis state
	genesis := s.state.Snapshot()

	// set initial state object value
	s.state.SetState(stateobjaddr, storageaddr, data1)
	snapshot := s.state.Snapshot()

	// set a new state object value, revert it and ensure correct content
	s.state.SetState(stateobjaddr, storageaddr, data2)
	s.state.RevertToSnapshot(snapshot)

	if v := s.state.GetState(stateobjaddr, storageaddr); v != data1 {
		t.Errorf("wrong storage value %v, want %v", v, data1)
	}
	if v := s.state.GetCommittedState(stateobjaddr, storageaddr); v != (common.Hash{}) {
		t.Errorf("wrong committed storage value %v, want %v", v, common.Hash{})
	}

	// revert up to the genesis state and ensure correct content
	s.state.RevertToSnapshot(genesis)
	if v := s.state.GetState(stateobjaddr, storageaddr); v != (common.Hash{}) {
		t.Errorf("wrong storage value %v, want %v", v, common.Hash{})
	}
	if v := s.state.GetCommittedState(stateobjaddr, storageaddr); v != (common.Hash{}) {
		t.Errorf("wrong committed storage value %v, want %v", v, common.Hash{})
	}
}

func TestSnapshotEmpty(t *testing.T) {
	s := newStateTest()
	s.state.RevertToSnapshot(s.state.Snapshot())
}

func TestSnapShot2(t *testing.T) {
	state, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(youdb.NewMemDatabase()))

	stateobjectaddr0 := toAddr([]byte("so0"))
	stateobjectaddr1 := toAddr([]byte("so1"))
	var storageaddr common.Hash

	data0 := common.BytesToHash([]byte{17})
	data1 := common.BytesToHash([]byte{18})

	state.SetState(stateobjectaddr0, storageaddr, data0)
	state.SetState(stateobjectaddr1, storageaddr, data1)

	so0 := state.GetOrNewStateObject(stateobjectaddr0)
	so0.SetBalance(big.NewInt(42))
	so0.SetNonce(43)
	so0.SetCode(crypto.Keccak256Hash([]byte("cafe")), []byte("cafe"))
	so0.suicided = false
	so0.deleted = false
	state.setStateObject(so0)

	root, valRoot, _, _ := state.Commit(true) //stataddr1 will be deleted as a empty object
	state.Reset(root, valRoot)

	state.SetState(stateobjectaddr1, storageaddr, data1)
	so1 := state.getStateObject(stateobjectaddr1)
	so1.SetBalance(big.NewInt(52))
	so1.SetNonce(53)
	so1.SetCode(crypto.Keccak256Hash([]byte("cafe2")), []byte("cafe2"))
	so1.suicided = true
	so1.deleted = true
	state.setStateObject(so1)

	so1 = state.getStateObject(stateobjectaddr1)
	if so1 != nil {
		t.Fatalf("deleted object not nil when getting")
	}

	snapshot := state.Snapshot()
	state.SetNonce(stateobjectaddr0, 0)
	state.RevertToSnapshot(snapshot)
	if state.GetNonce(stateobjectaddr0) == 0 {
		t.Fatal("revert failed")
	}

	so0Restored := state.getStateObject(stateobjectaddr0)
	// Update lazily-loaded values before comparing.
	so0Restored.GetState(state.db, storageaddr)
	so0Restored.Code(state.db)
	// non-deleted is equal (restored)
	compareStateObjects(so0Restored, so0, t)

	// deleted should be nil, both before and after restore of state copy
	so1Restored := state.getStateObject(stateobjectaddr1)
	if so1Restored != nil {
		t.Fatalf("deleted object not nil after restoring snapshot: %+v", so1Restored)
	}
}

func compareStateObjects(so0, so1 *stateObject, t *testing.T) {
	if so0.Address() != so1.Address() {
		t.Fatalf("Address mismatch: have %v, want %v", so0.address, so1.address)
	}
	if so0.Balance().Cmp(so1.Balance()) != 0 {
		t.Fatalf("Balance mismatch: have %v, want %v", so0.Balance(), so1.Balance())
	}
	if so0.Nonce() != so1.Nonce() {
		t.Fatalf("Nonce mismatch: have %v, want %v", so0.Nonce(), so1.Nonce())
	}
	if so0.data.Root != so1.data.Root {
		t.Errorf("Root mismatch: have %x, want %x", so0.data.Root[:], so1.data.Root[:])
	}
	if !bytes.Equal(so0.CodeHash(), so1.CodeHash()) {
		t.Fatalf("CodeHash mismatch: have %v, want %v", so0.CodeHash(), so1.CodeHash())
	}
	if !bytes.Equal(so0.code, so1.code) {
		t.Fatalf("Code mismatch: have %v, want %v", so0.code, so1.code)
	}

	if len(so1.dirtyStorage) != len(so0.dirtyStorage) {
		t.Errorf("Dirty storage size mismatch: have %d, want %d", len(so1.dirtyStorage), len(so0.dirtyStorage))
	}
	for k, v := range so1.dirtyStorage {
		if so0.dirtyStorage[k] != v {
			t.Errorf("Dirty storage key %x mismatch: have %v, want %v", k, so0.dirtyStorage[k], v)
		}
	}
	for k, v := range so0.dirtyStorage {
		if so1.dirtyStorage[k] != v {
			t.Errorf("Dirty storage key %x mismatch: have %v, want none.", k, v)
		}
	}
	if len(so1.originStorage) != len(so0.originStorage) {
		t.Errorf("Origin storage size mismatch: have %d, want %d", len(so1.originStorage), len(so0.originStorage))
	}
	for k, v := range so1.originStorage {
		if so0.originStorage[k] != v {
			t.Errorf("Origin storage key %x mismatch: have %v, want %v", k, so0.originStorage[k], v)
		}
	}
	for k, v := range so0.originStorage {
		if so1.originStorage[k] != v {
			t.Errorf("Origin storage key %x mismatch: have %v, want none.", k, v)
		}
	}
}

func produceState() (Database, common.Hash) {
	//dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	dir, err := filepath.Abs(os.Getenv("GOPATH"))
	if err != nil {
		log.Fatal(err)
	}

	allpath := dir + "state_test"
	log.Print("path: ", allpath)

	_, err = os.Stat(allpath)
	if err == nil {
		os.RemoveAll(allpath)
	} else if !(os.IsNotExist(err)) {
		os.RemoveAll(allpath)
	}

	db, err := youdb.NewLDBDatabase(allpath, 0, 0)
	if err != nil {
		log.Panic("failed to create test database: ", err)

	}

	rootaddr := common.HexToAddress("ABCDEFG")
	sdb := NewDatabase(db)
	statedb, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, sdb)
	statedb.AddBalance(rootaddr, big.NewInt(100000000))

	root, valRoot, stakingRoot := statedb.IntermediateRoot(false)
	statedb.Commit(true)
	statedb.Database().TrieDB().Commit(root, true)
	statedb.Database().TrieDB().Commit(valRoot, true)
	statedb.Database().TrieDB().Commit(stakingRoot, true)

	rr = root

	root = produceAllState(sdb, root, 2)

	return sdb, root
}

func produceAllState(db Database, root common.Hash, blockCount int) common.Hash {
	temproot := root
	for i := 0; i < blockCount; i++ {
		baddr := bytes.NewBuffer([]byte("095e7baea6a6c7c4c2dfeb977efac326af552d87"))
		//addr := baddr.String() + strconv.Itoa(i)

		statedb, _ := New(temproot, common.Hash{}, common.Hash{}, db)
		//log.Println("state root: ", temproot)
		for j := 0; j < 10; j++ {
			addr := baddr.String() + strconv.Itoa(i) + strconv.Itoa(j)
			statedb.AddBalance(common.HexToAddress(addr), big.NewInt(100000000))
		}

		statedb.Commit(true)
		statedb.Database().TrieDB().Commit(temproot, true)
		temproot, _, _ = statedb.IntermediateRoot(false)
	}

	return temproot
}

var (
	rr = common.Hash{}
)

func getSet(root common.Hash, db Database) (mapset.Set, Dump) {
	statedb, _ := New(root, common.Hash{}, common.Hash{}, db)
	dump := statedb.RawDump()
	set := mapset.NewSet()

	for k, _ := range dump.Accounts {
		set.Add(k)
	}

	return set, dump
}

func TestDump(t *testing.T) {
	db, root := produceState()
	t.Log(root.String())
	statedb, _ := New(root, common.Hash{}, common.Hash{}, db)
	dump := statedb.RawDump()
	t.Log(len(dump.Accounts))

	for k, v := range dump.Accounts {
		value := v.Balance
		t.Log("addr: ", k, " v: ", value)
	}
}

func TestDifference(t *testing.T) {
	db, root := produceState()
	t.Log(root.String())

	currentset, cdump := getSet(root, db)
	previouset, pdump := getSet(rr, db)

	for k, v := range cdump.Accounts {
		value := v.Balance
		t.Log("addr: ", k, " v: ", value)
	}
	t.Log(len(cdump.Accounts))

	t.Log("+++++++++++++++++++++++")
	for k, v := range pdump.Accounts {
		value := v.Balance
		t.Log("addr: ", k, " v: ", value)
	}
	t.Log(len(pdump.Accounts))

	dset := currentset.Difference(previouset)

	t.Log(dset)
}
