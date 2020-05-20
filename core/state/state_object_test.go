package state

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/rlp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
)

func TestStateObject_AddDelegationIfNotExist(t *testing.T) {
	st := &StateDB{
		journal: newJournal(),
	}
	obj := &stateObject{db: st}

	// first
	a1 := common.BytesToAddress([]byte{1})
	obj.UpdateDelegationTo(a1, false)
	require.Equal(t, 1, obj.delegations.Len())
	require.Equal(t, a1, obj.delegations[0])

	// append to last
	a3 := common.BytesToAddress([]byte{3})
	obj.UpdateDelegationTo(a3, false)
	require.Equal(t, 2, obj.delegations.Len())
	require.Equal(t, a1, obj.delegations[0])
	require.Equal(t, a3, obj.delegations[1])

	// insert to middle
	a2 := common.BytesToAddress([]byte{2})
	obj.UpdateDelegationTo(a2, false)
	require.Equal(t, 3, obj.delegations.Len())
	require.Equal(t, a1, obj.delegations[0])
	require.Equal(t, a2, obj.delegations[1])
	require.Equal(t, a3, obj.delegations[2])

	// insert to first
	a0 := common.BytesToAddress([]byte{0})
	obj.UpdateDelegationTo(a0, false)
	require.Equal(t, 4, obj.delegations.Len())
	require.Equal(t, a0, obj.delegations[0])
	require.Equal(t, a1, obj.delegations[1])
	require.Equal(t, a2, obj.delegations[2])
	require.Equal(t, a3, obj.delegations[3])

	// an exist one should not be add again
	obj.UpdateDelegationTo(a2, false)
	require.Equal(t, 4, obj.delegations.Len())
	require.Equal(t, a0, obj.delegations[0])
	require.Equal(t, a1, obj.delegations[1])
	require.Equal(t, a2, obj.delegations[2])
	require.Equal(t, a3, obj.delegations[3])

	// delete
	obj.UpdateDelegationTo(a2, true)
	require.Equal(t, 3, obj.delegations.Len())
	require.Equal(t, a0, obj.delegations[0])
	require.Equal(t, a1, obj.delegations[1])
	require.Equal(t, a3, obj.delegations[2])

	obj.UpdateDelegationTo(a3, true)
	require.Equal(t, 2, obj.delegations.Len())
	require.Equal(t, a0, obj.delegations[0])
	require.Equal(t, a1, obj.delegations[1])

	obj.UpdateDelegationTo(a0, true)
	require.Equal(t, 1, obj.delegations.Len())
	require.Equal(t, a1, obj.delegations[0])
}

func TestStateObject_Delegations(t *testing.T) {
	var dlgs common.SortedAddresses
	dlgs = append(dlgs, common.Address{0x11, 0x22, 0x33, 0x44, 0x55})
	bs, err := rlp.EncodeToBytes(dlgs)
	require.NoError(t, err)
	fmt.Println("bs: ", hexutil.Encode(bs))

	r := new(common.SortedAddresses)
	err = rlp.DecodeBytes(bs, r)
	require.NoError(t, err)
	require.Equal(t, dlgs.Len(), r.Len())
	require.Equal(t, dlgs[0].String(), (*r)[0].String())
}
