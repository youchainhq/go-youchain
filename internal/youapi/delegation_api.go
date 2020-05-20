package youapi

import (
	"context"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/staking"
)

func (y *PublicMainApi) GetDelegationAddData(ctx context.Context, toValidator common.Address, value hexutil.Big) (hexutil.Bytes, error) {
	return y.getDelegationData(ctx, &toValidator, &value, staking.DelegationAdd)
}

func (y *PublicMainApi) GetDelegationSubData(ctx context.Context, toValidator common.Address, value hexutil.Big) (hexutil.Bytes, error) {
	return y.getDelegationData(ctx, &toValidator, &value, staking.DelegationSub)
}

func (y *PublicMainApi) GetDelegationSettleData(ctx context.Context, toValidator common.Address) (hexutil.Bytes, error) {
	d := &staking.TxDelegationSettle{
		Validator: toValidator,
	}
	return staking.EncodeMessage(staking.DelegationSettle, d)
}

func (y *PublicMainApi) getDelegationData(ctx context.Context, toValidator *common.Address, value *hexutil.Big, action staking.ActionType) (hexutil.Bytes, error) {
	d := &staking.TxDelegation{
		Validator: *toValidator,
		Value:     value.ToInt(),
	}
	return staking.EncodeMessage(action, d)
}

func (y *PublicMainApi) GetDelegationsFrom(ctx context.Context, delegator common.Address, blockNr rpc.BlockNumber) (map[string]interface{}, error) {
	state, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	dtos, err := state.GetDelegationsFrom(delegator)
	if err != nil {
		return nil, err
	}
	fields := map[string]interface{}{
		"delegator":   delegator,
		"delegations": dtos,
	}
	return fields, nil
}
