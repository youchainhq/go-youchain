package core

import (
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/logging"
)

// Message represents a message to be applied to a state
type Message interface {
	From() common.Address
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	TxHash() common.Hash
	CheckNonce() bool
	Data() []byte
}

// MessageContext is the current context for applying a message
type MessageContext struct {
	Msg          Message
	State        *state.StateDB
	InitialGas   uint64
	AvailableGas uint64
	Header       *types.Header
	Coinbase     common.Address
	Chain        ChainContext
	GP           *GasPool
	Cfg          *vm.Config
}

func NewMsgContext(msg Message, statedb *state.StateDB, bc ChainContext, header *types.Header, coinBase common.Address, gp *GasPool, cfg *vm.Config) *MessageContext {
	return &MessageContext{
		Msg:          msg,
		State:        statedb,
		InitialGas:   0,
		AvailableGas: 0,
		Header:       header,
		Coinbase:     coinBase,
		Chain:        bc,
		GP:           gp,
		Cfg:          cfg,
	}
}

// preCheck checks the nonce and buy the supplied gas before applying the message
func (mc *MessageContext) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if mc.Msg.CheckNonce() {
		nonce := mc.State.GetNonce(mc.Msg.From())
		if nonce < mc.Msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > mc.Msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return mc.buyGas()
}

func (mc *MessageContext) buyGas() error {
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(mc.Msg.Gas()), mc.Msg.GasPrice())
	from := mc.Msg.From()
	if mc.State.GetBalance(from).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := mc.GP.SubGas(mc.Msg.Gas()); err != nil {
		return err
	}
	mc.AvailableGas = mc.Msg.Gas()
	mc.InitialGas = mc.Msg.Gas()
	mc.State.SubBalance(from, mgval)
	logging.Trace("buyGas", "from", from.String(), "payLu", mgval, "balance", mc.State.GetBalance(from), "msgGas", mc.Msg.Gas(), "gasPrice", mc.Msg.GasPrice(), "availableGas", mc.AvailableGas)
	return nil
}

func (mc *MessageContext) UseGas(amount uint64) error {
	if mc.AvailableGas < amount {
		logging.Error("vm.ErrOutOfGas", "availableGas", mc.AvailableGas, "amount", amount)
		return vm.ErrOutOfGas
	}
	mc.AvailableGas -= amount
	logging.Trace("useGas", "from", mc.Msg.From().String(), "tx", mc.Msg.TxHash().String(), "amount", amount, "availableGas", mc.AvailableGas)
	return nil
}

func (mc *MessageContext) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	refund := mc.GasUsed() / 2
	if refund > mc.State.GetRefund() {
		refund = mc.State.GetRefund()
	}
	mc.AvailableGas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(mc.AvailableGas), mc.Msg.GasPrice())
	mc.State.AddBalance(mc.Msg.From(), remaining)
	logging.Debug("refundGas", "from", mc.Msg.From().String(), "remaining", remaining, "gasUsed", mc.GasUsed())

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	mc.GP.AddGas(mc.AvailableGas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (mc *MessageContext) GasUsed() uint64 {
	return mc.InitialGas - mc.AvailableGas
}
