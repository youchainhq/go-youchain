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

package params

import (
	"github.com/youchainhq/go-youchain/common"
	"math/big"
)

// Node  {
//      Chamber {
//          Chancellor
//          Senator
//      }
//      House
// }

type ValidatorKind uint8
type ValidatorRole uint8

type CurdFlag uint8

const (
	Noop   CurdFlag = iota
	Create          // create, new inserted, new added
	Update
	Delete
)

const (
	// validator kinds
	KindValidator ValidatorKind = 0 // 全体验证人集合的统计
	KindChamber   ValidatorKind = 1 // 全体议员（全体议长+全体议员）
	KindHouse     ValidatorKind = 2 // 众议节点

	// validator roles
	RoleChancellor ValidatorRole = 1 // 议长
	RoleSenator    ValidatorRole = 2 // 议员
	RoleHouse      ValidatorRole = 3 // 众议

	KindNameValidator = "validator"
	KindNameChamber   = "chamber"
	KindNameHouse     = "house"

	RoleNameChancellor = "chancellor"
	RoleNameSenator    = "senator"
	RoleNameHouse      = "house"

	ValidatorOffline uint8 = 0
	ValidatorOnline  uint8 = 1

	// CommissionRateBase is the denominator of commission rate
	CommissionRateBase = 10000

	NotAcceptDelegation uint16 = 0
	AcceptDelegation    uint16 = 1
)

var (
	//StakeUint = new(big.Int).Mul(big.NewInt(1000), big.NewInt(YOU))
	StakeUint = new(big.Int).Mul(big.NewInt(1), big.NewInt(YOU))

	StakingModuleAddress = common.BytesToAddress([]byte(`ValidatorsManager`)) //0x00000056616C696461746f72734D616E61676572

	kinds = map[ValidatorRole]ValidatorKind{
		RoleChancellor: KindChamber,
		RoleSenator:    KindChamber,
		RoleHouse:      KindHouse,
	}
)

func YOUToStake(token *big.Int) *big.Int {
	return new(big.Int).Div(token, StakeUint)
}

func KindOfRole(role ValidatorRole) (ValidatorKind, bool) {
	if kind, ok := kinds[role]; ok {
		return kind, ok
	} else {
		return 0, false
	}
}

func CheckRole(role ValidatorRole) bool {
	if role == RoleHouse || role == RoleSenator || role == RoleChancellor {
		return true
	}
	return false
}

// 只返回大类
func ValidatorKindToString(kind ValidatorKind) string {
	switch kind {
	case KindValidator:
		return KindNameValidator
	case KindChamber:
		return KindNameChamber
	case KindHouse:
		return KindNameHouse
	}
	return "Unknown"
}
