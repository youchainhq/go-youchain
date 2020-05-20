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

type LookBackType uint8

const (
	LookBackNone LookBackType = iota
	LookBackPos
	LookBackSeed
	LookBackStake
	LookBackCert
	LookBackCertSeed
	LookBackCertStake

	MaxVoteCacheCount int = 4
)

func TurnToStakeType(backType LookBackType) LookBackType {
	switch backType {
	case LookBackPos:
		fallthrough
	case LookBackStake:
		fallthrough
	case LookBackSeed:
		return LookBackStake
	case LookBackCert:
		fallthrough
	case LookBackCertStake:
		fallthrough
	case LookBackCertSeed:
		return LookBackCertStake
	}
	return LookBackNone
}

func TurnToSeedType(backType LookBackType) LookBackType {
	switch backType {
	case LookBackPos:
		fallthrough
	case LookBackStake:
		fallthrough
	case LookBackSeed:
		return LookBackSeed
	case LookBackCert:
		fallthrough
	case LookBackCertStake:
		fallthrough
	case LookBackCertSeed:
		return LookBackCertSeed
	}
	return LookBackNone
}
