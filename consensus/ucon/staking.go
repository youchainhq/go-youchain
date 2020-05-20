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

package ucon

import (
	"errors"
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

func (s *Server) getVldReaderOfBlockHashWithCache(blockHash common.Hash) (state.ValidatorReader, error) {
	header := s.chain.GetHeaderByHash(blockHash)
	if header == nil {
		return nil, errors.New("unknown block")
	}
	if st, ok := s.vldReaderCache.Get(header.ValRoot); ok {
		return st.(state.ValidatorReader), nil
	} else {
		if vld, err := s.chain.GetVldReader(header.ValRoot); err == nil {
			s.vldReaderCache.Add(header.ValRoot, vld)
			return vld, nil
		} else {
			return nil, err
		}
	}
}

func (s *Server) GetValidatorByAddress(blockHash common.Hash, addr common.Address) *state.Validator {
	reader, err := s.getVldReaderOfBlockHashWithCache(blockHash)
	if err != nil {
		logging.Warn("getVldReaderOfBlockHashWithCache", "block", blockHash.String(), "addr", addr.String(), "err", err)
		return nil
	}
	return reader.GetValidatorByMainAddr(addr)
}

// TotalStakeOfKind 获取指定块上某类节点的 total stake
func (s *Server) TotalStakeOfKind(blockHash common.Hash, kind params.ValidatorKind) *big.Int {
	if reader, err := s.getVldReaderOfBlockHashWithCache(blockHash); err == nil {
		stat, err := reader.GetValidatorsStat()
		if err != nil {
			logging.Error("get validator stat failed", "err", err)
			return big.NewInt(0)
		}
		return new(big.Int).Set(stat.GetStakeByKind(kind))
	}
	return big.NewInt(0)
}

// TotalStakeOfKind 获取指定块上某类节点的数量
func (s *Server) ValidatorsNumOfKind(blockHash common.Hash, kind params.ValidatorKind) uint64 {
	if reader, err := s.getVldReaderOfBlockHashWithCache(blockHash); err == nil {
		stat, err := reader.GetValidatorsStat()
		if err != nil {
			logging.Error("get validator stat failed", "err", err)
			return 0
		}
		return stat.GetCountOfKind(kind)
	}
	return 0
}
