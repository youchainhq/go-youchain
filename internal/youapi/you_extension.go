/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * This file is part of the go-youchain library.
 *
 * The go-youchain library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-youchain library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.
 */

package youapi

import (
	"context"
	"errors"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/local"
	"github.com/youchainhq/go-youchain/rpc"
)

// YouExtApi contains some extended apis which are not necessary by default,
// and also these apis should be safe for public.
type YouExtApi struct {
	c *Container
}

func NewYouExtApi(c *Container) *YouExtApi {
	return &YouExtApi{c: c}
}

func (e *YouExtApi) GetExtDetail(ctx context.Context, blockNr rpc.BlockNumber) (*local.Detail, error) {
	block, _ := e.c.BlockByNumber(ctx, blockNr)
	if block == nil {
		return nil, errors.New("block not found")
	}
	return e.GetExtDetailByHash(ctx, block.Hash().String())
}

func (e *YouExtApi) GetExtDetailByHash(ctx context.Context, hash string) (*local.Detail, error) {
	return e.c.youChain.DetailDb().ReadDetail(common.HexToHash(hash)), nil
}
