// Copyright 2017 The go-ethereum Authors
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

package consensus

import "errors"

var (
	// ErrUnknownAncestor is returned when validating a block requires an ancestor
	// that is unknown.
	ErrUnknownAncestor = errors.New("unknown ancestor")

	// ErrPrunedAncestor is returned when validating a block requires an ancestor
	// that is known, but the state of which is not available.
	ErrPrunedAncestor = errors.New("pruned ancestor")

	//new block should not older than parent
	ErrOlderBlockTime    = errors.New("timestamp older than parent")

	// ErrFutureBlock is returned when a block's timestamp is in the future according
	// to the current node.
	ErrFutureBlock = errors.New("block in the future")

	// ErrInvalidNumber is returned if a block's number doesn't equal it's parent's
	// plus one.
	ErrInvalidNumber = errors.New("invalid block number")

	// ErrExistCanonical is returned when there is a different block in the canonical chain
	// which with the block's number.
	ErrExistCanonical = errors.New("exist canonical")

	// ErrUnknownParentState is returned when a block's parent state doesn't exist
	ErrUnknownParentState = errors.New("unknown parent state")

	ErrUnknownLookBackValidators = errors.New("unknown look back validators")

	ErrValKeyNotSet = errors.New("validator key not set")
	ErrBlsKeyNotSet = errors.New("validator's bls key not set")

	ErrMismatchCHTRoot = errors.New("mismatch CHT root")
)
