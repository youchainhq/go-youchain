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

package utils

import (
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/params"
	"testing"
)

func TestCheckNatTypeLoop(t *testing.T) {
	//init
	natPublicService = "stun.stunprotocol.org:3478,stun.ekiga.net:3478" // first use default
	natMasterAddr = "42.62.25.77:45521"
	natSlaveAddr = "42.62.25.79:45523"
	defer func() {
		natPublicService = ""
		natMasterAddr = ""
		natSlaveAddr = ""
	}()
	var err error
	natType := enode.NATUnknown

	logging.Info("start Nat check", "p2p port", params.DefaultP2PListenPort, "discover port", params.DefaultP2PDiscoverPort)
	natType, err = checkNatTypeLoop(params.DefaultP2PListenPort, params.DefaultP2PDiscoverPort, false)
	if err != nil {
		logging.Error("Nat check failed from public service", "err", err)
	}

	if natType == enode.NATUnknown {
		logging.Info("start nat check from you-natserver")
		natType, err = checkNatTypeLoop(params.DefaultP2PListenPort, params.DefaultP2PDiscoverPort, true)
		if err != nil {
			logging.Error("Nat check failed", "err", err)
		}
	}
	require.NoError(t, err)
	require.NotEqual(t, enode.NATUnknown, natType)
	logging.Info("nat type", "nat", natType)
}
