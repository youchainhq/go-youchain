// Copyright 2015 The go-ethereum Authors
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

// package web3ext contains geth specific web3.js extensions.
package web3ext

var Modules = map[string]string{
	"admin":    AdminJs,
	"debug":    DebugJs,
	"you":      YouJs,
	"miner":    MinerJs,
	"net":      NetJs,
	"personal": PersonalJs,
	"rpc":      RpcJs,
	"txpool":   TxpoolJs,
	"dev":      DevJs,
	"youext":   YouExtJs,
}

const AdminJs = `
youchain._extend({
	property: 'admin',
	methods: [
		new youchain._extend.Method({
			name: 'addPeer',
			call: 'admin_addPeer',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'removePeer',
			call: 'admin_removePeer',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'sleepBlocks',
			call: 'admin_sleepBlocks',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'startRPC',
			call: 'admin_startRPC',
			params: 4,
			inputFormatter: [null, null, null, null]
		}),
		new youchain._extend.Method({
			name: 'stopRPC',
			call: 'admin_stopRPC'
		}),
		new youchain._extend.Method({
			name: 'startWS',
			call: 'admin_startWS',
			params: 4,
			inputFormatter: [null, null, null, null]
		}),
		new youchain._extend.Method({
			name: 'stopWS',
			call: 'admin_stopWS'
		}),
		new youchain._extend.Method({
			name: 'blacklist',
			call: 'admin_blacklist'
		}),
		new youchain._extend.Method({
			name: 'clearBlacklistDB',
			call: 'admin_clearBlacklistDB'
		}),
		new youchain._extend.Method({
			name: 'removePeerFromBlacklist',
			call: 'admin_removePeerFromBlacklist'
			params: 2
		}),
	],
	properties: [
		new youchain._extend.Property({
			name: 'nodeInfo',
			getter: 'admin_nodeInfo'
		}),
		new youchain._extend.Property({
			name: 'peers',
			getter: 'admin_peers'
		}),
	]
});
`

const DevJs = `
youchain._extend({
	property: 'dev',
	methods: [
		new youchain._extend.Method({
			name: 'stateDump',
			call: 'dev_stateDump',
		}),
		new youchain._extend.Method({
			name: 'stateDumpByNumber',
			call: 'dev_stateDumpByNumber',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'stateLogDump',
			call: 'dev_stateLogDump',
		}),
		new youchain._extend.Method({
			name: 'setHead',
			call: 'dev_setHead',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'setPrintOrigin',
			call: 'dev_setPrintOrigin',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'verbosity',
			call: 'dev_verbosity',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'vmodule',
			call: 'dev_vmodule',
			params: 1,
			outputFormatter: console.log
		}),
		new youchain._extend.Method({
			name: 'exit',
			call: 'dev_exit',
		}),
		new youchain._extend.Method({
			name: 'stop',
			call: 'dev_stop',
		}),
		new youchain._extend.Method({
			name: 'doubleSign',
			call: 'dev_doubleSign',
			params: 3
		}),
	],
	properties: []
});
`

const DebugJs = `
youchain._extend({
	property: 'debug',
	methods: [
		new youchain._extend.Method({
			name: 'printBlock',
			call: 'debug_printBlock',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'getBlockRlp',
			call: 'debug_getBlockRlp',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'testSignCliqueBlock',
			call: 'debug_testSignCliqueBlock',
			params: 2, 
			inputFormatters: [youchain._extend.formatters.inputAddressFormatter, null],
		}),
		new youchain._extend.Method({
			name: 'setHead',
			call: 'debug_setHead',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'seedHash',
			call: 'debug_seedHash',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'dumpBlock',
			call: 'debug_dumpBlock',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'chaindbProperty',
			call: 'debug_chaindbProperty',
			params: 1,
			outputFormatter: console.log
		}),
		new youchain._extend.Method({
			name: 'chaindbCompact',
			call: 'debug_chaindbCompact',
		}),
		new youchain._extend.Method({
			name: 'metrics',
			call: 'debug_metrics',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'verbosity',
			call: 'debug_verbosity',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'vmodule',
			call: 'debug_vmodule',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'backtraceAt',
			call: 'debug_backtraceAt',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'stacks',
			call: 'debug_stacks',
			params: 0,
			outputFormatter: console.log
		}),
		new youchain._extend.Method({
			name: 'freeOSMemory',
			call: 'debug_freeOSMemory',
			params: 0,
		}),
		new youchain._extend.Method({
			name: 'setGCPercent',
			call: 'debug_setGCPercent',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'memStats',
			call: 'debug_memStats',
			params: 0,
		}),
		new youchain._extend.Method({
			name: 'gcStats',
			call: 'debug_gcStats',
			params: 0,
		}),
		new youchain._extend.Method({
			name: 'cpuProfile',
			call: 'debug_cpuProfile',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'startCPUProfile',
			call: 'debug_startCPUProfile',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'stopCPUProfile',
			call: 'debug_stopCPUProfile',
			params: 0
		}),
		new youchain._extend.Method({
			name: 'goTrace',
			call: 'debug_goTrace',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'startGoTrace',
			call: 'debug_startGoTrace',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'stopGoTrace',
			call: 'debug_stopGoTrace',
			params: 0
		}),
		new youchain._extend.Method({
			name: 'blockProfile',
			call: 'debug_blockProfile',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'setBlockProfileRate',
			call: 'debug_setBlockProfileRate',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'writeBlockProfile',
			call: 'debug_writeBlockProfile',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'mutexProfile',
			call: 'debug_mutexProfile',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'setMutexProfileFraction',
			call: 'debug_setMutexProfileFraction',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'writeMutexProfile',
			call: 'debug_writeMutexProfile',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'writeMemProfile',
			call: 'debug_writeMemProfile',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'traceBlock',
			call: 'debug_traceBlock',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'traceBlockFromFile',
			call: 'debug_traceBlockFromFile',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'traceBadBlock',
			call: 'debug_traceBadBlock',
			params: 1,
			inputFormatter: [null]
		}),
		new youchain._extend.Method({
			name: 'standardTraceBadBlockToFile',
			call: 'debug_standardTraceBadBlockToFile',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'standardTraceBlockToFile',
			call: 'debug_standardTraceBlockToFile',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'traceBlockByNumber',
			call: 'debug_traceBlockByNumber',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'traceBlockByHash',
			call: 'debug_traceBlockByHash',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'traceTransaction',
			call: 'debug_traceTransaction',
			params: 2,
			inputFormatter: [null, null]
		}),
		new youchain._extend.Method({
			name: 'preimage',
			call: 'debug_preimage',
			params: 1,
			inputFormatter: [null]
		}),
		new youchain._extend.Method({
			name: 'getBadBlocks',
			call: 'debug_getBadBlocks',
			params: 0,
		}),
		new youchain._extend.Method({
			name: 'storageRangeAt',
			call: 'debug_storageRangeAt',
			params: 5,
		}),
		new youchain._extend.Method({
			name: 'getModifiedAccountsByNumber',
			call: 'debug_getModifiedAccountsByNumber',
			params: 2,
			inputFormatter: [null, null],
		}),
		new youchain._extend.Method({
			name: 'getModifiedAccountsByHash',
			call: 'debug_getModifiedAccountsByHash',
			params: 2,
			inputFormatter:[null, null],
		}),
	],
	properties: []
});
`

const YouJs = `
youchain._extend({
	property: 'you',
	methods: [
		new youchain._extend.Method({
			name: 'sign',
			call: 'you_sign',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'signTransaction',
			call: 'you_signTransaction',
			params: 1,
			inputFormatter: [youchain._extend.formatters.inputTransactionFormatter]
		}),
		new youchain._extend.Method({
			name: 'getBlockByNumber',
			call: 'you_getBlockByNumber',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'getBlockByHash',
			call: 'you_getBlockByHash',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'getProof',
			call: 'you_getProof',
			params: 3,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null, youchain._extend.formatters.inputBlockNumberFormatter]
		}),
		new youchain._extend.Method({
			name: 'validators',
			call: 'you_validators',
			params: 4,
			inputFormatter: [null, null, null, youchain._extend.formatters.inputBlockNumberFormatter]
		}),
		new youchain._extend.Method({
			name: 'validatorByMainAddress',
			call: 'you_validatorByMainAddress',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputBlockNumberFormatter, youchain._extend.formatters.inputAddressFormatter]
		}),
		new youchain._extend.Method({
			name: 'validatorsStat',
			call: 'you_validatorsStat',
			params: 1,
			inputFormatter: [youchain._extend.formatters.inputBlockNumberFormatter]
		}),
		new youchain._extend.Method({
			name: 'networkId',
			call: 'you_networkId',
		}),
		new youchain._extend.Method({
			name: 'getFilterChanges',
			call: 'you_getFilterChanges',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'getFilterLogs',
			call: 'you_getFilterLogs',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'getLogs',
			call: 'you_getLogs',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'newFilter',
			call: 'you_newFilter',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'newBlockFilter',
			call: 'you_newBlockFilter',
		}),
		new youchain._extend.Method({
			name: 'newPendingTransactionFilter',
			call: 'you_newPendingTransactionFilter',
		}),
		new youchain._extend.Method({
			name: 'uninstallFilter',
			call: 'you_uninstallFilter',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'getPoolNonce',
			call: 'you_getPoolNonce',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'createValidator',
			call: 'you_createValidator',
			params: 11,
		}),
		new youchain._extend.Method({
			name: 'changeStatusValidator',
			call: 'you_changeStatusValidator',
			params: 3,
		}),
		new youchain._extend.Method({
			name: 'depositValidator',
			call: 'you_depositValidator',
			params: 3,
		}),
		new youchain._extend.Method({
			name: 'withdrawValidator',
			call: 'you_withdrawValidator',
			params: 4,
		}),
		new youchain._extend.Method({
			name: 'settleValidator',
			call: 'you_settleValidator',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'updateValidator',
			call: 'you_updateValidator',
			params: 8,
		}),
		new youchain._extend.Method({
			name: 'getWithdrawRecords',
			call: 'you_getWithdrawRecords',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'getDelegationAddData',
			call: 'you_getDelegationAddData',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'getDelegationSubData',
			call: 'you_getDelegationSubData',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'getDelegationSettleData',
			call: 'you_getDelegationSettleData',
			params: 1,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter]
		}),
		new youchain._extend.Method({
			name: 'getDelegationsFrom',
			call: 'you_getDelegationsFrom',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter,youchain._extend.formatters.inputDefaultBlockNumberFormatter]
		}),
		new youchain._extend.Method({
			name: 'getStakingEndBlockReceipt',
			call: 'you_getStakingEndBlockReceipt',
			params: 1,
		}),
		new youchain._extend.Method({
			name: 'getStakingRecord',
			call: 'you_getStakingRecord',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter,youchain._extend.formatters.inputDefaultBlockNumberFormatter]
		}),
	],
	properties: []
});
`

const MinerJs = `
youchain._extend({
	property: 'miner',
	methods: [
		new youchain._extend.Method({
			name: 'start',
			call: 'miner_start'
		}),
		new youchain._extend.Method({
			name: 'stop',
			call: 'miner_stop'
		}),
		new youchain._extend.Method({
			name: 'setExtra',
			call: 'miner_setExtra',
			params: 1
		}),
		new youchain._extend.Method({
			name: 'setGasPrice',
			call: 'miner_setGasPrice',
			params: 1,
			inputFormatter: [youchain._extend.utils.fromDecimal]
		}),
	],
	properties: []
});
`

const NetJs = `
youchain._extend({
	property: 'net',
	methods: [
	],
	properties: [
		new youchain._extend.Property({
			name: 'version',
			getter: 'net_version'
		}),
	]
});
`

const PersonalJs = `
youchain._extend({
	property: 'personal',
	methods: [
		new youchain._extend.Method({
			name: 'importRawKey',
			call: 'personal_importRawKey',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'sign',
			call: 'personal_sign',
			params: 3,
			inputFormatter: [null, youchain._extend.formatters.inputAddressFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'ecRecover',
			call: 'personal_ecRecover',
			params: 2
		}),
		new youchain._extend.Method({
			name: 'signTransaction',
			call: 'personal_signTransaction',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputTransactionFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'newValKey',
			call: 'personal_newValKey',
			params: 1,
			inputFormatter: [null]
		}),
		new youchain._extend.Method({
			name: 'useValKey',
			call: 'personal_useValKey',
			params: 3,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null, null]
		}),
		new youchain._extend.Method({
			name: 'exportValKey',
			call: 'personal_exportValKey',
			params: 3,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null, null]
		}),
		new youchain._extend.Method({
			name: 'importValKey',
			call: 'personal_importValKey',
			params: 3
		}),
		new youchain._extend.Method({
			name: 'delValKey',
			call: 'personal_delValKey',
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'lockValKey',
			call: 'personal_lockValKey'
		}),
		new youchain._extend.Method({
			name: 'exportKeyJson',
			call: 'personal_exportKeyJson'
			params: 3,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null, null]
		}),
		new youchain._extend.Method({
			name: 'exportRawKey',
			call: 'personal_exportRawKey'
			params: 2,
			inputFormatter: [youchain._extend.formatters.inputAddressFormatter, null]
		}),
		new youchain._extend.Method({
			name: 'importKeyJson',
			call: 'personal_importKeyJson'
			params: 3,
		}),
	],
	properties: []
})
`

const RpcJs = `
youchain._extend({
	property: 'rpc',
	methods: [],
	properties: [
		new youchain._extend.Property({
			name: 'modules',
			getter: 'rpc_modules'
		}),
	]
});
`

const TxpoolJs = `
youchain._extend({
	property: 'txpool',
	methods: [],
	properties:
	[
		new youchain._extend.Property({
			name: 'content',
			getter: 'txpool_content'
		}),
		new youchain._extend.Property({
			name: 'inspect',
			getter: 'txpool_inspect'
		}),
		new youchain._extend.Property({
			name: 'status',
			getter: 'txpool_status',
			outputFormatter: function(status) {
				status.pending = youchain._extend.utils.toDecimal(status.pending);
				status.queued = youchain._extend.utils.toDecimal(status.queued);
				return status;
			}
		}),
	]
});
`

const YouExtJs = `
youchain._extend({
	property: 'youext',
	methods: [
		new youchain._extend.Method({
			name: 'getExtDetail',
			call: 'youext_getExtDetail',
			params: 1,
			inputFormatter: [youchain._extend.formatters.inputBlockNumberFormatter]
		}),
		new youchain._extend.Method({
			name: 'getExtDetailByHash',
			call: 'youext_getExtDetailByHash',
			params: 1
		}),
	],
	properties: []
});
`
