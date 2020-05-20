// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
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

package node

import (
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/params"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/monitor"
	"github.com/youchainhq/go-youchain/rpc"

	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/p2p"
)

type Node struct {
	eventMux *event.TypeMux
	config   *Config

	serverConfig p2p.Config
	server       *p2p.Server

	serverFuncs []ServiceConstructor
	servers     map[reflect.Type]Service

	rpcAPIs       []rpc.API   // List of APIs currently provided by the node
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests

	ipcEndpoint string       // IPC endpoint to listen at (empty = IPC disabled)
	ipcListener net.Listener // IPC RPC listener socket to serve API requests
	ipcHandler  *rpc.Server  // IPC RPC request handler to process the API requests

	httpEndpoint  string       // HTTP endpoint (interface + port) to listen at (empty = HTTP disabled)
	httpWhitelist []string     // HTTP RPC modules to allow through this endpoint
	httpServer    *http.Server // HTTP RPC listener socket to server API requests
	httpListener  net.Listener // HTTP RPC listener socket to server API requests
	httpHandler   *rpc.Server  // HTTP RPC request handler to process the API requests

	wsEndpoint string       // Websocket endpoint (interface + port) to listen at (empty = websocket disabled)
	wsServer   *http.Server // Websocket RPC listener socket to server API requests
	wsListener net.Listener // Websocket RPC listener socket to server API requests
	wsHandler  *rpc.Server  // Websocket RPC request handler to process the API requests

	stop chan struct{}
	lock sync.RWMutex
}

func New(conf *Config) (*Node, error) {
	confCopy := *conf
	conf = &confCopy

	if conf.DataDir != "" {
		absdatadir, err := filepath.Abs(conf.DataDir)
		if err != nil {
			return nil, err
		}
		conf.DataDir = absdatadir
	}
	if strings.ContainsAny(conf.Name, `/\`) {
		return nil, errors.New(`Config.Name must not contain '/' or '\'`)
	}
	if conf.Name == datadirDefaultKeyStore {
		return nil, errors.New(`Config.Name cannot be "` + datadirDefaultKeyStore + `"`)
	}
	if strings.HasSuffix(conf.Name, ".ipc") {
		return nil, errors.New(`Config.Name cannot end in ".ipc"`)
	}

	return &Node{
		config:      conf,
		serverFuncs: []ServiceConstructor{},
		eventMux:    new(event.TypeMux),
		ipcEndpoint: conf.IPCEndpoint(),
	}, nil
}

func (n *Node) Register(constructor ServiceConstructor) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.server != nil {
		return ErrNodeRunning
	}

	n.serverFuncs = append(n.serverFuncs, constructor)
	return nil
}

func (n *Node) Start() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	logging.Info("Node Start...")

	if n.server != nil {
		return ErrNodeRunning
	}

	if err := n.openDataDir(); err != nil {
		return err
	}

	n.serverConfig = n.config.P2P
	n.serverConfig.PrivateKey = n.config.NodeKey()
	n.serverConfig.Name = n.config.NodeName()
	if n.serverConfig.StaticNodes == nil {
		n.serverConfig.StaticNodes = n.config.StaticNodes()
	}

	if n.serverConfig.TrustedNodes == nil {
		n.serverConfig.TrustedNodes = n.config.TrustedNodes()
	}
	if n.serverConfig.NodeDatabase == "" {
		n.serverConfig.NodeDatabase = n.config.NodeDB()
	}
	if n.serverConfig.BlacklistDatabase == "" {
		n.serverConfig.BlacklistDatabase = n.config.BlacklistDB()
	}
	running := &p2p.Server{Config: n.serverConfig}

	logging.Info("Starting peer-to-peer node", "instance", n.serverConfig.Name)

	// Otherwise copy and specialize the P2P configuration
	services := make(map[reflect.Type]Service)
	for _, constructor := range n.serverFuncs {
		// Create a new context for the particular service
		ctx := &ServiceContext{
			config:   n.config,
			services: make(map[reflect.Type]Service),
			EventMux: n.eventMux,
		}
		for kind, s := range services { // copy needed for threaded access
			ctx.services[kind] = s
		}
		// Construct and save the service
		service, err := constructor(ctx)
		if err != nil {
			return err
		}
		kind := reflect.TypeOf(service)
		if _, exists := services[kind]; exists {
			return &DuplicateServiceError{Kind: kind}
		}
		services[kind] = service
	}

	for _, service := range services {
		running.Protocols = append(running.Protocols, service.Protocols()...)
	}

	if n.serverConfig.EnableMsgEvents {
		mnt := monitor.Start()
		sub := running.SubscribeEvents(mnt)
		monitor.SetSubscription(sub)
	}

	if err := running.Start(); err != nil {
		return convertFileLockError(err)
	}
	started := make([]reflect.Type, 0)
	for kind, service := range services {
		logging.Info("Start service", "kind", kind)
		// Start the next service, stopping all previous upon failure
		if err := service.Start(running); err != nil {
			logging.Error("service start failed", "service", service, "err", err)
			for _, kind := range started {
				services[kind].Stop()
			}
			running.Stop()

			return err
		}
		logging.Info("Service started", "kind", kind)
		// Mark the service started for potential cleanup
		started = append(started, kind)
	}
	//// Lastly start the configured RPC interfaces
	//if err := n.startRPC(services); err != nil {
	//	for _, service := range services {
	//		service.Stop()
	//	}
	//	running.Stop()
	//	return err
	//}
	n.servers = services
	n.server = running
	n.stop = make(chan struct{})
	return nil
}

func (n *Node) GetP2pServer() *p2p.Server {
	return n.server
}

func (n *Node) openDataDir() error {
	if n.config.DataDir == "" {
		return nil // ephemeral
	}
	logging.Info("openDataDir", "data_dir", n.config.DataDir)
	if _, err := os.Stat(n.config.DataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(n.config.DataDir, 0700); err != nil {
			logging.Error("openDataDir", "err", err)
		}
	}
	instdir := filepath.Join(n.config.DataDir, n.config.name())
	if err := os.MkdirAll(instdir, 0700); err != nil {
		return err
	}
	return nil
}

func (n *Node) Wait() {
	n.lock.RLock()
	if n.server == nil {
		n.lock.RUnlock()
		return
	}
	stop := n.stop
	n.lock.RUnlock()

	<-stop
}

func (n *Node) Stop() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	// Short circuit if the node's not running
	if n.server == nil {
		return ErrNodeStopped
	}

	failure := &StopError{
		Services: make(map[reflect.Type]error),
	}
	for kind, service := range n.servers {
		if err := service.Stop(); err != nil {
			failure.Services[kind] = err
		}
	}
	n.server.Stop()
	n.servers = nil

	//@wei.ni
	if n.server.EnableMsgEvents {
		monitor.Stop()
		monitor.Unsubscription()
	}

	n.server = nil

	n.stopIPC()
	n.stopInProc()
	n.stopHTTP()
	n.stopWS()

	// unblock n.Wait
	close(n.stop)

	// Remove the keystore if it was created ephemerally.
	if len(failure.Services) > 0 {
		return failure
	}
	return nil
}

// Server retrieves the currently running P2P network layer. This method is meant
// only to inspect fields of the currently running server, life cycle management
// should be left to this Node entity.
func (n *Node) Server() *p2p.Server {
	n.lock.RLock()
	defer n.lock.RUnlock()

	return n.server
}

func (n *Node) StartWS(host *string, port *int, allowedOrigins *string, apis *string) (bool, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.wsHandler != nil {
		return false, fmt.Errorf("WebSocket RPC already running on %s", n.wsEndpoint)
	}

	config := n.config.RPC
	if host == nil {
		h := params.DefaultWSHost
		if config.WSHost != "" {
			h = config.WSHost
		}
		host = &h
	}
	if port == nil {
		port = &config.WSPort
	}

	origins := config.WSOrigins
	if allowedOrigins != nil {
		origins = nil
		for _, origin := range strings.Split(*allowedOrigins, ",") {
			origins = append(origins, strings.TrimSpace(origin))
		}
	}

	modules := config.WSModules
	if apis != nil {
		modules = nil
		for _, m := range strings.Split(*apis, ",") {
			modules = append(modules, strings.TrimSpace(m))
		}
	}

	if err := n.startWS(fmt.Sprintf("%s:%d", *host, *port), n.rpcAPIs, modules, origins); err != nil {
		return false, err
	}
	return true, nil

}

func (n *Node) StartHTTP(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.httpHandler != nil {
		return false, fmt.Errorf("HTTP RPC already running on %s", n.httpEndpoint)
	}
	config := n.config.RPC
	if host == nil {
		h := params.DefaultHTTPHost
		if config.HTTPHost != "" {
			h = config.HTTPHost
		}
		host = &h
	}
	if port == nil {
		port = &config.HTTPPort
	}

	allowedOrigins := config.HTTPCors
	if cors != nil {
		allowedOrigins = nil
		for _, origin := range strings.Split(*cors, ",") {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(origin))
		}
	}

	allowedVHosts := config.HTTPVirtualHosts
	if vhosts != nil {
		allowedVHosts = nil
		for _, vhost := range strings.Split(*host, ",") {
			allowedVHosts = append(allowedVHosts, strings.TrimSpace(vhost))
		}
	}

	modules := n.httpWhitelist
	if apis != nil {
		modules = nil
		for _, m := range strings.Split(*apis, ",") {
			modules = append(modules, strings.TrimSpace(m))
		}
	}

	if err := n.startHTTP(fmt.Sprintf("%s:%d", *host, *port), n.rpcAPIs, modules, allowedOrigins, allowedVHosts, rpc.DefaultHTTPTimeouts); err != nil {
		return false, err
	}
	return true, nil
}

// startHTTP initializes and starts the HTTP RPC endpoint.
func (n *Node) startHTTP(endpoint string, apis []rpc.API, modules []string, cors []string, vhosts []string, timeouts rpc.HTTPTimeouts) error {
	// Short circuit if the HTTP endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	server, listener, handler, err := rpc.StartHTTPEndpoint(endpoint, apis, modules, cors, vhosts, timeouts)
	if err != nil {
		return err
	}
	logging.Info("HTTP endpoint opened", "url", fmt.Sprintf("http://%s", listener.Addr()))
	// All listeners booted successfully
	n.httpEndpoint = endpoint
	n.httpServer = server
	n.httpListener = listener
	n.httpHandler = handler

	return nil
}

// stopHTTP terminates the HTTP RPC endpoint.
func (n *Node) stopHTTP() {
	if n.httpListener != nil {
		n.httpListener.Close()
		n.httpListener = nil

		logging.Info("HTTP endpoint closed", "url", fmt.Sprintf("http://%s", n.httpEndpoint))
	}
	if n.httpHandler != nil {
		n.httpHandler.Stop()
		n.httpHandler = nil
	}
	if n.httpServer != nil {
		n.httpServer.Close()
		n.httpServer = nil
	}
}

// startRPC is a helper method to start all the various RPC endpoint during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
func (n *Node) StartRPC(apis []rpc.API) error {
	cfg := n.config.RPC

	if err := n.startInProc(apis); err != nil {
		return err
	}
	if err := n.startIPC(apis); err != nil {
		n.stopInProc()
		return err
	}

	//http
	endpoint := fmt.Sprintf("%s:%d", cfg.HTTPHost, cfg.HTTPPort)
	if err := n.startHTTP(endpoint, apis, cfg.HTTPModules, cfg.HTTPCors, cfg.HTTPVirtualHosts, rpc.DefaultHTTPTimeouts); err != nil {
		n.stopIPC()
		n.stopInProc()
		return err
	}

	// ws
	wsEndpoint := fmt.Sprintf("%s:%d", cfg.WSHost, cfg.WSPort)
	if err := n.startWS(wsEndpoint, apis, cfg.WSModules, cfg.WSOrigins); err != nil {
		n.stopIPC()
		n.stopInProc()
		n.stopHTTP()
		return err
	}

	// All API endpoints started successfully
	n.rpcAPIs = apis
	return nil
}

// StopRPC terminates an already running HTTP RPC API endpoint.
func (n *Node) StopRPC() (bool, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.httpHandler == nil {
		return false, fmt.Errorf("HTTP RPC not running")
	}
	n.stopHTTP()
	return true, nil
}

// startInProc initializes an in-process RPC endpoint.
func (n *Node) startInProc(apis []rpc.API) error {
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
		logging.Infof("InProc registered %T under '%s'", api.Service, api.Namespace)
	}
	n.inprocHandler = handler
	return nil
}

// stopInProc terminates the in-process RPC endpoint.
func (n *Node) stopInProc() {
	if n.inprocHandler != nil {
		n.inprocHandler.Stop()
		n.inprocHandler = nil
	}
}

// startIPC initializes and starts the IPC RPC endpoint.
func (n *Node) startIPC(apis []rpc.API) error {
	// Short circuit if the IPC endpoint isn't being exposed
	if n.ipcEndpoint == "" {
		return nil
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
		logging.Info("InProc registered", "service", api.Service, "namespace", api.Namespace)
	}
	// All APIs registered, start the IPC listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = rpc.CreateIPCListener(n.ipcEndpoint); err != nil {
		return err
	}
	go func() {
		logging.Info("IPC endpoint opened", "endpoint", n.ipcEndpoint)

		for {
			conn, err := listener.Accept()
			if err != nil {
				// Terminate if the listener was closed
				n.lock.RLock()
				closed := n.ipcListener == nil
				n.lock.RUnlock()
				if closed {
					return
				}
				// Not closed, just some error; report and continue
				logging.Info("IPC accept failed", "err", err)
				continue
			}
			go handler.ServeCodec(rpc.NewJSONCodec(conn), rpc.OptionMethodInvocation|rpc.OptionSubscriptions)
		}
	}()
	// All listeners booted successfully
	n.ipcListener = listener
	n.ipcHandler = handler

	return nil
}

// stopIPC terminates the IPC RPC endpoint.
func (n *Node) stopIPC() {
	if n.ipcListener != nil {
		n.ipcListener.Close()
		n.ipcListener = nil

		logging.Info("IPC endpoint closed", "endpoint", n.ipcEndpoint)
	}
	if n.ipcHandler != nil {
		n.ipcHandler.Stop()
		n.ipcHandler = nil
	}
}

// startWS initializes and starts the websocket RPC endpoint.
func (n *Node) startWS(endpoint string, apis []rpc.API, modules []string, wsOrigins []string) error {
	// Short circuit if the WS endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	server, listener, handler, err := rpc.StartWSEndpoint(endpoint, apis, modules, wsOrigins)
	if err != nil {
		return err
	}
	logging.Info("WebSocket endpoint opened", "url", fmt.Sprintf("ws://%s", listener.Addr()))
	// All listeners booted successfully
	n.wsEndpoint = endpoint
	n.wsServer = server
	n.wsListener = listener
	n.wsHandler = handler

	return nil
}

// stopWS terminates the websocket RPC endpoint.
func (n *Node) StopWS() (bool, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.wsHandler == nil {
		return false, fmt.Errorf("WebSocket RPC not running")
	}
	n.stopWS()
	return true, nil
}

// stopWS terminates the websocket RPC endpoint.
func (n *Node) stopWS() (bool, error) {
	if n.wsHandler == nil {
		return false, fmt.Errorf("WebSocket RPC not running")
	}

	if n.wsListener != nil {
		n.wsListener.Close()
		n.wsListener = nil

		logging.Info("WebSocket endpoint closed", "url", fmt.Sprintf("ws://%s", n.wsEndpoint))
	}
	if n.wsHandler != nil {
		n.wsHandler.Stop()
		n.wsHandler = nil
	}
	if n.wsServer != nil {
		n.wsServer.Close()
		n.wsServer = nil
	}
	return true, nil
}

// Attach creates an RPC client attached to an in-process API handler.
func (n *Node) Attach() (*rpc.Client, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	if n.server == nil {
		return nil, ErrNodeStopped
	}
	return rpc.DialInProc(n.inprocHandler), nil
}

// apis returns the collection of RPC descriptors this node offers.
func (n *Node) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminApi(n),
			Public:    false,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPublicAdminApi(n),
			Public:    true,
		}, {
			Namespace: "youchain",
			Version:   "1.0",
			Service:   NewPublicNodeApi(n),
			Public:    true,
		},
		{
			Namespace: "net",
			Service:   NewPublicNetApi(n),
			Public:    true,
		},
	}
}
