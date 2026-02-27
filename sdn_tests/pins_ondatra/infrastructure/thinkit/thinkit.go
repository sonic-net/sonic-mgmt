// Copyright (c) 2025, Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package thinkit provides the cgo binding for ondatra to thinkit based tests.
package main

/*
#include "infrastructure/thinkit/thinkit_go_interface.h"

*/
import (
	"C"
)

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
	"unsafe"

	log "github.com/golang/glog"

	"github.com/openconfig/gnmi/errlist"

	"github.com/openconfig/ondatra/binding"
	"github.com/openconfig/ondatra/proxy"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/protobuf/proto"

	"github.com/openconfig/ondatra/fakebind"
	opb "github.com/openconfig/ondatra/proto"
	rpb "github.com/openconfig/ondatra/proxy/proto/reservation"
)

func main() {}

func readProto(msg proto.Message, protoIn C.struct_ProtoIn) {
	err := proto.UnmarshalOptions{AllowPartial: true}.Unmarshal(unsafe.Slice((*byte)(unsafe.Pointer(protoIn.data)), (int)(protoIn.length)), msg)
	if err != nil {
		log.Fatalf("Failed to parse proto from byte array from C++; err: %v", err)
	}
}

func writeProto(msg proto.Message, protoOut C.struct_ProtoOut) {
	b, err := proto.MarshalOptions{AllowPartial: true}.Marshal(msg)
	if err != nil {
		log.Fatalf("Failed to marshal proto to byte array for outputing proto to C++; err: %v", err)
	}
	ptr := unsafe.Pointer(unsafe.SliceData(b))
	C.write_proto(protoOut, (*C.char)(ptr), (C.size_t)(len(b)))
}

func writeErrorString(err error, strOut C.struct_StringOut) {
	str := ""
	if err != nil {
		str = err.Error()
	}
	size := len(str)
	ptr := C.resize_string(strOut, (C.size_t)(size))
	if size != 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size), str)
	}
}

//export platforms_networking_pins_ondatra_thinkit_Init
func platforms_networking_pins_ondatra_thinkit_Init(testbedIn C.struct_ProtoIn, waitTime, runTime C.long, errMsg C.struct_StringOut) {
	tb := &opb.Testbed{}
	readProto(tb, testbedIn)
	err := Init(context.TODO(), tb, waitTime, runTime)
	writeErrorString(err, errMsg)
}

//export platforms_networking_pins_ondatra_thinkit_Testbed
func platforms_networking_pins_ondatra_thinkit_Testbed(resvOut C.struct_ProtoOut, errMsg C.struct_StringOut) {
	resv, err := Testbed()
	writeProto(resv, resvOut)
	writeErrorString(err, errMsg)
}

//export platforms_networking_pins_ondatra_thinkit_Release
func platforms_networking_pins_ondatra_thinkit_Release(errMsg C.struct_StringOut) {
	err := Release(context.TODO())
	writeErrorString(err, errMsg)
}

type proxyBinding interface {
	proxy.Dialer
	Reserve(ctx context.Context, tb *opb.Testbed, waitTime time.Duration, runTime time.Duration, partial map[string]string) (*binding.Reservation, error)
	Release(ctx context.Context) error
}

var (
	mu         sync.Mutex
	p          *proxy.Proxy
	resv       *binding.Reservation
	b          proxyBinding
	f          *fakebind.Binding // Used to set the reservation used by Ondatra APIs.
	newBinding = defaultBinding
)

func defaultBinding() (proxyBinding, error) {
	return pinsbind.NewWithOpts()
}

// Init will init the binding and setup the proxy.
func Init(ctx context.Context, tb *opb.Testbed, waitTime, runTime C.long) error {
	mu.Lock()
	defer mu.Unlock()
	if p != nil {
		return fmt.Errorf("proxy already initialized, Init must only be called once")
	}
	var err error
	b, err = newBinding()
	if err != nil {
		return err
	}
	resv, err = b.Reserve(ctx, tb, time.Duration(int64(waitTime)), time.Duration(int64(runTime)), nil)
	if err != nil {
		return err
	}
	p, err = proxy.New(b, grpc.Creds(local.NewCredentials()))

	if err != nil {
		return err
	}

	// Set the reservation for Ondatra APIs.
	f = fakebind.Setup().WithReservation(resv)
	initGoTestHelpers()
	return nil
}

func addProxyTarget(s *rpb.Service, proxyAddr string) error {
	switch v := s.GetEndpoint().(type) {
	case *rpb.Service_ProxiedGrpc:
		v.ProxiedGrpc.Proxy = append([]string{proxyAddr}, v.ProxiedGrpc.Proxy...)
	case *rpb.Service_HttpOverGrpc:
		v.HttpOverGrpc.Address = proxyAddr
	default:
		return fmt.Errorf("invalid service endpoint type: %s:%T (must be proxiable)", s.GetId(), v)
	}
	return nil
}

// Testbed will return the resolved testbed proto.
func Testbed() (*rpb.Reservation, error) {
	mu.Lock()
	defer mu.Unlock()
	if p == nil || b == nil {
		return nil, fmt.Errorf("Init must be called before Testbed()")
	}
	proxyEndpoints := p.Endpoints()
	r, err := b.Resolve()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve reservation: %w", err)
	}
	// Add Proxy to DUT.
	for _, d := range r.GetDevices() {
		for name, service := range d.GetServices() {
			ep, ok := proxyEndpoints[service.GetProxiedGrpc().GetAddress()]
			if !ok {
				return nil, fmt.Errorf("failed to find proxy for address %q for service %s on target %q", service.GetProxiedGrpc().GetAddress(), name, d.GetName())
			}
			if err := addProxyTarget(service, ep.Addr); err != nil {
				return nil, err
			}
		}
	}
	// Add Proxy to ATE.
	for k, d := range r.GetAtes() {
		if ep, ok := proxyEndpoints[k]; ok {
			gService, ok := d.GetServices()["http"]
			if !ok {
				return nil, fmt.Errorf("failed to find 'http' service on target %q", d.GetName())
			}
			if err := addProxyTarget(gService, ep.Addr); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

// Release will release the testbed after use.
func Release(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	if p == nil || b == nil {
		return fmt.Errorf("Init must be called before Release()")
	}
	var errs errlist.List
	if err := b.Release(ctx); err != nil {
		errs.Add(err)
	}
	if err := p.Stop(); err != nil {
		errs.Add(err)
	}
	p = nil
	return errs.Err()
}

type teardownHandler struct {
	// Required to access ondatra APIs.
	t *testing.T
	// Handles the teardown logic for Ondatra tests.
	o *testhelper.TearDownOptions
	// Options used while creating the handler.
	createOpts C.struct_testhelper_TeardownCreateOpts
}

var (
	handlers      = map[int]*teardownHandler{}
	handlersGuard = sync.Mutex{}
	newHandlerID  = 1
)

func initGoTestHelpers() {
	// Execute the function only once.
	sync.OnceFunc(func() {
		// Initialize the testing.T to access GO test helpers.
		testing.Init()
	})()
}

//export testhelperNewTearDownOptions
func testhelperNewTearDownOptions(opts C.struct_testhelper_TeardownCreateOpts) C.int {
	// Create a new testing.T to access ondatra APIs.
	t := &testing.T{}
	// TeardownOptions handles the teardown logic for Ondatra tests.
	o := testhelper.NewTearDownOptions(t)
	// Set the test case ID if provided.
	id := C.GoString(opts.id)
	if id != "" {
		o = o.WithID(id)
	}
	// Set the teardown options.
	if opts.with_config_restorer {
		o = o.WithConfigRestorer(t, nil /*(ignorePaths)*/)
	}

	h := &teardownHandler{
		t:          &testing.T{},
		o:          o,
		createOpts: opts,
	}

	// Acquire the lock to save the handler in a map.
	handlersGuard.Lock()
	defer handlersGuard.Unlock()
	// Assign a unique ID to the handler.
	hID := newHandlerID
	newHandlerID++

	// Save the handler in the map.
	handlers[hID] = h
	log.InfoContextf(context.TODO(), "Created new testhelper teardown handler, with id: %v", hID)
	// Return the handler ID.
	// Handler ID is used to identify the handler coming from the CC code.
	return C.int(hID)
}

//export testhelperTeardown
func testhelperTeardown(handlerID C.int) {
	hID := int(handlerID)

	// Acquire the lock to read/remove the handler from the map.
	handlersGuard.Lock()
	defer handlersGuard.Unlock()

	h, ok := handlers[hID]
	if !ok {
		log.FatalContextf(context.TODO(), "handler %v not found", hID)
	}

	o := h.o
	// Trigger the teardown logic.
	o.Teardown(h.t)
	// Explicitly restore configs if enabled,
	// as config restorer is not triggered in the teardown logic.
	if h.createOpts.with_config_restorer {
		if err := o.RestoreConfigs(h.t); err != nil {
			log.WarningContextf(context.TODO(), "testhelperTeardown, failed to restore configs: %v", err)
		}
	}

	// Remove the handler from the map.
	delete(handlers, hID)
}

//export testhelperAddTestCaseID
func testhelperAddTestCaseID(handlerID C.int, testCaseID *C.char) {
	if testCaseID == nil {
		return
	}

	// Get the handler from the map.
	hID := int(handlerID)
	handlersGuard.Lock()
	defer handlersGuard.Unlock()
	h, ok := handlers[hID]
	if !ok {
		log.FatalContextf(context.TODO(), "handler %v not found", hID)
	}
	h.o.WithID(C.GoString(testCaseID))
}

//export testhelperSaveSwitchLogs
func testhelperSaveSwitchLogs() {
	log.Warningf("testhelperSaveSwitchLogs is unimplemented")
}
