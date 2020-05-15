/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package subscribe contains test interface definitions for gnmi Subscribe
// RPC.
package subscribe

import (
	"fmt"

	"github.com/openconfig/gnmitest/common/testerror"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	rpb "github.com/openconfig/gnmitest/proto/report"
)

// Status is a type that is used by test to notify test framework.
type Status int

const (
	// Running indicates that test can accept more proto.Message.
	Running Status = iota
	// Complete indicates that test is finished, so it can be unregistered.
	Complete
)

// Subscribe is the interface of a test for gnmi Subscribe RPC.
type Subscribe interface {
	// Process is called for each individual message received. Status returned by
	// Process may have Running or Complete status. When Complete is returned,
	// test framework calls Check function of the test to get the holistic test
	// result and to unregister test.
	Process(sr *gpb.SubscribeResponse) (Status, error)
	// Check is called to get the holistic test result in the following cases;
	// - Process function returns Complete
	// - Test times out
	// - GNMI RPC request fails
	Check() error
}

// Test must be embedded by each gnmi Subscribe RPC test.
type Test struct {
	sr *gpb.SubscribeRequest
}

// Check is the default implementation for a test that only evaluates
// individual messages via Process and does not return a stateful result across
// multiple messages.
func (s *Test) Check() error {
	return nil
}

// GetRequest returns the gnmi SubscribeRequest stored in the receiver object.
func (s *Test) GetRequest() *gpb.SubscribeRequest {
	return s.sr
}

// SetRequest stores the gnmi SubscribeRequest in the struct.
func (s *Test) SetRequest(sr *gpb.SubscribeRequest) {
	s.sr = sr
}

// OneShotGetOrCreate calls GetOrCreate for each Notification that is received
// with a value - deserialising the value into the supplied GoStruct using the
// specified schema.  It returns Complete when the sync_response message is
// received. It is called in tests that require deserialisation of
// Notifications into a ygot struct without validation of the data value.
func OneShotGetOrCreate(schema *yang.Entry, root ygot.GoStruct, sr *gpb.SubscribeResponse) (Status, error) {
	handler := func(p *gpb.Path) error {
		node, sch, err := ytypes.GetOrCreateNode(schema, root, p)
		if err != nil {
			return err
		}

		if sch.IsLeaf() || sch.IsLeafList() {
			return nil
		}

		return fmt.Errorf("path doesn't point to leaf node, %T", node)
	}

	switch v := sr.Response.(type) {
	case *gpb.SubscribeResponse_Update:
		pe := v.Update.GetPrefix().GetElem()
		for _, u := range v.Update.Update {
			if u != nil && u.Path != nil {
				if err := handler(&gpb.Path{Elem: append(pe, u.Path.GetElem()...)}); err != nil {
					return Running, err
				}
			}
		}

		for _, d := range v.Update.Delete {
			if d != nil {
				if err := handler(&gpb.Path{Elem: append(pe, d.GetElem()...)}); err != nil {
					return Running, err
				}
			}
		}

		return Running, nil
	case *gpb.SubscribeResponse_SyncResponse:
		//Once the subscription has received all paths at least once - i.e., sync_response is
		//sent by the target, then complete the test.
		return Complete, nil
	}
	return Running, fmt.Errorf("unexpected message: %T", sr.Response)
}

// OneShotSetNode unmarshals the values in gpb.SubscribeResponse into the given
// GoStruct with the provided schema.
func OneShotSetNode(schema *yang.Entry, root ygot.GoStruct, sr *gpb.SubscribeResponse, opts ...ytypes.SetNodeOpt) (Status, error) {
	switch v := sr.Response.(type) {
	case *gpb.SubscribeResponse_Update:
		errs := &testerror.List{}

		pe := v.Update.GetPrefix().GetElem()
		for _, u := range v.Update.Update {
			if u != nil && u.Path != nil {
				if err := ytypes.SetNode(schema, root, &gpb.Path{Elem: append(pe, u.Path.GetElem()...)}, u.GetVal(), opts...); err != nil {
					errs.AddTestErr(&rpb.TestError{Message: err.Error(), Path: joinPath(v.Update.GetPrefix(), u.GetPath())})
				}
			}
		}

		for _, d := range v.Update.Delete {
			if d != nil {
				// TODO(yusufsn): Support removing the value from GoStruct. Setting
				// value to nil will not modify anything.
				if err := ytypes.SetNode(schema, root, &gpb.Path{Elem: append(pe, d.GetElem()...)}, nil, opts...); err != nil {
					errs.AddTestErr(&rpb.TestError{Message: err.Error(), Path: joinPath(v.Update.GetPrefix(), d)})
				}
			}
		}

		if len(errs.Errors()) > 0 {
			return Running, errs
		}
		return Running, nil
	case *gpb.SubscribeResponse_SyncResponse:
		//Once the subscription has received all paths at least once - i.e., sync_response is
		//sent by the target, then complete the test.
		return Complete, nil
	}
	return Running, fmt.Errorf("unexpected message: %T", sr.Response)
}
