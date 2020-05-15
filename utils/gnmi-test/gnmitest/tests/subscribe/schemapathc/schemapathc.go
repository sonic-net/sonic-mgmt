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

// Package schemapathc runs a test in the gnmitest framework that checks
// for the presence of at least one gNMI Notification with each of the
// specified YANG schema paths. This allows a test to be run to check
// that an implementation is exporting specific paths. It does not check
// that the paths are repeated a specific number of times, but can indicate
// whether a target is implementing a particular schema path mapping.
//
// Any received Notification is converted to a schema path, that is to say
// that the keys within any gnmi.PathElen message are received. The test
// does not fail if additional paths are received, such that partial
// compliance for the subscription can be specified.
package schemapathc

import (
	"fmt"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/errlist"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/subscribe"
	"github.com/openconfig/ygot/ygot"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// test stores the state for the test that is independent of each update.
type test struct {
	subscribe.Test

	mu sync.Mutex
	// paths is the set of paths that are to be checked for after the
	// test has run.
	paths map[string]bool
}

// init statically registers the test against the gnmitest framework.
func init() {
	register.NewSubscribeTest(&tpb.SubscribeTest_SchemapathComplete{}, newTest)
}

// newTest creates a new instance of the test. It receives a copy of the SubscribeTest
// proto with the arguments that were received.
func newTest(st *tpb.Test) (subscribe.Subscribe, error) {

	spec := st.GetSubscribe().GetSchemapathComplete()
	if spec == nil {
		return nil, fmt.Errorf("received nil SchemaPathComplete in %s", proto.MarshalTextString(st))
	}

	tests := map[string]bool{}
	for _, p := range spec.GetPath() {
		// resolve the path according to the prefix specified.
		np := proto.Clone(p).(*gpb.Path)
		np.Elem = append(spec.GetPrefix().GetElem(), p.GetElem()...)

		scp, err := ygot.PathToSchemaPath(np)
		if err != nil {
			return nil, fmt.Errorf("invalid path %s received", proto.MarshalTextString(st))
		}

		tests[scp] = false
	}

	return &test{
		paths: tests,
	}, nil
}

// Check determines whether all paths that were specified in the test were received.
// It is called by the framework after the subscription is complete.
func (t *test) Check() error {
	var errs errlist.List

	for p, ok := range t.paths {
		if !ok {
			errs.Add(fmt.Errorf("did not receive update for path %s", p))
		}
	}

	return errs.Err()
}

// Process is called when SubscribeResponse messages are received for the test.
// It converts the received paths into a schema path and marks it as received.
func (t *test) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	switch v := sr.Response.(type) {
	case *gpb.SubscribeResponse_Update:
		var pe []*gpb.PathElem
		// Join prefix path and update/delete path.
		if v.Update.Prefix != nil {
			pe = append(pe, v.Update.Prefix.Elem...)
		}
		for _, u := range v.Update.Update {
			if u.GetPath() != nil {
				p := &gpb.Path{Elem: append(pe, u.GetPath().GetElem()...)}
				sp, err := ygot.PathToSchemaPath(p)
				if err != nil {
					return subscribe.Running, fmt.Errorf("invalid path received in test, %s", proto.MarshalTextString(u.Path))
				}
				t.mu.Lock()
				if _, ok := t.paths[sp]; ok {
					t.paths[sp] = true
				}
				t.mu.Unlock()
			}
		}
		return subscribe.Running, nil
	case *gpb.SubscribeResponse_SyncResponse:
		// Once the subscription has received all paths at least once - i.e., sync_response
		// is sent, then complete the test.
		return subscribe.Complete, nil
	}
	return subscribe.Running, fmt.Errorf("unexpected message; %T", sr.Response)
}
