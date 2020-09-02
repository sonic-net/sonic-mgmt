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

// Package haskeys runs a test that checks that a particular list within
// the OpenConfig schema has a set of specified keys.
package haskeys

import (
	"fmt"
	"reflect"

	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/errlist"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/schemas"
	"github.com/openconfig/gnmitest/subscribe"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// test stores the state for the test that is independent of each update.
type test struct {
	subscribe.Test
	// dataTree is the tree for Notifications to be deserialised into.
	dataTree ygot.GoStruct
	// schema is the root entry for the schema.
	schema *yang.Entry
	// paths specifies the set of paths that are to be checked at the
	// end of the test.
	paths []*gpb.Path
}

// init statically registers the test against the gnmitest framework.
func init() {
	register.NewSubscribeTest(&tpb.SubscribeTest_HasKeys{}, newTest)
}

// newTest creates a new instance of the test. It receives a copy of the SubscribeTest
// proto with the arguments that were received.
func newTest(st *tpb.Test) (subscribe.Subscribe, error) {
	goStruct, err := schema.Get(st.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to get %v schema; %v", st.GetSchema(), err)
	}
	root := goStruct.NewRoot()
	tn := reflect.TypeOf(root).Elem().Name()
	schema, err := goStruct.Schema(tn)
	if err != nil {
		return nil, fmt.Errorf("failed to get schema for %q; %v", tn, err)
	}

	paths, err := completePaths(st.GetSubscribe())
	if err != nil {
		return nil, fmt.Errorf("cannot parse input path arguments: %v ", err)
	}

	return &test{
		dataTree: root,
		schema:   schema,
		paths:    paths,
	}, nil
}

// completePaths extracts the set of paths specified in the input test arguments.
func completePaths(st *tpb.SubscribeTest) ([]*gpb.Path, error) {
	hk := st.GetHasKeys()
	if hk == nil {
		return nil, fmt.Errorf("test did not specify an argument: %s", proto.MarshalTextString(st))
	}

	basePath := hk.GetPath()
	switch {
	case basePath == nil:
		return nil, fmt.Errorf("nil list schema specified in argument: %s", proto.MarshalTextString(hk))
	case basePath.Elem == nil || len(basePath.Elem) == 0:
		return nil, fmt.Errorf("zero length path specified in argument: %s", proto.MarshalTextString(hk))
	case len(basePath.Elem[len(basePath.Elem)-1].Key) != 0:
		return nil, fmt.Errorf("invalid path with keys specified in argument: %s", proto.MarshalTextString(basePath))
	}

	var paths []*gpb.Path
	for _, i := range hk.GetItem() {
		p := proto.Clone(basePath).(*gpb.Path)
		p.Elem[len(p.Elem)-1].Key = i.Key
		paths = append(paths, p)
	}

	return paths, nil
}

// Check determines whether the keys that are specified in the test arguments exist within the list.
// It is called by the framework after the subscription is complete.
func (t *test) Check() error {
	var errs errlist.List

	for _, p := range t.paths {
		nodes, err := ytypes.GetNode(t.schema, t.dataTree, p)
		if err != nil {
			errs.Add(fmt.Errorf("could not get requested path %s: %v", proto.MarshalTextString(p), err))
		}
		switch {
		case len(nodes) == 0:
			errs.Add(fmt.Errorf("no nodes found for requested path %v", proto.MarshalTextString(p)))
		case len(nodes) > 1:
			errs.Add(fmt.Errorf("%d nodes found for path %v, want 1", len(nodes), proto.MarshalTextString(p)))
		}
	}

	return errs.Err()
}

// Process is called when SubscribeResponse messages are received for the test. It
// deserialises each subscription response into the dataTree. When the sync_response
// message is received, it validates that the specified keys exist within the dataTree
// that has been built.
func (t *test) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	return subscribe.OneShotGetOrCreate(t.schema, t.dataTree, sr)
}
