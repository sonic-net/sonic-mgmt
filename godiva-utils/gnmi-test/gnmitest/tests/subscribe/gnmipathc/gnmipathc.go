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

// Package gnmipathc tests whether received SubscribeResponse messages has a
// gNMI Path format in accordance with the specification. Test may be
// configured to validate for usage of target and origin fields in addition
// to checking whether Elem field is used instead of Element field.
package gnmipathc

import (
	"errors"
	"fmt"

	"github.com/openconfig/gnmitest/common/testerror"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/subscribe"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// test stores the state for the test that is independent of each update.
type test struct {
	subscribe.Test
	gpc *tpb.GNMIPathCompliance
}

// init statically registers the test against the gnmitest framework.
func init() {
	register.NewSubscribeTest(&tpb.SubscribeTest_GnmipathCompliance{}, newTest)
}

// newTest creates a new instance of the test. It receives a copy of the SubscribeTest
// proto with the arguments that were received.
func newTest(st *tpb.Test) (subscribe.Subscribe, error) {
	gpc := st.GetSubscribe().GetGnmipathCompliance()
	if gpc == nil {
		return nil, errors.New("expect GnmipathCompliance argument to be set")
	}

	return &test{gpc: gpc}, nil
}

// Process function checks whether each received SubscribeResponse has
// gNMI Path format in accordance with the arguments provided during instantiation.
func (t *test) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	switch v := sr.Response.(type) {
	case *gpb.SubscribeResponse_Update:
		if err := t.pathValidate(v.Update.GetPrefix(), true); err != nil {
			return subscribe.Running, err
		}
		for _, u := range v.Update.Update {
			if u != nil && u.Path != nil {
				if err := t.pathValidate(u.Path, false); err != nil {
					return subscribe.Running, err
				}
			}
		}

		for _, d := range v.Update.Delete {
			if d != nil {
				if err := t.pathValidate(d, false); err != nil {
					return subscribe.Running, err
				}
			}
		}

		return subscribe.Running, nil
	case *gpb.SubscribeResponse_SyncResponse:
		return subscribe.Complete, nil
	}
	return subscribe.Running, fmt.Errorf("unexpected message: %T", sr.Response)
}

// pathValidate performs required validations on provided gNMI Path.
// Checking target and origin fields are only performed if function is dealing
// with a prefix gNMI Path.
func (t *test) pathValidate(p *gpb.Path, prefix bool) error {
	errs := &testerror.List{}

	if t.gpc.CheckElem && p != nil && len(p.Element) > 0 {
		errs.AddErr(fmt.Errorf("element field is used in gNMI Path %v", p))
	}

	if !prefix || (t.gpc.CheckTarget == "" && t.gpc.CheckOrigin == "") {
		return errs
	}

	if p == nil {
		errs.AddErr(fmt.Errorf("prefix gNMI Path must be non-nil, origin and/or target are missing"))
		return errs
	}

	switch {
	case t.gpc.CheckTarget == "": // Validation on target field isn't requested.
	case t.gpc.CheckTarget == "*":
		if p.Target == "" {
			errs.AddErr(fmt.Errorf("target isn't set in prefix gNMI Path %v", p))
		}
	case t.gpc.CheckTarget != p.Target:
		errs.AddErr(fmt.Errorf("target in gNMI Path %v is %q, expect %q", p, p.Target, t.gpc.CheckTarget))
	}

	switch {
	case t.gpc.CheckOrigin == "": // Validation on origin field isn't requested.
	case t.gpc.CheckOrigin == "*":
		if p.Origin == "" {
			errs.AddErr(fmt.Errorf("origin isn't set in prefix gNMI Path %v", p))
		}
	case t.gpc.CheckOrigin != p.Origin:
		errs.AddErr(fmt.Errorf("origin in gNMI Path %v is %q, expect %q", p, p.Origin, t.gpc.CheckOrigin))
	}

	return errs
}
