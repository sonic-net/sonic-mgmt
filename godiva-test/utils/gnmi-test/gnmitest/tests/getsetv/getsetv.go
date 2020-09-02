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

// Package getsetv defines the logic that implements the GetSetValidate tests
// for the gnmitest framework. These tests are described in tests.proto in
// detail. The procedure implemented by the test is
//
//   1. Perform an initial Set operation, which can be used to initialise the
//      target system to a known good state.
//   2. Perform a Get operation, whose result is compared against a specified
//      GetResponse.
//   3. Perform a Set operation, which can be used to test a particular
//      behaviour of the system.
//   4. Perform a Get operation, whose result is again compared against a
//      specified GetResponse.
//
// The operations are paired such that 1+2, and 3+4 are considered together.
// Optionally, in each pair the Get or Set operation can be omitted. The
// initial operations (i.e., 1+2) may also be omitted. This test therefore
// allows a sequence of Get+Set tests, as well as individual tests for Get and
// Set if required.
//
// All operations are performed sequentially. The failure of any one of the
// operations is considered fatal for the test.
package getsetv

import (
	"context"
	"fmt"
	"time"

	log "github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmitest/common"
	"github.com/openconfig/ygot/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	rpb "github.com/openconfig/gnmitest/proto/report"
	spb "github.com/openconfig/gnmitest/proto/suite"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// Specification defines the parameters for a GetSetValidate test.
type Specification struct {
	Connection     *tpb.Connection     // Connection specifies the target to be connected to.
	Instance       *spb.Instance       // Instance is the test instance that is being executed.
	Result         *rpb.Instance       // Result is the result of the test instance that should be written to.
	CommonRequests *spb.CommonMessages // CommonRequests is the library of common messages that can be referenced by the test.
}

// GetSetValidate runs the GetSetValidate test specified in testInst
// using the specification provided.  It returns an error if encountered in the
// test, and writes it result to the Instance protobuf in the Specification.
func GetSetValidate(ctx context.Context, testInst *tpb.GetSetValidationTest, spec *Specification) error {
	log.Infof("connecting to target %s", spec.Connection.Address)

	creds, err := common.ResolveCredentials(ctx, spec.Connection)
	if err != nil {
		return fmt.Errorf("cannot resolve credentials, %v", err)
	}
	ctx = common.ContextWithAuth(ctx, creds)

	conn, cleanup, err := common.Connect(ctx, spec.Connection)
	if err != nil {
		return fmt.Errorf("cannot connect to target: %v", err)
	}
	defer cleanup()

	o, err := resolveOper(testInst.GetInitialiseOper(), spec.CommonRequests)
	if err != nil {
		return fmt.Errorf("cannot resolve initialise oper, %v", err)
	}

	t, err := resolveOper(testInst.GetTestOper(), spec.CommonRequests)
	if err != nil {
		return fmt.Errorf("cannot resolve test oper, %v", err)
	}

	ti := proto.Clone(testInst).(*tpb.GetSetValidationTest)
	ti.InitialiseOper = o
	ti.TestOper = t

	iRes, iPass, err, _ := doOper(ctx, conn, ti.InitialiseOper)
	if err != nil {
		return fmt.Errorf("cannot run initialise oper, got error: %v", err)
	}

	tRes, tPass, err, oper_time := doOper(ctx, conn, ti.TestOper)
	if err != nil {
		return fmt.Errorf("cannot run test oper, got err: %v", err)
	}

	passRes := func(a, b bool) rpb.Status {
		if a && b {
			return rpb.Status_SUCCESS
		}
		return rpb.Status_FAIL
	}

	spec.Result.Test = &rpb.TestResult{
		Test:   spec.Instance.GetTest(),
		Result: passRes(iPass, tPass),
		OperTime: oper_time,
		Type: &rpb.TestResult_Getset{
			&rpb.GetSetTestResult{
				Result:         passRes(iPass, tPass),
				InitialiseOper: iRes,
				TestOper:       tRes,
			},
		},
	}

	return nil
}

// resolveOper looks up the common messages that are specified in the supplied
// oper in the lib provided. The fully resolved GetSetValidationOper is returned
// to the caller.
func resolveOper(oper *tpb.GetSetValidationOper, lib *spb.CommonMessages) (*tpb.GetSetValidationOper, error) {
	gn := oper.GetCommonGetrequest()
	sn := oper.GetCommonSetrequest()
	gr := oper.GetCommonGetresponse()

	switch {
	case gn == "" && sn == "" && gr == "":
		return oper, nil
	case (gn != "" || sn != "" || gr != "") && lib == nil:
		return nil, fmt.Errorf("cannot look up common requests (Get: %s, Set: %s), nil library", gn, sn)
	case gn != "" && lib.GetRequests == nil:
		return nil, fmt.Errorf("cannot look up common GetRequest %s, nil GetRequest library", gn)
	case sn != "" && lib.SetRequests == nil:
		return nil, fmt.Errorf("cannot look up common SetRequest %s, nil SetRequest library", sn)
	}

	rt := proto.Clone(oper).(*tpb.GetSetValidationOper)
	if gn != "" {
		req, ok := lib.GetRequests[gn]
		if !ok {
			return nil, fmt.Errorf("common GetRequest %s does not exist", gn)
		}
		rt.Getrequest = &tpb.GetSetValidationOper_Get{req}
	}

	if sn != "" {
		req, ok := lib.SetRequests[sn]
		if !ok {
			return nil, fmt.Errorf("common SetRequest %s does not exist", sn)
		}
		rt.Setrequest = &tpb.GetSetValidationOper_Set{req}
	}

	if gr != "" {
		res, ok := lib.GetResponses[gr]
		if !ok {
			return nil, fmt.Errorf("common GetResponse %s does not exist", gr)
		}
		rt.Getresponse = &tpb.GetSetValidationOper_GetResponse{res}
	}

	return rt, nil
}

// doOper runs the specified oper test operation, and returns its result, along with a boolean
// which indicates whether the overall test was successful.
func doOper(ctx context.Context, conn gpb.GNMIClient, oper *tpb.GetSetValidationOper) (*rpb.GetSetOperResult, bool, error, int64) {
	var t0,t1 int64
	if oper.GetSet() == nil && oper.GetGet() == nil {
		return nil, true, nil, 0
	}

	log.Infof("running operation %s", proto.MarshalTextString(oper))

	r := &rpb.GetSetOperResult{}
	pass := true

	if s := oper.GetSet(); s != nil {
		t0 =  time.Now().Round(time.Millisecond).UnixNano() / 1e6
		sr, err := conn.Set(ctx, s)
		t1 = time.Now().Round(time.Millisecond).UnixNano() / 1e6
		r.SetResponse = sr
		if err != nil {
			if oper.SetOk != tpb.GetSetValidationOper_FAILED {
				r.Result = rpb.Status_FAIL
				pass = false
			}
			if s, ok := status.FromError(err); ok {
				r.SetStatus = s.Proto()
			}
		}

		if r.Result == rpb.Status_UNSET {
			r.Result = rpb.Status_SUCCESS
		}
	}

	if g := oper.GetGet(); g != nil {
		t0 = time.Now().Round(time.Millisecond).UnixNano() / 1e6
		gr, err := conn.Get(ctx, g)
		t1 = time.Now().Round(time.Millisecond).UnixNano() / 1e6
		r.GetResponse = gr
		if err != nil {
			if oper.GetOk != tpb.GetSetValidationOper_FAILED {
				r.Result = rpb.Status_FAIL
				pass = false
			}

			if s, ok := status.FromError(err); ok {
				r.GetStatus = s.Proto()
			}
		}

		if wantRes := oper.GetGetResponse(); err == nil && wantRes != nil {
			switch tr := testutil.GetResponseEqual(gr, wantRes, testutil.IgnoreTimestamp{}); tr {
			case false:
				r.Result = rpb.Status_FAIL
				r.GetResponseMatched = rpb.MatchResult_MR_UNEQUAL
				pass = false
			default:
				r.GetResponseMatched = rpb.MatchResult_MR_EQUAL
			}
		}

		if r.Result == rpb.Status_UNSET {
			r.Result = rpb.Status_SUCCESS
		}
	}

	return r, pass, nil, t1-t0
}

// toCode returns the error supplied as a status code. If the error is not a
// valid status then the Invalid error code is used.
func toCode(err error) codes.Code {
	s, ok := status.FromError(err)
	if !ok {
		return codes.Unknown
	}
	return s.Code()
}
