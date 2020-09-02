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

// Package runner has functions to be able to run given suite of tests. It runs
// InstanceGroups sequentially, with each Instance within a group being run in
// parallel. See the comments in suite.proto for further description of the test
// suite execution logic.
package runner

import (
	"context"
	//"crypto/tls"
	"fmt"
	"strconv"
	"time"

	log "github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/client"
	//"github.com/openconfig/gnmitest/common"
	"github.com/openconfig/gnmitest/common/report"
	"github.com/openconfig/gnmitest/common/testerror"
	"github.com/openconfig/gnmitest/config"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/subscribe"
	"github.com/openconfig/gnmitest/tests/getsetv"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	rpb "github.com/openconfig/gnmitest/proto/report"
	spb "github.com/openconfig/gnmitest/proto/suite"
	tpb "github.com/openconfig/gnmitest/proto/tests"
	ppb "github.com/openconfig/gnmitest/proto/perf"
)

// PartialReportFunc is used by framework to notify caller when running
// a single spb.InstanceGroup is finished.
type PartialReportFunc func(*rpb.InstanceGroup, *ppb.InstanceGroup, int64, int64)

// Runner object encapsulates the config, report and logging to run
// a Suite of tests.
type Runner struct {
	cfg    *config.Config    // object that contains the Suite proto.
	report PartialReportFunc // used to update caller incrementally.
}

var (
	// createSubscription creates a gNMI subscription with the provided
	// gpb.SubscribeRequest and tpb.Connection parameters. Received messages
	// are dispatched to the provided ProtoHandler. clientType defines the
	// type of the client that needs to be created.
	createSubscription = func(ctx context.Context, sr *gpb.SubscribeRequest, pHandler client.ProtoHandler, conn *tpb.Connection, clientType string) error {
		log.Infof("creating Subscribe client subscription with %s", proto.MarshalTextString(sr))
		q, err := client.NewQuery(sr)
		if err != nil {
			return err
		}
		q.Addrs = []string{conn.GetAddress()}
		q.Timeout = time.Duration(conn.GetTimeout()) * time.Second
		q.ProtoHandler = pHandler
/*
		creds, err := common.ResolveCredentials(ctx, conn)
		if err != nil {
			return err
		}

		if creds != nil {
			q.Credentials = &client.Credentials{
				Username: creds.Username,
				Password: creds.Password,
			}

			// If credentials are specified, we must run TLS.
			q.TLS = &tls.Config{
				// Always assume that the certificate should not be
				// verified.
				InsecureSkipVerify: true,
			}
		}
		*/

		c := client.BaseClient{}
		defer c.Close()
		return c.Subscribe(ctx, q, clientType)
	}
)

// New creates an instance of runner. It receives;
// - config that contains the Suite proto
// - update function to notify caller about the partial results
func New(cfg *config.Config, r PartialReportFunc) *Runner {
	return &Runner{cfg: cfg, report: r}
}

// Start runs all the tests in the Suite. Start blocks caller until all tests
// finish. Reporting is done by calling PartialReportFunc as rpb.InstanceGroup
// ready.
func (r *Runner) Start(pCtx context.Context) error {
	// total time for running all the instance group 
	var total_time int64 = 0
	if r.cfg.Suite.Iteration == 0 {
          r.cfg.Suite.Iteration = 1
	}
	for j := 0; j < int(r.cfg.Suite.Iteration); j++ {
           fmt.Println("Iteration: ", j) 

	   for igIndex, ig := range r.cfg.Suite.InstanceGroupList {

		// Create an InstanceGroup report.
		igResult := &rpb.InstanceGroup{Description: ig.Description}

		// Error value of all the tests are pushed into error channel
		errC := make(chan error)
		ctx, cancelFunc := context.WithCancel(pCtx)
		defer cancelFunc()

		t0 :=  time.Now().Round(time.Millisecond).UnixNano() / 1e6
		for _, ins := range ig.Instance {
			// Create a rpb.Instance report and append it to rpb.IntanceGroup.
			// So, while each test is running, no synchronization is needed
			// as each is given a rpb.Instance to update.
			insResult := &rpb.Instance{Description: ins.Description}
			igResult.Instance = append(igResult.Instance, insResult)

			// Run test and continue to next one without waiting this to finish.
			go func(gIns *spb.Instance) {
				select {
				case errC <- r.runTest(ctx, gIns, insResult):
				case <-ctx.Done():
				}
			}(ins)
		} 


		for i := 0; i < len(ig.Instance); i++ {
			err := <-errC
			if err != nil {
				return err
			}
		}
		t1 :=  time.Now().Round(time.Millisecond).UnixNano() / 1e6

		//Create an InstanceGroup perf
		igPerf := &ppb.InstanceGroup{Description: ig.Description}
		igPerf.Iteration = int64(j+1);
		inst := 0
		fmt.Println("  Instance Group(" + igResult.Description + ") :", igIndex)
		var max_instance_time int64 = 0
		for  _, insr := range igResult.Instance {
			inst  += 1

			insPerf := &ppb.Instance{Description: insr.Description}
			insPerf.ExecTime = insr.Test.OperTime 
			igPerf.Instance = append(igPerf.Instance, insPerf)
			if max_instance_time < insPerf.ExecTime {
				max_instance_time = insPerf.ExecTime
			}
			fmt.Print("    Instance(" + insr.Description + ") :", inst);
			fmt.Println("    ExecTime : " + strconv.FormatInt(insr.Test.OperTime,10) + "ms");

		}
		// assign max instance time for the Instance group time
		igPerf.ExecTime = max_instance_time

		//cumulative total_time
		total_time += igPerf.ExecTime

                if r.cfg.Suite.Verbose == spb.Verbose_ALL  {
	  	  // Update caller with the result of running spb.InstanceGroup
		  r.report(igResult, igPerf, total_time, total_time/int64(j+1))
                } else if r.cfg.Suite.Verbose == spb.Verbose_PERF {
			r.report(&rpb.InstanceGroup{Description: ig.Description}, igPerf, total_time, total_time/int64(j+1))
                } else if r.cfg.Suite.Verbose == spb.Verbose_REPORT {
		  r.report(igResult, nil, total_time, total_time/int64(j+1))
		}

		// If the instance group is marked as fatal, and any test within
		// it failed, then stop processing.
		if ig.Fatal && report.InstGroupFailed(igResult) {
			// Mark all other instance groups as not run.
			for i := igIndex + 1; i < len(r.cfg.Suite.InstanceGroupList); i++ {
				g := r.cfg.Suite.InstanceGroupList[i]
				r.report(&rpb.InstanceGroup{Description: g.Description, Skipped: true}, nil, 0, 0)
			}
			break
		}
		fmt.Println("  Instance Group Time : " + strconv.FormatInt(max_instance_time, 10) + "ms");
		fmt.Println("  Instance Group Time(including overhead) : " + strconv.FormatInt(t1-t0, 10) + "ms");
	    }
        }
	fmt.Println("---------------------------------------")
	fmt.Println("Total time : " + strconv.FormatInt(total_time, 10) + "ms");
	fmt.Println("Avg time : " + strconv.FormatInt(((total_time)/int64(r.cfg.Suite.Iteration)), 10) + "ms")
	fmt.Println("---------------------------------------")
	return nil
}

// runTest runs parent test and its extensions.
func (r *Runner) runTest(ctx context.Context, ins *spb.Instance, ir *rpb.Instance) error {
	switch v := ins.Test.Type.(type) {
	case *tpb.Test_FakeTest:
		return r.runFakeTest(ins, ir)
	case *tpb.Test_Subscribe:
		return r.runSubscribeTest(ctx, ins, ir)
	case *tpb.Test_GetSet:
		return r.runGetSetTest(ctx, ins, ir)
	default:
		return fmt.Errorf("runner doesn't know how to run %T test", v)
	}
}

// runFakeTest allows a fake test to be run to check the execution logic of the
// test framework without external dependencies.
func (r *Runner) runFakeTest(ins *spb.Instance, res *rpb.Instance) error {
	res.Description = ins.Description
	switch t := ins.GetTest().GetFakeTest(); t.Pass {
	case true:
		res.Test = &rpb.TestResult{Result: rpb.Status_SUCCESS}
	default:
		res.Test = &rpb.TestResult{Result: rpb.Status_FAIL}
	}
	return nil
}

// runGetSetTest runs a Get/Set Validation test specified by the input instance, outputting
// the result to the supplied report Instance.
func (r *Runner) runGetSetTest(ctx context.Context, ins *spb.Instance, insRes *rpb.Instance) error {
	log.Infof("running GetSetTest, with %s", proto.MarshalTextString(ins.GetTest().GetGetSet()))
	ts := ins.GetTest().GetGetSet()
	if ts == nil {
		return fmt.Errorf("invalid nil test specification received in test %s", ins.Description)
	}

	c := ins.GetTest().GetConnection()
	if c == nil {
		return fmt.Errorf("invalid nil connection received in test %s", ins.Description)
	}

	switch ts.GetArgs().(type) {
	case *tpb.GetSetTest_OperValidation:
		return getsetv.GetSetValidate(ctx, ts.GetOperValidation(), &getsetv.Specification{
			Connection:     c,
			Instance:       ins,
			Result:         insRes,
			CommonRequests: r.cfg.Suite.GetCommon(),
		})
	default:
		return fmt.Errorf("cannot run GetSet test of type %T", ts.GetArgs())
	}
}

func (r *Runner) runSubscribeTest(ctx context.Context, ins *spb.Instance, insRes *rpb.Instance) error {
	v := ins.Test.GetSubscribe()

	// set the subscribe test report
	insRes.Description = ins.Description
	subRes := &rpb.SubscribeTestResult{}
	insRes.Test = &rpb.TestResult{Type: &rpb.TestResult_Subscribe{Subscribe: subRes}, Test: ins.Test}

	// get the registered test by its oneof type from the SubscribeTest message
	// in tests.proto.
	ti, err := register.GetSubscribeTest(v.Args, ins.Test)
	if err != nil {
		return fmt.Errorf("failed getting an instance of %T test: %v", v.Args, err)
	}

	// create a child context with the test timeout
	tCtx, cancel := context.WithTimeout(ctx, time.Duration(ins.GetTest().GetTimeout())*time.Second)
	defer cancel()
	ctx = nil

	// Note that subscribe test has a callback to cancel context when it is done.
	// That allows test to finish earlier than its subscription.
	subTest := &subscribeTest{
		ti:           ti,
		subRes:       subRes,
		finish:       cancel,
		logResponses: ins.GetTest().GetSubscribe().GetLogResponses(),
		errs:         &testerror.List{},
	}

	err = createSubscription(tCtx, v.Request, func(msg proto.Message) error {
		sr, ok := msg.(*gpb.SubscribeResponse)
		if !ok {
			return fmt.Errorf("update has unknown type: %T", msg)
		}

		subTest.Update(sr)
		return nil
	}, ins.GetTest().GetConnection(), r.cfg.ClientType)

	switch {
	// A test may return Complete status which in turn triggers context
	// to be cancelled. This doesn't need to be reported as an RPC error.
	case tCtx.Err() == context.Canceled:
	// A test may timeout. This doesn't need to be reported as an RPC error.
	case tCtx.Err() == context.DeadlineExceeded:
		subRes.Status = rpb.CompletionStatus_TIMEOUT
	case err != nil:
		subRes.Status = rpb.CompletionStatus_RPC_ERROR
		subRes.Errors = append(subRes.Errors, &rpb.TestError{Message: err.Error()})
		// We still return nil, so that the overall test execution is not
		// fatal, and we continue with other tests.
		return nil
	}

	insRes.Test.Result = rpb.Status_SUCCESS
	if len(subTest.End()) > 0 {
		insRes.Test.Result = rpb.Status_FAIL
	}

	return nil
}

// subscribeTest represents a working subscribe test and messages
// can be dispatched by using Update function. When the test ends,
// End function must be called, otherwise test may not report properly.
type subscribeTest struct {
	// ti is the subscribe test that the SubscribeResponse
	// messages are being dispatched.
	ti subscribe.Subscribe
	// logResponses indicates whether SubscribeResponses should be logged
	// in the report proto.
	logResponses bool
	// subRes is used to store received SubscribeResponse messages
	// as well as errors if logResponses is set to true.
	subRes *rpb.SubscribeTestResult
	// errs is the list of errors received during the execution of test.
	errs *testerror.List
	// finish is a callback to cancel the context if test indicates to
	// finish execution.
	finish func()
}

func (s *subscribeTest) Update(l interface{}) {
	sr := l.(*gpb.SubscribeResponse)
	status, err := s.ti.Process(sr)
	s.errs.AddErr(err)

	if s.logResponses {
		s.subRes.Responses = append(s.subRes.Responses, &rpb.SubscribeResponseResult{Response: sr})
	}

	if status == subscribe.Complete {
		s.subRes.Status = rpb.CompletionStatus_EARLY_FINISHED
		s.finish()
	}
}

func (s *subscribeTest) End() []*rpb.TestError {
	if err := s.ti.Check(); err != nil {
		s.errs.AddErr(err)
	}
	if s.subRes.Status == rpb.CompletionStatus_UNKNOWN {
		s.subRes.Status = rpb.CompletionStatus_FINISHED
	}
// Update the result proto with the errors received in the test.
	s.subRes.Errors = s.errs.Errors()
	return s.errs.Errors()
}
