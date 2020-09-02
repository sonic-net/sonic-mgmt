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

package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/client"
	"github.com/openconfig/gnmitest/config"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/subscribe"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	rpb "github.com/openconfig/gnmitest/proto/report"
	spb "github.com/openconfig/gnmitest/proto/suite"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func configFromProto(s *spb.Suite) (*config.Config, error) {
	b := &bytes.Buffer{}
	if err := proto.MarshalText(b, s); err != nil {
		return nil, fmt.Errorf("cannot unmarshal configuration, %v", err)
	}
	cfg, err := config.New(b.Bytes(), "<client type>")
	if err != nil {
		return nil, fmt.Errorf("cannot create config, %v", err)
	}
	return cfg, nil
}

func TestSimpleRunner(t *testing.T) {
	tests := []struct {
		name       string
		inSuite    *spb.Suite
		wantReport *rpb.Report
	}{{
		name: "one instance group - pass",
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*spb.Instance{{
					Description: "group 1, test 1",
					Test: &tpb.Test{
						Description: "group 1, test1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: true}},
					},
				}, {
					Description: "group 1, test 2",
					Test: &tpb.Test{
						Description: "group1, test2a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: true}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*rpb.Instance{{
					Description: "group 1, test 1",
					Test:        &rpb.TestResult{Result: rpb.Status_SUCCESS},
				}, {
					Description: "group 1, test 2",
					Test:        &rpb.TestResult{Result: rpb.Status_SUCCESS},
				}},
			}},
		},
	}, {
		name: "two instance groups - pass",
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*spb.Instance{{
					Description: "group 1, test 1",
					Test: &tpb.Test{
						Description: "group 1, test 1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: true}},
					},
				}},
			}, {
				Description: "instance group 2",
				Instance: []*spb.Instance{{
					Description: "group 2, test 1",
					Test: &tpb.Test{
						Description: "group 2, test 1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: true}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*rpb.Instance{{
					Description: "group 1, test 1",
					Test:        &rpb.TestResult{Result: rpb.Status_SUCCESS},
				}},
			}, {
				Description: "instance group 2",
				Instance: []*rpb.Instance{{
					Description: "group 2, test 1",
					Test:        &rpb.TestResult{Result: rpb.Status_SUCCESS},
				}},
			}},
		},
	}, {
		name: "two instance groups, first fails, not fatal",
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*spb.Instance{{
					Description: "group 1, test 1",
					Test: &tpb.Test{
						Description: "group 1, test 1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: false}},
					},
				}},
			}, {
				Description: "instance group 2",
				Instance: []*spb.Instance{{
					Description: "group 2, test 1",
					Test: &tpb.Test{
						Description: "group 2, test 1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: true}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*rpb.Instance{{
					Description: "group 1, test 1",
					Test:        &rpb.TestResult{Result: rpb.Status_FAIL},
				}},
			}, {
				Description: "instance group 2",
				Instance: []*rpb.Instance{{
					Description: "group 2, test 1",
					Test:        &rpb.TestResult{Result: rpb.Status_SUCCESS},
				}},
			},
			}},
	}, {
		name: "two instance groups, first fails, fatal",
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group 1",
				Fatal:       true,
				Instance: []*spb.Instance{{
					Description: "group 1, test 1",
					Test: &tpb.Test{
						Description: "group 1, test 1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: false}},
					},
				}},
			}, {
				Description: "instance group 2",
				Instance: []*spb.Instance{{
					Description: "group 2, test 1",
					Test: &tpb.Test{
						Description: "group 2, test 1a",
						Type:        &tpb.Test_FakeTest{&tpb.FakeTest{Pass: true}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group 1",
				Instance: []*rpb.Instance{{
					Description: "group 1, test 1",
					Test:        &rpb.TestResult{Result: rpb.Status_FAIL},
				}},
			}, {
				Description: "instance group 2",
				Skipped:     true,
			}},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := configFromProto(tt.inSuite)
			if err != nil {
				t.Fatalf("cannot create config, got: %v, want: nil", err)
			}

			got := &rpb.Report{}
			r := New(cfg, func(ig *rpb.InstanceGroup) {
				got.Results = append(got.Results, ig)
			})

			if err := r.Start(context.Background()); err != nil {
				t.Fatalf("error occurred during test execution, %v", err)
			}

			if diff := pretty.Compare(got, tt.wantReport); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

var (
	tests = map[string]subscribe.Subscribe{
		"test11": &test1{},
	}
)

func TestMain(m *testing.M) {
	register.NewSubscribeTest(&tpb.SubscribeTest_FakeTest{}, newFake)
	os.Exit(m.Run())
}

func newFake(t *tpb.Test) (subscribe.Subscribe, error) {
	s := t.GetSubscribe().GetFakeTest()
	test, ok := tests[s]
	if !ok {
		return nil, fmt.Errorf("no such test: %q", s)
	}
	return test, nil
}

type test1 struct {
	subscribe.Test
}

// Process is placeholder to satisfy subscribe.Subscribe interface.
func (test1) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	if sr.GetUpdate().GetPrefix().GetOrigin() != "stop" {
		return subscribe.Running, nil
	}
	return subscribe.Complete, nil
}

func TestSubscriptionEndReason(t *testing.T) {
	tests := []struct {
		name                   string
		inSuite                *spb.Suite
		inSubscriptionTimeSpan time.Duration
		inEarlyFinish          bool
		inRPCErrors            bool
		wantReport             *rpb.Report
	}{{
		name:                   "test times out with an outliving subscription",
		inSubscriptionTimeSpan: time.Second * 5,
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Timeout:    3,
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group",
				Instance: []*spb.Instance{{
					Description: "test",
					Test: &tpb.Test{
						Description: "fake test",
						Type:        &tpb.Test_Subscribe{Subscribe: &tpb.SubscribeTest{Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"}}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group",
				Instance: []*rpb.Instance{{
					Description: "test",
					Test: &rpb.TestResult{
						Test: &tpb.Test{
							Description: "fake test",
							Connection:  &tpb.Connection{},
							Timeout:     3,
							Schema:      "openconfig",
							Type: &tpb.Test_Subscribe{
								Subscribe: &tpb.SubscribeTest{
									Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"},
								},
							},
						},
						Result: rpb.Status_SUCCESS,
						Type: &rpb.TestResult_Subscribe{
							Subscribe: &rpb.SubscribeTestResult{
								Status: rpb.CompletionStatus_TIMEOUT,
							},
						},
					},
				}},
			}},
		},
	}, {
		name:                   "test finishs early with an outliving subscription",
		inSubscriptionTimeSpan: time.Second * 5,
		inEarlyFinish:          true,
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group",
				Instance: []*spb.Instance{{
					Description: "test",
					Test: &tpb.Test{
						Description: "fake test",
						Type:        &tpb.Test_Subscribe{Subscribe: &tpb.SubscribeTest{Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"}}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group",
				Instance: []*rpb.Instance{{
					Description: "test",
					Test: &rpb.TestResult{
						Test: &tpb.Test{
							Description: "fake test",
							Connection:  &tpb.Connection{},
							Timeout:     60,
							Schema:      "openconfig",
							Type: &tpb.Test_Subscribe{
								Subscribe: &tpb.SubscribeTest{
									Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"},
								},
							},
						},
						Result: rpb.Status_SUCCESS,
						Type: &rpb.TestResult_Subscribe{
							Subscribe: &rpb.SubscribeTestResult{
								Status: rpb.CompletionStatus_EARLY_FINISHED,
							},
						},
					},
				}},
			}},
		},
	}, {
		name:                   "test finishs with the subscription",
		inSubscriptionTimeSpan: time.Second * 5,
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group",
				Instance: []*spb.Instance{{
					Description: "test",
					Test: &tpb.Test{
						Description: "fake test",
						Type:        &tpb.Test_Subscribe{Subscribe: &tpb.SubscribeTest{Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"}}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group",
				Instance: []*rpb.Instance{{
					Description: "test",
					Test: &rpb.TestResult{
						Test: &tpb.Test{
							Description: "fake test",
							Connection:  &tpb.Connection{},
							Timeout:     60,
							Schema:      "openconfig",
							Type: &tpb.Test_Subscribe{
								Subscribe: &tpb.SubscribeTest{
									Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"},
								},
							},
						},
						Result: rpb.Status_SUCCESS,
						Type: &rpb.TestResult_Subscribe{
							Subscribe: &rpb.SubscribeTestResult{
								Status: rpb.CompletionStatus_FINISHED,
							},
						},
					},
				}},
			}},
		},
	}, {
		name:        "test finishes due to rpc error",
		inRPCErrors: true,
		inSuite: &spb.Suite{
			Name:       "simple suite",
			Connection: &tpb.Connection{},
			InstanceGroupList: []*spb.InstanceGroup{{
				Description: "instance group",
				Instance: []*spb.Instance{{
					Description: "test",
					Test: &tpb.Test{
						Description: "fake test",
						Type:        &tpb.Test_Subscribe{Subscribe: &tpb.SubscribeTest{Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"}}},
					},
				}},
			}},
		},
		wantReport: &rpb.Report{
			Results: []*rpb.InstanceGroup{{
				Description: "instance group",
				Instance: []*rpb.Instance{{
					Description: "test",
					Test: &rpb.TestResult{
						Test: &tpb.Test{
							Description: "fake test",
							Connection:  &tpb.Connection{},
							Timeout:     60,
							Schema:      "openconfig",
							Type: &tpb.Test_Subscribe{
								Subscribe: &tpb.SubscribeTest{
									Args: &tpb.SubscribeTest_FakeTest{FakeTest: "test11"},
								},
							},
						},
						Result: rpb.Status_UNSET,
						Type: &rpb.TestResult_Subscribe{
							Subscribe: &rpb.SubscribeTestResult{
								Errors: []*rpb.TestError{{Message: "fake rpc error"}},
								Status: rpb.CompletionStatus_RPC_ERROR,
							},
						},
					},
				}},
			}},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createSubscription = func(ctx context.Context, sr *gpb.SubscribeRequest, handler client.ProtoHandler, conn *tpb.Connection, s string) error {
				if tt.inRPCErrors {
					return errors.New("fake rpc error")
				}
				handler(&gpb.SubscribeResponse{Response: &gpb.SubscribeResponse_Update{Update: &gpb.Notification{Prefix: &gpb.Path{Origin: "go on"}}}})

				if tt.inEarlyFinish {
					handler(&gpb.SubscribeResponse{Response: &gpb.SubscribeResponse_Update{Update: &gpb.Notification{Prefix: &gpb.Path{Origin: "stop"}}}})
				}
				time.Sleep(tt.inSubscriptionTimeSpan)
				return nil
			}

			cfg, err := configFromProto(tt.inSuite)
			if err != nil {
				t.Fatalf("cannot create config, got: %v, want: nil", err)
			}

			got := &rpb.Report{}
			r := New(cfg, func(ig *rpb.InstanceGroup) {
				got.Results = append(got.Results, ig)
			})

			if err := r.Start(context.Background()); err != nil {
				t.Fatalf("error occurred during test execution, %v", err)
			}
			if diff := pretty.Compare(got, tt.wantReport); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
