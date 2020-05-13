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

package getsetv

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/schemafake"
	"github.com/openconfig/gnmitest/schemas/openconfig"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	rpb "github.com/openconfig/gnmitest/proto/report"
	spb "github.com/openconfig/gnmitest/proto/suite"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func mustPath(s string) *gpb.Path {
	p, err := ygot.StringToStructuredPath(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestResolveOper(t *testing.T) {
	tests := []struct {
		name             string
		inOper           *tpb.GetSetValidationOper
		inLib            *spb.CommonMessages
		want             *tpb.GetSetValidationOper
		wantErrSubstring string
	}{{
		name: "no messages to resolve",
		inOper: &tpb.GetSetValidationOper{
			Setrequest: &tpb.GetSetValidationOper_Set{
				&gpb.SetRequest{
					Delete: []*gpb.Path{
						mustPath("/interfaces"),
					},
				},
			},
			Getrequest: &tpb.GetSetValidationOper_Get{
				&gpb.GetRequest{
					Path: []*gpb.Path{
						mustPath("/interfaces"),
					},
					Encoding: gpb.Encoding_JSON_IETF,
				},
			},
		},
		want: &tpb.GetSetValidationOper{
			Setrequest: &tpb.GetSetValidationOper_Set{
				&gpb.SetRequest{
					Delete: []*gpb.Path{
						mustPath("/interfaces"),
					},
				},
			},
			Getrequest: &tpb.GetSetValidationOper_Get{
				&gpb.GetRequest{
					Path: []*gpb.Path{
						mustPath("/interfaces"),
					},
					Encoding: gpb.Encoding_JSON_IETF,
				},
			},
		},
	}, {
		name: "resolve common setrequest",
		inOper: &tpb.GetSetValidationOper{
			Setrequest: &tpb.GetSetValidationOper_CommonSetrequest{"setname"},
		},
		inLib: &spb.CommonMessages{
			SetRequests: map[string]*gpb.SetRequest{
				"setname": {
					Delete: []*gpb.Path{
						mustPath("/interfaces"),
					},
				},
			},
		},
		want: &tpb.GetSetValidationOper{
			Setrequest: &tpb.GetSetValidationOper_Set{
				&gpb.SetRequest{
					Delete: []*gpb.Path{
						mustPath("/interfaces"),
					},
				},
			},
		},
	}, {
		name: "resolve common getrequest",
		inOper: &tpb.GetSetValidationOper{
			Getrequest: &tpb.GetSetValidationOper_CommonGetrequest{"getname"},
		},
		inLib: &spb.CommonMessages{
			GetRequests: map[string]*gpb.GetRequest{
				"getname": {
					Path: []*gpb.Path{
						mustPath("/interfaces"),
					},
					Encoding: gpb.Encoding_JSON_IETF,
				},
			},
		},
		want: &tpb.GetSetValidationOper{
			Getrequest: &tpb.GetSetValidationOper_Get{
				&gpb.GetRequest{
					Path: []*gpb.Path{
						mustPath("/interfaces"),
					},
					Encoding: gpb.Encoding_JSON_IETF,
				},
			},
		},
	}, {
		name: "resolve common getresponse",
		inOper: &tpb.GetSetValidationOper{
			Getresponse: &tpb.GetSetValidationOper_CommonGetresponse{"getres"},
		},
		inLib: &spb.CommonMessages{
			GetResponses: map[string]*gpb.GetResponse{
				"getres": {
					Notification: []*gpb.Notification{},
				},
			},
		},
		want: &tpb.GetSetValidationOper{
			Getresponse: &tpb.GetSetValidationOper_GetResponse{
				&gpb.GetResponse{
					Notification: []*gpb.Notification{},
				},
			},
		},
	}, {
		name: "missing setrequest",
		inOper: &tpb.GetSetValidationOper{
			Setrequest: &tpb.GetSetValidationOper_CommonSetrequest{"invalid"},
		},
		inLib:            &spb.CommonMessages{},
		wantErrSubstring: "cannot look up common SetRequest",
	}, {
		name: "missing getrequest",
		inOper: &tpb.GetSetValidationOper{
			Getrequest: &tpb.GetSetValidationOper_CommonGetrequest{"invalid"},
		},
		inLib:            &spb.CommonMessages{},
		wantErrSubstring: "cannot look up common GetRequest",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveOper(tt.inOper, tt.inLib)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Fatalf("did not get expected operation, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestGetSetValidateInternal(t *testing.T) {
	schemafake.Timestamp = func() int64 { return 42 }

	ocSchema, err := gostructs.Schema()
	if err != nil {
		t.Fatalf("cannot extract gostructs schema, got err: %v", err)
	}

	fg, err := schemafake.New(map[string]*ytypes.Schema{"openconfig": ocSchema})
	if err != nil {
		t.Fatalf("cannot init schema-aware fake, %v", err)
	}
	port, stop, err := fg.Start("testdata/cert.crt", "testdata/key.key")
	if err != nil {
		t.Fatalf("cannot start fake, %v", err)
	}
	defer stop()

	commonConnectionArgs := &tpb.Connection{
		Address: fmt.Sprintf("localhost:%d", port),
		Timeout: 3,
	}

	tests := []struct {
		name             string
		inTestInst       *tpb.GetSetValidationTest
		inSpec           *Specification
		inDataFile       string
		wantResult       *rpb.Instance
		wantErrSubstring string
	}{{
		name: "empty interfaces",
		inTestInst: &tpb.GetSetValidationTest{
			TestOper: &tpb.GetSetValidationOper{
				Getrequest: &tpb.GetSetValidationOper_Get{
					&gpb.GetRequest{
						Path: []*gpb.Path{
							mustPath("/interfaces"),
						},
					Encoding: gpb.Encoding_JSON_IETF,
					},
				},
				Getresponse: &tpb.GetSetValidationOper_GetResponse{
					&gpb.GetResponse{
						Notification: []*gpb.Notification{{
							Timestamp: 42,
							Update: []*gpb.Update{{
								Path: mustPath("/interfaces"),
							}},
						}},
					},
				},
			},
		},
		inSpec: &Specification{
			Connection: commonConnectionArgs,
			Result:     &rpb.Instance{},
		},
		wantResult: &rpb.Instance{
			Test: &rpb.TestResult{
				Result: rpb.Status_SUCCESS,
				Type: &rpb.TestResult_Getset{
					&rpb.GetSetTestResult{
						Result: rpb.Status_SUCCESS,
						TestOper: &rpb.GetSetOperResult{
							Result: rpb.Status_SUCCESS,
							GetResponse: &gpb.GetResponse{
								Notification: []*gpb.Notification{{
									Timestamp: 42,
									Update: []*gpb.Update{{
										Path: mustPath("/interfaces"),
									}},
								}},
							},
							GetResponseMatched: rpb.MatchResult_MR_EQUAL,
						},
					},
				},
			},
		},
	}, {
		name: "matching interfaces, with mismatched timestamp",
		inTestInst: &tpb.GetSetValidationTest{
			TestOper: &tpb.GetSetValidationOper{
				Getrequest: &tpb.GetSetValidationOper_Get{
					&gpb.GetRequest{
						Path: []*gpb.Path{
							mustPath("/interfaces"),
						},
					Encoding: gpb.Encoding_JSON_IETF,
					},
				},
				Getresponse: &tpb.GetSetValidationOper_GetResponse{
					&gpb.GetResponse{
						Notification: []*gpb.Notification{{
							Timestamp: 84,
							Update: []*gpb.Update{{
								Path: mustPath("/interfaces"),
							}},
						}},
					},
				},
			},
		},
		inSpec: &Specification{
			Connection: commonConnectionArgs,
			Result:     &rpb.Instance{},
		},
		wantResult: &rpb.Instance{
			Test: &rpb.TestResult{
				Result: rpb.Status_SUCCESS,
				Type: &rpb.TestResult_Getset{
					&rpb.GetSetTestResult{
						Result: rpb.Status_SUCCESS,
						TestOper: &rpb.GetSetOperResult{
							Result: rpb.Status_SUCCESS,
							GetResponse: &gpb.GetResponse{
								Notification: []*gpb.Notification{{
									Timestamp: 42,
									Update: []*gpb.Update{{
										Path: mustPath("/interfaces"),
									}},
								}},
							},
							GetResponseMatched: rpb.MatchResult_MR_EQUAL,
						},
					},
				},
			},
		},
	}, {
		name: "non-matching interfaces",
		inTestInst: &tpb.GetSetValidationTest{
			TestOper: &tpb.GetSetValidationOper{
				Getrequest: &tpb.GetSetValidationOper_Get{
					&gpb.GetRequest{
						Path: []*gpb.Path{
							mustPath("/interfaces"),
						},
					Encoding: gpb.Encoding_JSON_IETF,
					},
				},
				Getresponse: &tpb.GetSetValidationOper_GetResponse{
					&gpb.GetResponse{
						Notification: []*gpb.Notification{{
							Timestamp: 42,
							Update: []*gpb.Update{{
								Path: mustPath("/INVALID"),
							}},
						}},
					},
				},
			},
		},
		inSpec: &Specification{
			Connection: commonConnectionArgs,
			Result:     &rpb.Instance{},
		},
		wantResult: &rpb.Instance{
			Test: &rpb.TestResult{
				Result: rpb.Status_FAIL,
				Type: &rpb.TestResult_Getset{
					&rpb.GetSetTestResult{
						Result: rpb.Status_FAIL,
						TestOper: &rpb.GetSetOperResult{
							Result: rpb.Status_FAIL,
							GetResponse: &gpb.GetResponse{
								Notification: []*gpb.Notification{{
									Timestamp: 42,
									Update: []*gpb.Update{{
										Path: mustPath("/interfaces"),
									}},
								}},
							},
							GetResponseMatched: rpb.MatchResult_MR_UNEQUAL,
						},
					},
				},
			},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := GetSetValidate(ctx, tt.inTestInst, tt.inSpec); err != nil {
				if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
					t.Fatalf("did not get expected error, %s", diff)
				}
			}

			if diff := pretty.Compare(tt.inSpec.Result, tt.wantResult); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
