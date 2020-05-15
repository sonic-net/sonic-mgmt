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

package schemapathc

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/ygot/ygot"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func mustPath(p string) *gpb.Path {
	path, err := ygot.StringToStructuredPath(p)
	if err != nil {
		panic(err)
	}
	return path
}

func noti(prefixPath string, updatePath string) *gpb.SubscribeResponse {
	return &gpb.SubscribeResponse{
		Response: &gpb.SubscribeResponse_Update{
			Update: &gpb.Notification{
				Prefix: mustPath(prefixPath),
				Update: []*gpb.Update{
					&gpb.Update{
						Path: mustPath(updatePath),
					},
				},
			},
		},
	}
}

func TestSchemaPathComplete(t *testing.T) {
	tests := []struct {
		name                 string
		inConfig             *tpb.Test
		inSubscribeResponses []*gpb.SubscribeResponse
		wantErrSubstrings    []string
	}{{
		name: "simple single path",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Path: []*gpb.Path{
								mustPath("/interfaces/interface/state/counters/in-pkts"),
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti("", "/interfaces/interface[name=eth0]/state/counters/in-pkts"),
		},
	}, {
		name: "single path, test failure",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Path: []*gpb.Path{
								mustPath("/interfaces/interface/state/counters/in-pkts"),
							},
						},
					},
				},
			},
		},
		wantErrSubstrings: []string{"did not receive update for path /interfaces/interface/state/counters/in-pkts"},
	}, {
		name: "multiple paths missing",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Path: []*gpb.Path{
								mustPath("/interfaces/interface/state/counters/in-pkts"),
								mustPath("/interfaces/interface/state/counters/out-pkts"),
							},
						},
					},
				},
			},
		},
		wantErrSubstrings: []string{
			"did not receive update for path /interfaces/interface/state/counters/in-pkts",
			"did not receive update for path /interfaces/interface/state/counters/out-pkts",
		},
	}, {
		name: "paths not required present",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Path: []*gpb.Path{
								mustPath("/interfaces/interface/state/counters/in-pkts"),
								mustPath("/interfaces/interface/state/counters/out-pkts"),
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti("", "/interfaces/interface[name=eth0]/state/counters/in-pkts"),
			noti("", "/interfaces/interface[name=eth0]/state/name"),
			noti("", "/interfaces/interface[name=eth1]/state/counters/in-pkts"),
			noti("", "/interfaces/interface[name=eth2]/state/counters/out-pkts"),
		},
	}, {
		name: "prefixed paths",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Path: []*gpb.Path{
								mustPath("/system/state/hostname"),
								mustPath("/system/state/domain-name"),
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti("/system/state", "hostname"),
			noti("", "/system/state/domain-name"),
		},
	}, {
		name: "nil path in update",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Path: []*gpb.Path{
								mustPath("/system/state/hostname"),
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{{
			Response: &gpb.SubscribeResponse_Update{
				Update: &gpb.Notification{
					Update: []*gpb.Update{
						&gpb.Update{},
					},
				},
			},
		}},
	}, {
		name: "prefix in test specification",
		inConfig: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_SchemapathComplete{
						&tpb.SchemaPathComplete{
							Prefix: mustPath("/system"),
							Path: []*gpb.Path{
								mustPath("state/hostname"),
								mustPath("state/domain-name"),
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti("", "/system/state/hostname"),
			noti("", "/system/state/domain-name"),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := newTest(tt.inConfig)
			if err != nil {
				t.Fatalf("invalid configuration supplied, got err: %v", err)
			}

			for _, sr := range tt.inSubscribeResponses {
				if _, err := ts.Process(sr); err != nil {
					t.Fatalf("cannot process SubscribeResponse %s, got: %v", proto.MarshalTextString(sr), err)
				}
			}

			err = ts.Check()
			for _, ss := range tt.wantErrSubstrings {
				if diff := errdiff.Substring(err, ss); diff != "" {
					t.Fatalf("missing error, %s", diff)
				}
			}
		})
	}
}
