package schemafake

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/common"
	"github.com/openconfig/gnmitest/schemas/openconfig"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func mustPath(s string) *gpb.Path {
	p, err := ygot.StringToStructuredPath(s)
	if err != nil {
		panic(err)
	}
	return p
}

// mustPathTargetOrigin converts the path s into a gNMI Path message using
// o as the origin, and t as the name of the target.
func mustPathTargetOrigin(s, o, t string) *gpb.Path {
	p := mustPath(s)
	p.Target = t
	p.Origin = o
	return p
}

type pathVal struct {
	p *gpb.Path
	v *gpb.TypedValue
}

func notification(ts int64, pfx *gpb.Path, upd ...pathVal) *gpb.Notification {
	n := &gpb.Notification{
		Prefix:    pfx,
		Timestamp: ts,
	}

	for _, u := range upd {
		n.Update = append(n.Update, &gpb.Update{
			Path: u.p,
			Val:  u.v,
		})
	}

	return n
}

func mustSchema(s *ytypes.Schema, err error) *ytypes.Schema {
	if err != nil {
		panic(err)
	}
	return s
}

func TestLoadGet(t *testing.T) {
	type getTest struct {
		req          *gpb.GetRequest
		res          *gpb.GetResponse
		errSubstring string
	}

	tsVal := int64(42)
	// Explicitly override the timestamp function to return a constant value.
	Timestamp = func() int64 { return tsVal }

	tests := []struct {
		name     string
		inSchema map[string]*ytypes.Schema
		inKey    string
		inCert   string
		inJSON   map[string][]byte // input data, keyed by origin name
		inTests  []getTest
	}{{
		name: "simple get",
		inSchema: map[string]*ytypes.Schema{
			"openconfig": mustSchema(gostructs.Schema()),
		},
		inKey:  "testdata/key.key",
		inCert: "testdata/cert.crt",
		inJSON: map[string][]byte{"openconfig": []byte(`
		{
			"system": {
				"config": {
					"hostname": "a machine",
					"domain-name": "google.com"
				}
			}
		}`)},
		inTests: []getTest{{
			req: &gpb.GetRequest{
				Path: []*gpb.Path{mustPath("/system/config/hostname")},
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, nil, pathVal{mustPath("/system/config/hostname"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"a machine"}}}),
				},
			},
		}, {
			req: &gpb.GetRequest{
				Path:     []*gpb.Path{mustPath("/system/config")},
				Encoding: gpb.Encoding_JSON_IETF,
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, nil, pathVal{mustPath("/system/config"), &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{[]byte(`{
  "openconfig-system:domain-name": "google.com",
  "openconfig-system:hostname": "a machine"
}`)}}}),
				},
			},
		}, {
			req: &gpb.GetRequest{
				Path:     []*gpb.Path{mustPathTargetOrigin("/system/config/domain-name", "openconfig", "tt")},
				Encoding: gpb.Encoding_JSON_IETF,
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, mustPathTargetOrigin("", "openconfig", "tt"), pathVal{mustPath("/system/config/domain-name"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"google.com"}}}),
				},
			},
		}},
	}, {
		name: "list based gets",
		inSchema: map[string]*ytypes.Schema{
			"openconfig": mustSchema(gostructs.Schema()),
		},
		inKey:  "testdata/key.key",
		inCert: "testdata/cert.crt",
		inJSON: map[string][]byte{"openconfig": []byte(`
		{
			"interfaces": {
				"interface": [
					{
						"name": "eth0",
						"config": {
							"name": "eth0",
							"type": "ethernetCsmacd",
							"mtu": 1500
						},
						"subinterfaces": {
							"subinterface": [
								{
									"index": 0,
									"config": {
										"index": 0
									},
									"ipv4": {
										"addresses": {
											"address": [
												{
													"ip": "192.0.2.1",
													"config": {
														"ip": "192.0.2.1",
														"prefix-length": 24
													}
												}
											]
										}
									}
								},
								{
									"index": 1,
									"config": {
										"index": 1
									},
									"ipv6": {
										"addresses": {
											"address": [
												{
													"ip": "2001:db8::dead:beef",
													"config":  {
														"ip": "2001:db8::dead::beef",
														"prefix-length": 64
													}
												}
											]
										}
									}
								}
							]
						}
					},
					{
						"name": "eth1",
						"config": {
							"name": "eth1"
						}
					}
				]
			}
		}`)},
		inTests: []getTest{{
			req: &gpb.GetRequest{
				Path: []*gpb.Path{
					mustPath("/interfaces/interface/config/name"),
				},
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, mustPath("/interfaces"),
						pathVal{mustPath("interface[name=eth0]/config/name"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"eth0"}}},
						pathVal{mustPath("interface[name=eth1]/config/name"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"eth1"}}},
					),
				},
			},
		}},
	}, {
		name: "multiple origins",
		inSchema: map[string]*ytypes.Schema{
			"openconfig":      mustSchema(gostructs.Schema()),
			"vendor-specific": mustSchema(gostructs.Schema()),
		},
		inKey:  filepath.Join("testdata", "key.key"),
		inCert: filepath.Join("testdata", "cert.crt"),
		inJSON: map[string][]byte{
			"openconfig": []byte(`
{
	"system": {
		"config": {
			"hostname": "test-device"
		}
	}
}`),
			"vendor-specific": []byte(`
{
	"system": {
		"config": {
			"domain-name": "google.com"
		}
	}
}`),
		},
		inTests: []getTest{{
			req: &gpb.GetRequest{
				Path: []*gpb.Path{
					mustPathTargetOrigin("/system/config/hostname", "openconfig", ""),
					mustPathTargetOrigin("/system/config/domain-name", "vendor-specific", ""),
				},
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, mustPathTargetOrigin("", "openconfig", ""), pathVal{mustPath("/system/config/hostname"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"test-device"}}}),
					notification(tsVal, mustPathTargetOrigin("", "vendor-specific", ""), pathVal{mustPath("/system/config/domain-name"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"google.com"}}}),
				},
			},
		}, {
			req: &gpb.GetRequest{
				Path: []*gpb.Path{
					mustPathTargetOrigin("/system/config/domain-name", "openconfig", ""), // explicitly doesn't exist
				},
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, mustPathTargetOrigin("", "openconfig", ""), pathVal{mustPath("/system/config/domain-name"), nil}),
				},
			},
		}},
	}, {
		name: "failure followed by success",
		inSchema: map[string]*ytypes.Schema{
			"openconfig": mustSchema(gostructs.Schema()),
		},
		inKey:  filepath.Join("testdata", "key.key"),
		inCert: filepath.Join("testdata", "cert.crt"),
		inJSON: map[string][]byte{
			"openconfig": []byte(`
{
	"system": {
		"config": {
			"hostname": "device"
		}
	}
}`),
		},
		inTests: []getTest{{
			req: &gpb.GetRequest{
				Path: []*gpb.Path{
					mustPath("/does-not-exist"),
				},
			},
			errSubstring: "InvalidArgument",
		}, {
			req: &gpb.GetRequest{
				Path: []*gpb.Path{
					mustPath("/system/config/hostname"),
				},
			},
			res: &gpb.GetResponse{
				Notification: []*gpb.Notification{
					notification(tsVal, nil, pathVal{mustPath("/system/config/hostname"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"device"}}}),
				},
			},
		}},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			target, err := New(tt.inSchema)
			if err != nil {
				t.Fatalf("cannot create fake, %v", err)
			}

			for orig, data := range tt.inJSON {
				if err := target.Load(data, orig); err != nil {
					t.Fatalf("cannot load JSON input, %v", err)
				}
			}

			port, stop, err := target.Start(tt.inCert, tt.inKey)
			if err != nil {
				t.Fatalf("cannot start fake, %v", err)
			}
			defer stop()

			c, cclose, err := common.Connect(context.Background(), &tpb.Connection{
				Address: fmt.Sprintf("localhost:%d", port),
				Timeout: 30,
			})
			if err != nil {
				t.Fatalf("cannot connect to fake, %v", err)
			}
			defer cclose()

			for i, tc := range tt.inTests {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				got, err := c.Get(ctx, tc.req)
				if diff := errdiff.Substring(err, tc.errSubstring); diff != "" {
					t.Fatalf("test %d, did not get expected error, %s", i, diff)
				}

				if err != nil {
					continue
				}

				if !testutil.NotificationSetEqual(got.Notification, tc.res.Notification) {
					t.Fatalf("did not get expected response, for test case %d. Sent:\n%s\ndiff(-got,+want):\n%s", i, proto.MarshalTextString(tc.req), pretty.Compare(got, tc.res))
				}
			}
		})
	}
}

// subscribeTest defines a test for the Subscribe RPC.
type subscribeTest struct {
	desc         string                   // desc describes the subtest for documentation purposes.
	req          *gpb.SubscribeRequest    // req is the input request sent to the target.
	res          []*gpb.SubscribeResponse // res is the set of responses received from the target.
	errSubstring string                   // errSubstring is used to substring match any received error.
}

func subReq(paths []string, mode gpb.SubscriptionList_Mode) *gpb.SubscribeRequest {
	sl := &gpb.SubscriptionList{
		Mode: mode,
	}

	for _, p := range paths {
		sl.Subscription = append(sl.Subscription, &gpb.Subscription{
			Path: mustPath(p),
		})
	}

	return &gpb.SubscribeRequest{
		Request: &gpb.SubscribeRequest_Subscribe{
			sl,
		},
	}
}
func TestSubscribeOnce(t *testing.T) {
	Timestamp = func() int64 { return 42 }

	tests := []struct {
		name     string
		inSchema map[string]*ytypes.Schema
		inKey    string
		inCert   string
		inJSON   map[string][]byte // input data, keyed by origin name
		inTests  []subscribeTest
	}{{
		name: "single leaf",
		inSchema: map[string]*ytypes.Schema{
			"openconfig": mustSchema(gostructs.Schema()),
		},
		inKey:  "testdata/key.key",
		inCert: "testdata/cert.crt",
		inJSON: map[string][]byte{"openconfig": []byte(`
		{
			"system": {
				"state": {
					"hostname": "gnmi-target",
					"domain-name": "google.com"
				}
			}
		}`)},
		inTests: []subscribeTest{{
			desc: "leaf subscribe",
			req:  subReq([]string{"/system/state/hostname"}, gpb.SubscriptionList_ONCE),
			res: []*gpb.SubscribeResponse{{
				Response: &gpb.SubscribeResponse_Update{
					notification(Timestamp(), nil,
						pathVal{p: mustPath("/system/state/hostname"), v: &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"gnmi-target"}}},
					),
				},
			}, {
				Response: &gpb.SubscribeResponse_SyncResponse{true},
			}},
		}, {
			desc: "container path",
			req:  subReq([]string{"/system/state"}, gpb.SubscriptionList_ONCE),
			res: []*gpb.SubscribeResponse{{
				Response: &gpb.SubscribeResponse_Update{
					notification(Timestamp(), mustPath("/system/state"),
						pathVal{p: mustPath("hostname"), v: &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"gnmi-target"}}},
						pathVal{p: mustPath("domain-name"), v: &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"google.com"}}},
					),
				},
			}, {
				Response: &gpb.SubscribeResponse_SyncResponse{true},
			}},
		}, {
			desc: "unknown path - valid in schema",
			req:  subReq([]string{"/system/clock/state"}, gpb.SubscriptionList_ONCE),
			// target should not return an error, but rather just a sync response.
			res: []*gpb.SubscribeResponse{{
				Response: &gpb.SubscribeResponse_SyncResponse{true},
			}},
		}, {
			desc:         "unknown invalid path",
			req:          subReq([]string{"/system/fish"}, gpb.SubscriptionList_ONCE),
			errSubstring: "InvalidArgument",
		}},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := New(tt.inSchema)
			if err != nil {
				t.Fatalf("cannot create fake, %v", err)
			}

			for orig, data := range tt.inJSON {
				if err := target.Load(data, orig); err != nil {
					t.Fatalf("cannot load JSON input, %v", err)
				}
			}

			port, stop, err := target.Start(tt.inCert, tt.inKey)
			if err != nil {
				t.Fatalf("cannot start fake, %v", err)
			}
			defer stop()

			c, cclose, err := common.Connect(context.Background(), &tpb.Connection{
				Address: fmt.Sprintf("localhost:%d", port),
				Timeout: 30,
			})
			if err != nil {
				t.Fatalf("cannot connect to fake, %v", err)
			}

			defer cclose()

			for _, tc := range tt.inTests {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				stream, err := c.Subscribe(ctx)
				if err != nil {
					t.Errorf("test %s, did not create stream successfully, got err: %v", tc.desc, err)
					continue
				}

				got := []*gpb.SubscribeResponse{}

				if err := stream.Send(tc.req); err != nil {
					t.Errorf("test %s, cannot send subscribe request, got err: %v", tc.desc, err)
					continue
				}

				for {
					msg, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						if diff := errdiff.Substring(err, tc.errSubstring); diff != "" {
							t.Errorf("test %s, got unexpected error whilst receiving, got err: %v", tc.desc, err)
						}
						break
					}

					got = append(got, msg)
				}

				if matched := testutil.SubscribeResponseSetEqual(got, tc.res); !matched {
					t.Errorf("did not get matching SubscribeResponses, got: %s, want: %s", got, tc.res)
				}
			}

		})
	}
}
