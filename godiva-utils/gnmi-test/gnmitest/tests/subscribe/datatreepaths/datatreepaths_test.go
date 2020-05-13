package datatreepaths

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmitest/schemas"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/exampleoc"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ygot"

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

func noti(p ...string) *gpb.Notification {
	n := &gpb.Notification{}
	for _, s := range p {
		n.Update = append(n.Update, &gpb.Update{Path: mustPath(s)})
	}
	return n
}

type pathVal struct {
	p *gpb.Path
	v *gpb.TypedValue
}

func notiVal(ts int64, pfx *gpb.Path, upd ...pathVal) *gpb.Notification {
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

func TestCheck(t *testing.T) {
	s, err := exampleoc.Schema()
	if err != nil {
		t.Fatalf("cannot get schema, %v", err)
	}

	if err := schema.Set("", s.Root, exampleoc.UnzipSchema, exampleoc.Unmarshal); err != nil {
		t.Fatalf("cannot register new schema, %v", err)
	}

	tests := []struct {
		name                 string
		inSpec               *tpb.Test
		inSubscribeResponses []*gpb.SubscribeResponse
		wantErrSubstring     string
	}{{
		name: "simple data tree path",
		inSpec: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_DataTreePaths{
						DataTreePaths: &tpb.DataTreePaths{
							TestOper: &tpb.DataTreePaths_TestQuery{
								Steps: []*tpb.DataTreePaths_QueryStep{{
									Name: "interfaces",
								}, {
									Name: "interface",
									Key:  map[string]string{"name": "eth0"},
								}},
								Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
									&tpb.DataTreePaths_RequiredPaths{
										Prefix: mustPath("state/counters"),
										Paths: []*gpb.Path{
											mustPath("in-pkts"),
											mustPath("out-pkts"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{{
			Response: &gpb.SubscribeResponse_Update{
				noti(
					"/interfaces/interface[name=eth0]/state/counters/in-pkts",
					"/interfaces/interface[name=eth0]/state/counters/out-pkts",
				),
			},
		}},
	}, {
		name: "simple data tree path with enum",
		inSpec: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_DataTreePaths{
						DataTreePaths: &tpb.DataTreePaths{
							TestOper: &tpb.DataTreePaths_TestQuery{
								Steps: []*tpb.DataTreePaths_QueryStep{{
									Name: "interfaces",
								}, {
									Name: "interface",
									Key:  map[string]string{"name": "eth0"},
								}},
								Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
									&tpb.DataTreePaths_RequiredPaths{
										Prefix: mustPath("state"),
										Paths: []*gpb.Path{
											mustPath("admin-status"),
											mustPath("oper-status"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{{
			Response: &gpb.SubscribeResponse_Update{
				notiVal(42, mustPath("/interfaces/interface[name=eth0]/state"),
					pathVal{mustPath("admin-status"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"UP"}}},
					pathVal{mustPath("oper-status"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"DORMANT"}}},
				),
			},
		}},
	}, {
		name: "unset enum",
		inSpec: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_DataTreePaths{
						DataTreePaths: &tpb.DataTreePaths{
							TestOper: &tpb.DataTreePaths_TestQuery{
								Steps: []*tpb.DataTreePaths_QueryStep{{
									Name: "interfaces",
								}, {
									Name: "interface",
									Key:  map[string]string{"name": "eth0"},
								}},
								Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
									&tpb.DataTreePaths_RequiredPaths{
										Prefix: mustPath("state"),
										Paths: []*gpb.Path{
											mustPath("admin-status"),
											mustPath("oper-status"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{{
			Response: &gpb.SubscribeResponse_Update{
				notiVal(42, mustPath("/interfaces/interface[name=eth0]/state"),
					pathVal{mustPath("admin-status"), &gpb.TypedValue{Value: &gpb.TypedValue_StringVal{"UP"}}},
				),
			},
		}},
		wantErrSubstring: "enum type exampleoc.E_OpenconfigInterfaces_Interface_OperStatus was UNSET",
	}, {
		name: "iterative test",
		inSpec: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_DataTreePaths{
						DataTreePaths: &tpb.DataTreePaths{
							TestOper: &tpb.DataTreePaths_TestQuery{
								Steps: []*tpb.DataTreePaths_QueryStep{{
									Name: "interfaces",
								}, {
									Name: "interface",
								}},
								Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
									&tpb.DataTreePaths_ListQuery{
										VarName: "%%interface%%",
										NextQuery: &tpb.DataTreePaths_TestQuery{
											Steps: []*tpb.DataTreePaths_QueryStep{{
												Name: "interfaces",
											}, {
												Name:    "interface",
												KeyName: "%%interface%%",
											}},

											Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
												&tpb.DataTreePaths_RequiredPaths{
													Prefix: mustPath("state/counters"),
													Paths: []*gpb.Path{
														mustPath("in-pkts"),
														mustPath("out-pkts"),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{{
			Response: &gpb.SubscribeResponse_Update{
				noti(
					"/interfaces/interface[name=eth0]/state/counters/in-pkts",
					"/interfaces/interface[name=eth0]/state/counters/out-pkts",
					"/interfaces/interface[name=eth1]/state/counters/in-pkts",
					"/interfaces/interface[name=eth1]/state/counters/out-pkts",
				),
			},
		}},
	}, {
		name: "iterative test - failed",
		inSpec: &tpb.Test{
			Type: &tpb.Test_Subscribe{
				&tpb.SubscribeTest{
					Args: &tpb.SubscribeTest_DataTreePaths{
						DataTreePaths: &tpb.DataTreePaths{
							TestOper: &tpb.DataTreePaths_TestQuery{
								Steps: []*tpb.DataTreePaths_QueryStep{{
									Name: "interfaces",
								}, {
									Name: "interface",
								}},
								Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
									&tpb.DataTreePaths_ListQuery{
										VarName: "%%interface%%",
										NextQuery: &tpb.DataTreePaths_TestQuery{
											Steps: []*tpb.DataTreePaths_QueryStep{{
												Name: "interfaces",
											}, {
												Name:    "interface",
												KeyName: "%%interface%%",
											}},

											Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
												&tpb.DataTreePaths_RequiredPaths{
													Prefix: mustPath("state/counters"),
													Paths: []*gpb.Path{
														mustPath("in-pkts"),
														mustPath("out-pkts"),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inSubscribeResponses: []*gpb.SubscribeResponse{{
			Response: &gpb.SubscribeResponse_Update{
				noti(
					"/interfaces/interface[name=eth0]/state/counters/in-pkts",
					"/interfaces/interface[name=eth1]/state/counters/in-pkts",
					"/interfaces/interface[name=eth1]/state/counters/out-pkts",
				),
			},
		}},
		wantErrSubstring: "got nil data for path",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := newTest(tt.inSpec)
			if err != nil {
				t.Fatalf("cannot initialise test, %v", err)
			}

			for _, sr := range tt.inSubscribeResponses {
				if _, err := ts.Process(sr); err != nil {
					t.Fatalf("cannot process SubscribeResponse %s, %v", sr, err)
				}
			}

			err = ts.Check()
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %v", err)
			}
		})
	}
}

func TestQueries(t *testing.T) {
	tests := []struct {
		name             string
		inTestSpec       *tpb.DataTreePaths
		inSchema         *yang.Entry
		inDevice         *exampleoc.Device
		want             []*gpb.Path
		wantErrSubstring string
	}{{
		name: "foreach subinterface of each interface",
		inTestSpec: &tpb.DataTreePaths{
			TestOper: &tpb.DataTreePaths_TestQuery{
				Steps: []*tpb.DataTreePaths_QueryStep{{
					Name: "interfaces",
				}, {
					Name: "interface",
				}},
				Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
					&tpb.DataTreePaths_ListQuery{
						VarName: "%%interface%%",
						NextQuery: &tpb.DataTreePaths_TestQuery{
							Steps: []*tpb.DataTreePaths_QueryStep{{
								Name: "interfaces",
							}, {
								Name:    "interface",
								KeyName: "%%interface%%",
							}, {
								Name: "subinterfaces",
							}, {
								Name: "subinterface",
							}},
							Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
								&tpb.DataTreePaths_ListQuery{
									VarName: "%%subinterface%%",
									NextQuery: &tpb.DataTreePaths_TestQuery{
										Steps: []*tpb.DataTreePaths_QueryStep{{
											Name: "interfaces",
										}, {
											Name:    "interface",
											KeyName: "%%interface%%",
										}, {
											Name: "subinterfaces",
										}, {
											Name:    "subinterface",
											KeyName: "%%subinterface%%",
										}},
										Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
											&tpb.DataTreePaths_RequiredPaths{
												Paths: []*gpb.Path{
													mustPath("state/index"),
													mustPath("state/description"),
													mustPath("ipv4/addresses/address[ip=192.168.1.2]/state/ip"),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		inDevice: func() *exampleoc.Device {
			oc := &exampleoc.Device{}
			oc.GetOrCreateInterface("eth0").GetOrCreateSubinterface(1)
			oc.GetOrCreateInterface("eth0").GetOrCreateSubinterface(2)
			oc.GetOrCreateInterface("eth1").GetOrCreateSubinterface(10)
			oc.GetOrCreateInterface("eth1").GetOrCreateSubinterface(20)
			return oc
		}(),
		want: []*gpb.Path{
			mustPath("/interfaces/interface[name=eth0]/subinterfaces/subinterface[index=1]/state/index"),
			mustPath("/interfaces/interface[name=eth0]/subinterfaces/subinterface[index=1]/state/description"),
			mustPath("/interfaces/interface[name=eth0]/subinterfaces/subinterface[index=1]/ipv4/addresses/address[ip=192.168.1.2]/state/ip"),
			mustPath("/interfaces/interface[name=eth0]/subinterfaces/subinterface[index=2]/state/index"),
			mustPath("/interfaces/interface[name=eth0]/subinterfaces/subinterface[index=2]/state/description"),
			mustPath("/interfaces/interface[name=eth0]/subinterfaces/subinterface[index=2]/ipv4/addresses/address[ip=192.168.1.2]/state/ip"),
			mustPath("/interfaces/interface[name=eth1]/subinterfaces/subinterface[index=10]/state/index"),
			mustPath("/interfaces/interface[name=eth1]/subinterfaces/subinterface[index=10]/state/description"),
			mustPath("/interfaces/interface[name=eth1]/subinterfaces/subinterface[index=10]/ipv4/addresses/address[ip=192.168.1.2]/state/ip"),
			mustPath("/interfaces/interface[name=eth1]/subinterfaces/subinterface[index=20]/state/index"),
			mustPath("/interfaces/interface[name=eth1]/subinterfaces/subinterface[index=20]/state/description"),
			mustPath("/interfaces/interface[name=eth1]/subinterfaces/subinterface[index=20]/ipv4/addresses/address[ip=192.168.1.2]/state/ip"),
		},
	}, {
		name: "simple data tree paths, no queries",
		inTestSpec: &tpb.DataTreePaths{
			TestOper: &tpb.DataTreePaths_TestQuery{
				Steps: []*tpb.DataTreePaths_QueryStep{{
					Name: "interfaces",
				}, {
					Name: "interface",
					Key:  map[string]string{"name": "eth0"},
				}},
				Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
					&tpb.DataTreePaths_RequiredPaths{
						Prefix: mustPath("state/counters"),
						Paths: []*gpb.Path{
							mustPath("in-pkts"),
							mustPath("out-pkts"),
						},
					},
				},
			},
		},
		inDevice: &exampleoc.Device{},
		want: []*gpb.Path{
			mustPath("/interfaces/interface[name=eth0]/state/counters/in-pkts"),
			mustPath("/interfaces/interface[name=eth0]/state/counters/out-pkts"),
		},
	}, {
		name: "list query for non-list",
		inTestSpec: &tpb.DataTreePaths{
			TestOper: &tpb.DataTreePaths_TestQuery{
				Steps: []*tpb.DataTreePaths_QueryStep{{
					Name: "interfaces",
				}, {
					Name: "interface",
				}, {
					Name: "ethernet",
				}},
				Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
					&tpb.DataTreePaths_ListQuery{
						VarName: "%%foo%%",
						NextQuery: &tpb.DataTreePaths_TestQuery{
							Steps: []*tpb.DataTreePaths_QueryStep{{
								Name: "interfaces",
							}, {
								Name:    "interface",
								KeyName: "%%foo%%",
							}},
							Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
								&tpb.DataTreePaths_RequiredPaths{
									Prefix: mustPath("state/counters"),
									Paths: []*gpb.Path{
										mustPath("in-pkts"),
									},
								},
							},
						},
					},
				},
			},
		},
		inDevice: func() *exampleoc.Device {
			d := &exampleoc.Device{}
			d.GetOrCreateInterface("eth0")
			return d
		}(),
		wantErrSubstring: "was not a list",
	}, {
		name: "list query for empty list",
		inTestSpec: &tpb.DataTreePaths{
			TestOper: &tpb.DataTreePaths_TestQuery{
				Steps: []*tpb.DataTreePaths_QueryStep{{
					Name: "interfaces",
				}, {
					Name: "interface",
				}},
				Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
					&tpb.DataTreePaths_ListQuery{
						VarName: "%%foo%%",
						NextQuery: &tpb.DataTreePaths_TestQuery{
							Steps: []*tpb.DataTreePaths_QueryStep{{
								Name: "interfaces",
							}, {
								Name:    "interface",
								KeyName: "%%foo%%",
							}},
							Type: &tpb.DataTreePaths_TestQuery_RequiredPaths{
								&tpb.DataTreePaths_RequiredPaths{
									Prefix: mustPath("state/counters"),
									Paths: []*gpb.Path{
										mustPath("in-pkts"),
									},
								},
							},
						},
					},
				},
			},
		},
		wantErrSubstring: "code = NotFound",
	}, {
		name: "nil next_query in list query",
		inTestSpec: &tpb.DataTreePaths{
			TestOper: &tpb.DataTreePaths_TestQuery{
				Steps: []*tpb.DataTreePaths_QueryStep{{
					Name: "interfaces",
				}, {
					Name: "interface",
				}},
				Type: &tpb.DataTreePaths_TestQuery_GetListKeys{
					&tpb.DataTreePaths_ListQuery{
						VarName: "%%foo%%",
					},
				},
			},
		},
		wantErrSubstring: "specified nil next_query",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tinst := &test{
				dataTree: tt.inDevice,
				schema:   exampleoc.SchemaTree[reflect.TypeOf(tt.inDevice).Elem().Name()],
				testSpec: tt.inTestSpec,
			}

			got, err := tinst.queries()
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if err != nil {
				return
			}

			neq := func(a, b []*gpb.Path) bool {
				return cmp.Equal(a, b, cmpopts.SortSlices(testutil.PathLess), cmpopts.EquateEmpty())
			}

			if !neq(got, tt.want) {
				diff := pretty.Compare(got, tt.want)
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestMakeQuery(t *testing.T) {
	tests := []struct {
		name             string
		inQuery          []*tpb.DataTreePaths_QueryStep
		inKnownVars      keyQuery
		want             []*gpb.Path
		wantErrSubstring string
	}{{
		name: "query with no expansions",
		inQuery: []*tpb.DataTreePaths_QueryStep{{
			Name: "one",
		}, {
			Name: "two",
			Key:  map[string]string{"value": "forty-two"},
		}},
		want: []*gpb.Path{
			mustPath("/one/two[value=forty-two]"),
		},
	}, {
		name: "query with expansions",
		inQuery: []*tpb.DataTreePaths_QueryStep{{
			Name: "one",
		}, {
			Name:    "two",
			KeyName: "%%vars%%",
		}},
		inKnownVars: keyQuery{
			"%%vars%%": []map[string]string{
				map[string]string{"val": "one"},
				map[string]string{"val": "two"},
			},
		},
		want: []*gpb.Path{
			mustPath("/one/two[val=one]"),
			mustPath("/one/two[val=two]"),
		},
	}, {
		name: "query with multiple expansions",
		inQuery: []*tpb.DataTreePaths_QueryStep{{
			Name:    "one",
			KeyName: "%%keyone%%",
		}, {
			Name:    "two",
			KeyName: "%%keytwo%%",
		}},
		inKnownVars: keyQuery{
			"%%keyone%%": []map[string]string{
				map[string]string{"v1": "one"},
				map[string]string{"v1": "two"},
			},
			"%%keytwo%%": []map[string]string{
				map[string]string{"v2": "one"},
				map[string]string{"v2": "two"},
			},
		},
		want: []*gpb.Path{
			mustPath("/one[v1=one]/two[v2=one]"),
			mustPath("/one[v1=one]/two[v2=two]"),
			mustPath("/one[v1=two]/two[v2=one]"),
			mustPath("/one[v1=two]/two[v2=two]"),
		},
	}, {
		name: "query with unresolvable step",
		inQuery: []*tpb.DataTreePaths_QueryStep{{
			Name:    "one",
			KeyName: "%%val%%",
		}},
		wantErrSubstring: "cannot resolve step",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := makeQuery(tt.inQuery, tt.inKnownVars)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("got unexpected error, %s", diff)
			}

			if err != nil {
				return
			}

			neq := func(a, b []*gpb.Path) bool {
				return cmp.Equal(a, b, cmpopts.SortSlices(testutil.PathLess), cmpopts.EquateEmpty())
			}

			if !neq(got, tt.want) {
				diff := pretty.Compare(got, tt.want)
				t.Fatalf("did not get expected value, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestMakeStep(t *testing.T) {
	tests := []struct {
		name             string
		inQueryStep      *tpb.DataTreePaths_QueryStep
		inKnownVars      keyQuery
		inKnownPaths     []*gpb.Path
		want             []*gpb.Path
		wantErrSubstring string
	}{{
		name: "no paths with simple element append",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name: "last-element",
		},
		want: []*gpb.Path{mustPath("last-element")},
	}, {
		name: "specified path with simple element append",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name: "last-element",
		},
		inKnownPaths: []*gpb.Path{mustPath("path-one")},
		want:         []*gpb.Path{mustPath("/path-one/last-element")},
	}, {
		name: "multiple specified paths with simple element append",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name: "last-element",
		},
		inKnownPaths: []*gpb.Path{
			mustPath("/path-one"),
			mustPath("/path-two"),
		},
		want: []*gpb.Path{
			mustPath("/path-one/last-element"),
			mustPath("/path-two/last-element"),
		},
	}, {
		name: "specified path with element expansion",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name:    "list-element",
			KeyName: "%%keys%%",
		},
		inKnownVars: keyQuery{
			"%%keys%%": []map[string]string{
				{"name": "val1"},
			},
		},
		want: []*gpb.Path{
			mustPath("/list-element[name=val1]"),
		},
	}, {
		name: "specified paths with multiple element expansion",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name:    "list-element",
			KeyName: "%%keyname%%",
		},
		inKnownVars: keyQuery{
			"%%keyname%%": []map[string]string{
				{"name": "val1"},
				{"name": "val2"},
			},
		},
		want: []*gpb.Path{
			mustPath("/list-element[name=val1]"),
			mustPath("/list-element[name=val2]"),
		},
	}, {
		name: "error expanding step",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name:    "list-element",
			KeyName: "%%invalid%%",
		},
		wantErrSubstring: "cannot resolve step",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := makeStep(tt.inQueryStep, tt.inKnownVars, tt.inKnownPaths)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if err != nil {
				return
			}

			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Fatalf("did not get expected output, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestResolvedPathElem(t *testing.T) {
	tests := []struct {
		name             string
		inQueryStep      *tpb.DataTreePaths_QueryStep
		inKeyQuery       keyQuery
		want             []*gpb.PathElem
		wantErrSubstring string
	}{{
		name: "no expansion",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name: "element",
		},
		want: []*gpb.PathElem{{Name: "element"}},
	}, {
		name: "with key, no expansion",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name: "element",
			Key:  map[string]string{"key-name": "value"},
		},
		want: []*gpb.PathElem{{Name: "element", Key: map[string]string{"key-name": "value"}}},
	}, {
		name: "with key, expanded to one value",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name:    "element",
			KeyName: "%%test%%",
		},
		inKeyQuery: keyQuery{"%%test%%": {
			map[string]string{
				"value": "forty-two",
			},
		}},
		want: []*gpb.PathElem{{
			Name: "element",
			Key:  map[string]string{"value": "forty-two"},
		}},
	}, {
		name: "with key, expanded to >1 value",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name:    "element",
			KeyName: "%%test%%",
		},
		inKeyQuery: keyQuery{"%%test%%": {
			map[string]string{
				"value": "forty-two",
			},
			map[string]string{
				"value": "forty-three",
			},
		}},
		want: []*gpb.PathElem{{
			Name: "element",
			Key:  map[string]string{"value": "forty-two"},
		}, {
			Name: "element",
			Key:  map[string]string{"value": "forty-three"},
		}},
	}, {
		name: "with invalid key_name",
		inQueryStep: &tpb.DataTreePaths_QueryStep{
			Name:    "element",
			KeyName: "%%invalid%%",
		},
		wantErrSubstring: "could not substitute for key name %%invalid%%, no specified values",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvedPathElem(tt.inQueryStep, tt.inKeyQuery)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, %s", diff)
			}

			if err != nil {
				return
			}

			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
